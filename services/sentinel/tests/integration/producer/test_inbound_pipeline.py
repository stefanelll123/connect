"""Integration tests for the Producer Inbound Pipeline (TASK-045).

Tests:
  1. Valid request → permit, forwarded to backend
  2. Missing SentinelProof header → 401 MISSING_PROOF
  3. Missing SentinelVP header → 401 MISSING_VP
  4. Tampered body → 401 BODY_HASH_MISMATCH
  5. Expired proof → 401 PROOF_EXPIRED
  6. Replay attack (same jti twice) → 401 REPLAY_DETECTED
  7. Body over 2MB → 413 REQUEST_TOO_LARGE
  8. Backend unreachable → 502 BACKEND_UNAVAILABLE
"""
from __future__ import annotations

import base64
import json
import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import ASGITransport, AsyncClient

from sentinel.producer.pipeline import InboundPipeline
from sentinel.producer.pipeline_context import PipelineContext

# ---------------------------------------------------------------------------
# Key material and DID helpers
# ---------------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    res = []
    while n:
        n, r = divmod(n, 58)
        res.append(_B58_ALPHABET[r])
    for b in data:
        if b == 0:
            res.append(_B58_ALPHABET[0])
        else:
            break
    return "".join(reversed(res))


def _make_did_key(pub_bytes: bytes) -> str:
    return f"did:key:z{_b58(bytes([0xED, 0x01]) + pub_bytes)}"


def _gen():
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = priv.public_key().public_bytes_raw()
    did = _make_did_key(pub_bytes)
    return priv_bytes, pub_bytes, did


CONSUMER_PRIV, CONSUMER_PUB, CONSUMER_DID = _gen()
PRODUCER_PRIV, PRODUCER_PUB, PRODUCER_DID = _gen()

ENV = "test"
SERVICE_ID = "my-service"
BODY = b'{"hello": "world"}'
URL = "http://producer.local:8080/api/resource"
METHOD = "POST"


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign_jwt(header: dict, payload: dict, priv_bytes: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _Key
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = _Key.from_private_bytes(priv_bytes).sign(signing_input)
    return f"{h}.{p}.{_b64url(sig)}"


def _build_proof(jti: str, body: bytes, url: str = URL, now: float | None = None) -> str:
    """Build a valid SentinelProof JWT."""
    from common.security_envelope.builder import compute_body_hash, compute_query_hash

    now = now or time.time()
    header = {"alg": "EdDSA", "typ": "sentinel-proof+jwt", "kid": f"{CONSUMER_DID}#key"}
    payload = {
        "iss": CONSUMER_DID,
        "aud": PRODUCER_DID,
        "env": ENV,
        "jti": jti,
        "iat": int(now),
        "exp": int(now) + 60,
        "htm": METHOD,
        "htu": url.split("?")[0],
        "bh": compute_body_hash(body),
        "qsh": compute_query_hash(url),
    }
    return _sign_jwt(header, payload, CONSUMER_PRIV)


def _build_vp(jti: str) -> str:
    """Build a valid VP JWT with nonce=jti."""
    from common.vc_engine.builder import create_vp
    return create_vp(
        vcs=[],
        holder_did=CONSUMER_DID,
        holder_key_bytes=CONSUMER_PRIV,
        aud=PRODUCER_DID,
        nonce=jti,
        env=ENV,
        exp_seconds=300,
    )


def _headers(proof_jwt: str, vp_jwt: str, extra: dict | None = None) -> dict:
    h = {
        "authorization": f"SentinelProof {proof_jwt}",
        "sentinelvp": vp_jwt,
        "content-type": "application/json",
        "host": "producer.local:8080",
    }
    if extra:
        h.update(extra)
    return h


# ---------------------------------------------------------------------------
# Pipeline factory
# ---------------------------------------------------------------------------

def _make_pipeline(
    http_client: httpx.AsyncClient,
    replay_cache=None,
    trust_client=None,
    revocation_manager=None,
    backend_url: str = "http://backend:9090",
) -> InboundPipeline:
    from common.security_envelope.replay_cache import ReplayCache
    from common.vc_engine.resolver import DIDResolver

    return InboundPipeline(
        service_did=PRODUCER_DID,
        service_id=SERVICE_ID,
        env=ENV,
        resolver=DIDResolver(),
        replay_cache=replay_cache or ReplayCache(redis_client=None),
        trust_client=trust_client,
        revocation_manager=revocation_manager,
        http_client=http_client,
        backend_url=backend_url,
        max_clock_skew=300,
    )


def _mock_request(
    body: bytes = BODY,
    headers: dict | None = None,
    url: str = URL,
    method: str = METHOD,
) -> MagicMock:
    """Create a partial mock of a FastAPI Request."""
    req = MagicMock()
    req.method = method
    req.url = MagicMock()
    req.url.__str__ = lambda self: url
    req.url.query = ""
    req.body = AsyncMock(return_value=body)
    # Use httpx.Headers for case-insensitive header lookup (matches FastAPI behaviour)
    req.headers = httpx.Headers(headers or {})
    return req


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestInboundPipelinePermit:
    """Test 1: Valid request → 200 forwarded from backend."""

    async def test_permit_valid_request(self, httpx_mock):
        httpx_mock.add_response(status_code=200, json={"status": "ok"})

        jti = str(uuid.uuid4())
        proof_jwt = _build_proof(jti, BODY)
        vp_jwt = _build_vp(jti)
        req_headers = _headers(proof_jwt, vp_jwt)

        async with httpx.AsyncClient() as client:
            pipeline = _make_pipeline(client)
            request = _mock_request(headers=req_headers)
            response = await pipeline.process(request, "api/resource")

        assert response.status_code == 200


class TestMissingProofHeader:
    """Test 2: Missing SentinelProof → 401 MISSING_PROOF."""

    async def test_missing_proof(self):
        jti = str(uuid.uuid4())
        vp_jwt = _build_vp(jti)
        req_headers = {"sentinelvp": vp_jwt, "content-type": "application/json"}

        async with httpx.AsyncClient() as client:
            pipeline = _make_pipeline(client)
            request = _mock_request(headers=req_headers)
            response = await pipeline.process(request, "api/resource")

        assert response.status_code == 401
        body = json.loads(response.body)
        assert body["error"] == "MISSING_PROOF"


class TestMissingVPHeader:
    """Test 3: Missing SentinelVP → 401 MISSING_VP."""

    async def test_missing_vp(self):
        jti = str(uuid.uuid4())
        proof_jwt = _build_proof(jti, BODY)
        req_headers = {"authorization": f"SentinelProof {proof_jwt}"}

        async with httpx.AsyncClient() as client:
            pipeline = _make_pipeline(client)
            request = _mock_request(headers=req_headers)
            response = await pipeline.process(request, "api/resource")

        assert response.status_code == 401
        body = json.loads(response.body)
        assert body["error"] == "MISSING_VP"


class TestTamperedBody:
    """Test 4: Tampered body → 401 BODY_HASH_MISMATCH."""

    async def test_body_hash_mismatch(self):
        jti = str(uuid.uuid4())
        # Build proof over original body
        proof_jwt = _build_proof(jti, BODY)
        vp_jwt = _build_vp(jti)
        req_headers = _headers(proof_jwt, vp_jwt)

        # Send a DIFFERENT body
        tampered_body = b'{"malicious": "payload"}'

        async with httpx.AsyncClient() as client:
            pipeline = _make_pipeline(client)
            request = _mock_request(body=tampered_body, headers=req_headers)
            response = await pipeline.process(request, "api/resource")

        assert response.status_code == 401
        body = json.loads(response.body)
        assert body["error"] == "BODY_HASH_MISMATCH"


class TestExpiredProof:
    """Test 5: Expired proof → 401 PROOF_EXPIRED."""

    async def test_expired_proof(self):
        jti = str(uuid.uuid4())
        # Build proof that was valid 2 minutes ago (expired)
        past = time.time() - 120
        proof_jwt = _build_proof(jti, BODY, now=past)
        vp_jwt = _build_vp(jti)
        req_headers = _headers(proof_jwt, vp_jwt)

        async with httpx.AsyncClient() as client:
            pipeline = _make_pipeline(client)
            request = _mock_request(headers=req_headers)
            response = await pipeline.process(request, "api/resource")

        assert response.status_code == 401
        body = json.loads(response.body)
        assert body["error"] == "PROOF_EXPIRED"


class TestReplayDetection:
    """Test 6: Same jti used twice → second attempt gets 401 REPLAY_DETECTED."""

    async def test_replay_rejected(self, httpx_mock):
        httpx_mock.add_response(status_code=200, json={"ok": True})

        from common.security_envelope.replay_cache import ReplayCache
        from common.vc_engine.resolver import DIDResolver

        replay_cache = ReplayCache(redis_client=None)  # shared between requests

        jti = str(uuid.uuid4())
        proof_jwt = _build_proof(jti, BODY, url="http://producer.local:8080/resource")
        vp_jwt = _build_vp(jti)
        req_headers = _headers(proof_jwt, vp_jwt)

        async with httpx.AsyncClient() as client:
            pipeline = _make_pipeline(client, replay_cache=replay_cache)

            # First request succeeds
            req1 = _mock_request(headers=req_headers, url="http://producer.local:8080/resource")
            resp1 = await pipeline.process(req1, "resource")
            assert resp1.status_code == 200

            # Second request with SAME jti is rejected
            req2 = _mock_request(headers=req_headers, url="http://producer.local:8080/resource")
            resp2 = await pipeline.process(req2, "resource")

        assert resp2.status_code == 401
        body = json.loads(resp2.body)
        assert body["error"] == "REPLAY_DETECTED"


class TestBodyTooLarge:
    """Test 7: Body over 2MB → 413 REQUEST_TOO_LARGE."""

    async def test_body_over_limit(self):
        # Set content-length > 2MB so the pipeline rejects at Stage 1
        # before computing any proof hashes (avoids ProofError in test setup)
        big_size = 2 * 1024 * 1024 + 1
        req_headers = {"content-length": str(big_size)}

        async with httpx.AsyncClient() as client:
            pipeline = _make_pipeline(client)
            request = _mock_request(body=b"placeholder", headers=req_headers)
            response = await pipeline.process(request, "resource")

        assert response.status_code == 413
        body = json.loads(response.body)
        assert body["error"] == "REQUEST_TOO_LARGE"


class TestBackendUnavailable:
    """Test 8: Backend unreachable → 502."""

    async def test_backend_error(self, httpx_mock):
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))

        jti = str(uuid.uuid4())
        proof_jwt = _build_proof(jti, BODY)
        vp_jwt = _build_vp(jti)
        req_headers = _headers(proof_jwt, vp_jwt)

        async with httpx.AsyncClient() as client:
            pipeline = _make_pipeline(client)
            request = _mock_request(headers=req_headers)
            response = await pipeline.process(request, "api/resource")

        assert response.status_code == 502
        body = json.loads(response.body)
        assert body["error"] == "BACKEND_UNAVAILABLE"
