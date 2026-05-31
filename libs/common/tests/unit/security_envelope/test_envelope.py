"""Unit tests for the security envelope (TASK-043).

10 adversarial test vectors covering:
  1. Round-trip build+verify succeeds
  2. Tampered body detected (bh mismatch)
  3. Tampered query string detected (qsh mismatch)
  4. Expired proof rejected
  5. Replay of same jti rejected second time
  6. Wrong aud rejected
  7. Missing SentinelVP header rejected
  8. VP nonce mismatch rejected
  9. Clock skew exactly at limit accepted
  10. Clock skew beyond limit rejected
"""
from __future__ import annotations

import base64
import json
import time
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.security_envelope.builder import ProofClaimsBuilder, build_secure_headers
from common.security_envelope.errors import ProofError, ProofErrorCode
from common.security_envelope.replay_cache import ReplayCache
from common.security_envelope.verifier import ProofVerifier
from common.vc_engine.builder import create_vp
from common.vc_engine.resolver import DIDResolver


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    result = []
    while n:
        n, r = divmod(n, 58)
        result.append(_B58_ALPHABET[r])
    for b in data:
        if b == 0:
            result.append(_B58_ALPHABET[0])
        else:
            break
    return "".join(reversed(result))


def _make_did_key(pub_bytes: bytes) -> str:
    prefixed = bytes([0xED, 0x01]) + pub_bytes
    return f"did:key:z{_b58_encode(prefixed)}"


def _gen():
    """Generate (priv_bytes, pub_bytes, did) for a fresh Ed25519 key."""
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = priv.public_key().public_bytes_raw()
    did = _make_did_key(pub_bytes)
    return priv_bytes, pub_bytes, did


CONSUMER_PRIV, CONSUMER_PUB, CONSUMER_DID = _gen()
PRODUCER_PRIV, PRODUCER_PUB, PRODUCER_DID = _gen()

ENV = "test"
URL = "https://producer.example.com/api/v1/resource?b=2&a=1"
BODY = b'{"hello": "world"}'


def _make_verifier() -> ProofVerifier:
    return ProofVerifier(max_clock_skew=300)


def _make_builder() -> ProofClaimsBuilder:
    return ProofClaimsBuilder(CONSUMER_DID, CONSUMER_PRIV)


def _make_replay_cache() -> ReplayCache:
    return ReplayCache(redis_client=None)  # in-memory fallback


def _make_resolver() -> DIDResolver:
    return DIDResolver()  # resolves did:key locally


def _build_vp(jti: str, aud: str = PRODUCER_DID, nonce: str | None = None) -> str:
    return create_vp(
        vcs=[],
        holder_did=CONSUMER_DID,
        holder_key_bytes=CONSUMER_PRIV,
        aud=aud,
        nonce=nonce or jti,
        env=ENV,
        exp_seconds=300,
    )


async def _full_verify(
    proof_jwt: str,
    vp_jwt: str,
    body: bytes = BODY,
    url: str = URL,
    method: str = "POST",
    expected_aud: str = PRODUCER_DID,
    expected_env: str = ENV,
    replay_cache: ReplayCache | None = None,
    now: float | None = None,
):
    verifier = _make_verifier()
    rc = replay_cache or _make_replay_cache()
    return await verifier.verify(
        proof_header_value=f"SentinelProof {proof_jwt}",
        vp_header_value=vp_jwt,
        body=body,
        url=url,
        method=method,
        expected_aud=expected_aud,
        expected_env=expected_env,
        resolver=_make_resolver(),
        replay_cache=rc,
        trusted_issuer_dids=set(),
        now=now,
    )


# ---------------------------------------------------------------------------
# 1. Round-trip succeeds
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_round_trip_succeeds():
    builder = _make_builder()
    jti = str(uuid.uuid4())
    proof_jwt, claims = builder.build("POST", URL, BODY, aud=PRODUCER_DID, env=ENV, jti=jti)
    vp_jwt = _build_vp(jti)

    ctx = await _full_verify(proof_jwt, vp_jwt)
    assert ctx.consumer_did == CONSUMER_DID
    assert ctx.jti == jti


# ---------------------------------------------------------------------------
# 2. Tampered body detected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tampered_body_detected():
    builder = _make_builder()
    jti = str(uuid.uuid4())
    proof_jwt, _ = builder.build("POST", URL, BODY, aud=PRODUCER_DID, env=ENV, jti=jti)
    vp_jwt = _build_vp(jti)

    with pytest.raises(ProofError) as exc_info:
        await _full_verify(proof_jwt, vp_jwt, body=b"tampered body!")
    assert exc_info.value.code == ProofErrorCode.BODY_HASH_MISMATCH


# ---------------------------------------------------------------------------
# 3. Tampered query string detected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tampered_query_string_detected():
    builder = _make_builder()
    jti = str(uuid.uuid4())
    proof_jwt, _ = builder.build("GET", URL, None, aud=PRODUCER_DID, env=ENV, jti=jti)
    vp_jwt = _build_vp(jti)

    # Different URL (different query params)
    tampered_url = "https://producer.example.com/api/v1/resource?a=1&b=EVIL"
    with pytest.raises(ProofError) as exc_info:
        await _full_verify(proof_jwt, vp_jwt, body=None, url=tampered_url, method="GET")
    assert exc_info.value.code == ProofErrorCode.QUERY_HASH_MISMATCH


# ---------------------------------------------------------------------------
# 4. Expired proof rejected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_expired_proof_rejected():
    builder = _make_builder()
    jti = str(uuid.uuid4())
    # Build proof in the far past
    past_now = time.time() - 7200  # 2 hours ago
    proof_jwt, _ = builder.build("POST", URL, BODY, aud=PRODUCER_DID, env=ENV, jti=jti, exp_seconds=60)
    # Verify as of "now" — proof.exp is in the past
    with pytest.raises(ProofError) as exc_info:
        await _full_verify(proof_jwt, vp_jwt=_build_vp(jti), now=time.time() + 7200)
    assert exc_info.value.code == ProofErrorCode.PROOF_EXPIRED


# ---------------------------------------------------------------------------
# 5. Replay of same jti rejected on second attempt
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_replay_rejected():
    builder = _make_builder()
    rc = _make_replay_cache()
    jti = str(uuid.uuid4())
    proof_jwt, _ = builder.build("POST", URL, BODY, aud=PRODUCER_DID, env=ENV, jti=jti)
    vp_jwt = _build_vp(jti)

    # First attempt — accepted
    ctx = await _full_verify(proof_jwt, vp_jwt, replay_cache=rc)
    assert ctx.jti == jti

    # Second attempt with SAME jti — must be rejected
    with pytest.raises(ProofError) as exc_info:
        await _full_verify(proof_jwt, vp_jwt, replay_cache=rc)
    assert exc_info.value.code == ProofErrorCode.REPLAY_DETECTED


# ---------------------------------------------------------------------------
# 6. Wrong aud rejected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_wrong_aud_rejected():
    builder = _make_builder()
    jti = str(uuid.uuid4())
    wrong_aud = "did:key:zWRONGAUDIENCE"
    proof_jwt, _ = builder.build("POST", URL, BODY, aud=PRODUCER_DID, env=ENV, jti=jti)
    vp_jwt = _build_vp(jti)

    with pytest.raises(ProofError) as exc_info:
        await _full_verify(proof_jwt, vp_jwt, expected_aud=wrong_aud)
    assert exc_info.value.code == ProofErrorCode.AUD_MISMATCH


# ---------------------------------------------------------------------------
# 7. Missing SentinelVP header rejected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_missing_vp_rejected():
    builder = _make_builder()
    jti = str(uuid.uuid4())
    proof_jwt, _ = builder.build("POST", URL, BODY, aud=PRODUCER_DID, env=ENV, jti=jti)

    verifier = _make_verifier()
    with pytest.raises(ProofError) as exc_info:
        await verifier.verify(
            proof_header_value=f"SentinelProof {proof_jwt}",
            vp_header_value="",  # empty
            body=BODY,
            url=URL,
            method="POST",
            expected_aud=PRODUCER_DID,
            expected_env=ENV,
            resolver=_make_resolver(),
            replay_cache=_make_replay_cache(),
            trusted_issuer_dids=set(),
        )
    assert exc_info.value.code == ProofErrorCode.MISSING_VP


# ---------------------------------------------------------------------------
# 8. VP nonce mismatch rejected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_vp_nonce_mismatch_rejected():
    builder = _make_builder()
    jti = str(uuid.uuid4())
    proof_jwt, _ = builder.build("POST", URL, BODY, aud=PRODUCER_DID, env=ENV, jti=jti)
    # VP built with DIFFERENT nonce — nonce != jti
    wrong_nonce_vp = _build_vp(jti, nonce=str(uuid.uuid4()))

    with pytest.raises(ProofError) as exc_info:
        await _full_verify(proof_jwt, wrong_nonce_vp)
    assert exc_info.value.code in (ProofErrorCode.VP_INVALID, ProofErrorCode.VP_VC_INVALID)


# ---------------------------------------------------------------------------
# 9. Clock skew exactly at limit accepted
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_clock_skew_at_limit_accepted():
    """iat = now + max_clock_skew should still be accepted."""
    max_skew = 300
    now = time.time()
    builder = _make_builder()
    jti = str(uuid.uuid4())
    proof_jwt, _ = builder.build("POST", URL, BODY, aud=PRODUCER_DID, env=ENV, jti=jti)

    # Decode the proof and adjust iat to exactly now + max_skew
    parts = proof_jwt.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    # We verify at time now - max_skew so that iat (which is ~now) equals verify_time + max_skew
    verify_time = now - max_skew

    vp_jwt = create_vp(
        vcs=[],
        holder_did=CONSUMER_DID,
        holder_key_bytes=CONSUMER_PRIV,
        aud=PRODUCER_DID,
        nonce=jti,
        env=ENV,
        exp_seconds=3600,  # long enough
    )

    verifier = ProofVerifier(max_clock_skew=max_skew)
    # Should NOT raise; iat = verify_time + max_clock_skew (exactly at limit)
    ctx = await verifier.verify(
        proof_header_value=f"SentinelProof {proof_jwt}",
        vp_header_value=vp_jwt,
        body=BODY,
        url=URL,
        method="POST",
        expected_aud=PRODUCER_DID,
        expected_env=ENV,
        resolver=_make_resolver(),
        replay_cache=_make_replay_cache(),
        trusted_issuer_dids=set(),
        now=verify_time,
    )
    assert ctx.consumer_did == CONSUMER_DID


# ---------------------------------------------------------------------------
# 10. Clock skew beyond limit rejected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_clock_skew_beyond_limit_rejected():
    """iat > now + max_clock_skew should be rejected."""
    max_skew = 30  # very small limit
    now = time.time()
    builder = ProofClaimsBuilder(CONSUMER_DID, CONSUMER_PRIV)
    jti = str(uuid.uuid4())
    proof_jwt, _ = builder.build("POST", URL, BODY, aud=PRODUCER_DID, env=ENV, jti=jti)

    # Verify at a time far in the past so iat >> verify_time + max_skew
    verify_time = now - 3600  # verify 1h in the past

    with pytest.raises(ProofError) as exc_info:
        await ProofVerifier(max_clock_skew=max_skew).verify(
            proof_header_value=f"SentinelProof {proof_jwt}",
            vp_header_value=_build_vp(jti),
            body=BODY,
            url=URL,
            method="POST",
            expected_aud=PRODUCER_DID,
            expected_env=ENV,
            resolver=_make_resolver(),
            replay_cache=_make_replay_cache(),
            trusted_issuer_dids=set(),
            now=verify_time,
        )
    assert exc_info.value.code == ProofErrorCode.CLOCK_SKEW_EXCEEDED
