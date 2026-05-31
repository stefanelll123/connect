"""ProofClaimsBuilder — consumer-side request security envelope (TASK-043).

Builds and signs a ProofClaims JWT that cryptographically binds:
  - HTTP method, URL, query string hash, body hash
  - iat / exp / jti (replay protection)
  - aud (producer DID), env

The signed JWT is sent in the ``Authorization: SentinelProof <jwt>`` header.
A separately constructed VP goes in the ``SentinelVP`` header.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlparse

from common.security_envelope.errors import ProofError, ProofErrorCode

# 2 MB hard limit for hashing request bodies
MAX_BODY_SIZE = 2 * 1024 * 1024  # 2 MB


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def compute_body_hash(body: Optional[bytes]) -> str:
    """Return SHA-256 hex of *body*, or '' if body is empty/None.

    Raises:
        ProofError(BODY_TOO_LARGE): if body exceeds MAX_BODY_SIZE.
    """
    if not body:
        return ""
    if len(body) > MAX_BODY_SIZE:
        raise ProofError(ProofErrorCode.BODY_TOO_LARGE, f"Body size {len(body)} exceeds {MAX_BODY_SIZE}")
    return hashlib.sha256(body).hexdigest()


def compute_query_hash(url: str) -> str:
    """Return SHA-256 hex of the canonicalised query string, or '' if none.

    Canonical form: alphabetically sorted key=value pairs joined with '&'.
    """
    parsed = urlparse(url)
    if not parsed.query:
        return ""
    params = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    canonical = urlencode(params)
    return hashlib.sha256(canonical.encode()).hexdigest()


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign_jwt(header: dict, payload: dict, private_key_bytes: bytes) -> str:
    """Sign *header* + *payload* as a compact JWT with Ed25519 (EdDSA)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    privkey = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    sig = privkey.sign(signing_input)
    return f"{header_b64}.{payload_b64}.{_b64url(sig)}"


# ---------------------------------------------------------------------------
# ProofClaimsBuilder
# ---------------------------------------------------------------------------

class ProofClaimsBuilder:
    """Build and sign a ProofClaims JWT for a single outbound request.

    Args:
        consumer_did:       The consumer sentinel's DID (iss + kid prefix).
        private_key_bytes:  Raw 32-byte Ed25519 private key.
        key_fragment:       Short fragment for the ``kid`` header (default: first 8 chars of DID method-specific-id).
    """

    def __init__(
        self,
        consumer_did: str,
        private_key_bytes: bytes,
        key_fragment: Optional[str] = None,
    ) -> None:
        self._did = consumer_did
        self._key = private_key_bytes
        if key_fragment is None:
            # Use characters after "did:key:z" prefix (or fallback)
            if consumer_did.startswith("did:key:z"):
                key_fragment = consumer_did[9:17]
            else:
                key_fragment = "key-1"
        self._kid = f"{consumer_did}#{key_fragment}"

    def build(
        self,
        method: str,
        url: str,
        body: Optional[bytes],
        aud: str,
        env: str,
        jti: Optional[str] = None,
        exp_seconds: int = 60,
    ) -> tuple[str, dict]:
        """Build and sign a ProofClaims JWT.

        Args:
            method:       HTTP method (uppercased).
            url:          Full request URL (including query string).
            body:         Raw request body bytes.
            aud:          Producer service DID.
            env:          Deployment environment.
            jti:          Explicit jti (generated if not provided).
            exp_seconds:  Proof TTL (default 60s).

        Returns:
            Tuple of ``(proof_jwt, claims_dict)``.
        """
        now = int(time.time())
        jti = jti or str(uuid.uuid4())

        # Strip query string from htu (URL without query)
        parsed = urlparse(url)
        htu = parsed._replace(query="", fragment="").geturl()

        claims = {
            "jti": jti,
            "iat": now,
            "exp": now + exp_seconds,
            "aud": aud,
            "env": env,
            "htm": method.upper(),
            "htu": htu,
            "qsh": compute_query_hash(url),
            "bh": compute_body_hash(body),
        }

        header = {
            "alg": "EdDSA",
            "typ": "sentinel-proof+jwt",
            "kid": self._kid,
        }

        proof_jwt = _sign_jwt(header, claims, self._key)
        return proof_jwt, claims


# ---------------------------------------------------------------------------
# Secure headers helper
# ---------------------------------------------------------------------------

def build_secure_headers(proof_jwt: str, vp_jwt: str) -> dict:
    """Build request headers that carry the security envelope.

    Returns:
        Dict with ``Authorization`` and ``SentinelVP`` keys.
    """
    return {
        "Authorization": f"SentinelProof {proof_jwt}",
        "SentinelVP": vp_jwt,
    }


# ---------------------------------------------------------------------------
# SD-JWT helpers
# ---------------------------------------------------------------------------

def is_sd_jwt(s: str) -> bool:
    """Return True if *s* looks like an SD-JWT or SD-JWT presentation.

    Both the issuer SD-JWT (``header.payload.sig``) stored in the credential
    store and a full presentation (``SD-JWT~[disclosures~]KB-JWT``) are
    detected by the presence of a ``~`` character, OR by the ``typ: sd+jwt``
    header claim.
    """
    if not isinstance(s, str):
        return False
    if "~" in s:
        return True
    # Check typ header without full decode
    try:
        import base64
        import json
        header_b64 = s.split(".")[0]
        padded = header_b64 + "=" * (4 - len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
        return header.get("typ", "").lower() in ("sd+jwt",)
    except Exception:
        return False


def extract_sd_jwt_payload(s: str) -> dict:
    """Decode the payload of an SD-JWT (or presentation) without verification.

    For a full presentation ``SD-JWT~[disclosures~]KB-JWT``, the SD-JWT part
    is everything before the first ``~``.

    Returns an empty dict on any decode error.
    """
    try:
        import base64
        import json
        jwt_part = s.split("~")[0]
        parts = jwt_part.split(".")
        if len(parts) != 3:
            return {}
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}

