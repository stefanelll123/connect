"""ProofClaims JWT verifier for the Producer Sentinel.

Implements the 11-step verification procedure defined in
docs/protocols/request-security-envelope.md §5.

Step ordering is security-critical:
  1. Structural decode (garbled tokens rejected cheaply)
  2. Algorithm / typ check (before any key operations)
  3. Signature check (authenticates the issuer)
  4. Expiry / iat freshness checks (time-bounding attacks)
  5. TTL-length check (reject unusually long-lived proofs)
  6. Audience check (binding to this producer)
  7. Environment check (prevents cross-env replay)
  8. Body hash verification (binds proof to request body)
  9. Replay cache lookup (detects replayed proofs)
 10. Replay cache INSERT — MUST happen before backend forwarding
 11. Parse and return typed ProofClaims

"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from common.crypto.jws import JWSVerificationError, verify_jws
from common.proof.hash_utils import hash_bytes
from common.proof.models import DEFAULT_PROOF_TTL, MAX_PROOF_TTL, PROOF_TYP, ProofClaims
from common.proof.replay_cache import InMemoryReplayCache, ReplayCache, make_cache_key

__all__ = [
    "ProofVerificationError",
    "VerificationConfig",
    "verify_proof",
]

# Default maximum clock skew tolerance (seconds).
DEFAULT_CLOCK_SKEW = 5


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class ProofVerificationError(ValueError):
    """Raised when a ProofClaims JWT fails any step of verification.

    Attributes:
        code: Machine-readable error code (see spec §error-handling).
        http_status: Recommended HTTP status code to return to the caller.
    """

    _STATUS_MAP: dict[str, int] = {
        "MISSING_PROOF": 401,
        "MISSING_VP": 401,
        "PROOF_ALG_PROHIBITED": 400,
        "PROOF_SIGNATURE_INVALID": 401,
        "PROOF_EXPIRED": 401,
        "PROOF_NOT_YET_VALID": 401,
        "PROOF_TTL_TOO_LONG": 400,
        "AUD_MISMATCH": 403,
        "ENV_MISMATCH": 403,
        "BODY_HASH_MISMATCH": 400,
        "REPLAY_DETECTED": 401,
        "NONCE_INVALID": 401,
    }

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.http_status: int = self._STATUS_MAP.get(code, 400)
        super().__init__(f"{code}: {detail}" if detail else code)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationConfig:
    """Tunable parameters for ProofClaims verification.

    Attributes:
        max_clock_skew: Tolerance for clock drift between Consumer and
            Producer (seconds).  Default: 5.
        max_proof_ttl: Maximum acceptable ``exp - iat`` value (seconds).
            VCs from TrustPolicyRegistry may lower this; default is the
            hard cap (:data:`~common.proof.models.MAX_PROOF_TTL`).
        allowed_envs: If non-empty, ``env`` must be in this set.
            Typically contains exactly one value — the Producer's env.
    """

    max_clock_skew: int = DEFAULT_CLOCK_SKEW
    max_proof_ttl: int = MAX_PROOF_TTL
    allowed_envs: frozenset[str] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url_decode(text: str) -> bytes:
    padding = 4 - len(text) % 4
    if padding != 4:
        text += "=" * padding
    return base64.urlsafe_b64decode(text)


def _decode_header(token: str) -> dict:
    """Decode the JOSE header of *token* without verifying the signature."""
    try:
        header_b64 = token.split(".")[0]
        return json.loads(_b64url_decode(header_b64))
    except Exception as exc:
        raise ProofVerificationError("PROOF_SIGNATURE_INVALID", str(exc)) from exc


# ---------------------------------------------------------------------------
# Main verification function
# ---------------------------------------------------------------------------


def verify_proof(
    jwt: str,
    consumer_public_key: Ed25519PublicKey,
    *,
    producer_did: str,
    producer_env: str,
    body: bytes = b"",
    replay_cache: Optional[ReplayCache] = None,
    config: Optional[VerificationConfig] = None,
    expected_nonce: Optional[str] = None,
) -> ProofClaims:
    """Verify a ProofClaims JWT according to the 11-step procedure.

    Args:
        jwt: Compact JWS from the ``Authorization: SentinelProof`` header.
        consumer_public_key: Ed25519 public key corresponding to the
            Consumer Sentinel's DID.  Derived from ``did:key`` via
            :func:`~common.crypto.did_key.did_key_to_public_key`.
        producer_did: This Producer Sentinel's DID — checked against ``aud``.
        producer_env: This Producer's deployment environment — checked
            against ``env``.
        body: Raw request body bytes (as received from the wire).  Used to
            recompute and verify ``req.body_hash``.
        replay_cache: JTI replay cache.  If ``None``, an ephemeral
            :class:`~common.proof.replay_cache.InMemoryReplayCache` is used
            (useful in unit tests; **not** safe for production).
        config: Verification tuning parameters.  Defaults to
            :class:`VerificationConfig` with factory defaults.
        expected_nonce: If the Producer manages session nonces, pass the
            expected value here.  ``None`` skips nonce validation.

    Returns:
        Typed :class:`~common.proof.models.ProofClaims` on success.

    Raises:
        ProofVerificationError: On any verification failure.  Check
            ``.code`` for the machine-readable reason.
    """
    if replay_cache is None:
        replay_cache = InMemoryReplayCache()
    if config is None:
        config = VerificationConfig()

    # ------------------------------------------------------------------ 1
    # Structural decode + typ check (before signature, cheap rejection)
    # ------------------------------------------------------------------ 1
    header = _decode_header(jwt)
    typ = header.get("typ", "")
    if typ != PROOF_TYP:
        raise ProofVerificationError(
            "PROOF_ALG_PROHIBITED",
            f"Expected typ={PROOF_TYP!r}, got {typ!r}.",
        )

    # ------------------------------------------------------------------ 2
    # Signature verification
    # ------------------------------------------------------------------ 2
    try:
        claims_raw = verify_jws(jwt, consumer_public_key)
    except (JWSVerificationError, Exception) as exc:
        raise ProofVerificationError("PROOF_SIGNATURE_INVALID", str(exc)) from exc

    # ------------------------------------------------------------------ 3–4
    # Time checks: expiry and freshness
    # ------------------------------------------------------------------ 3–4
    now = int(time.time())
    exp = claims_raw.get("exp", 0)
    iat = claims_raw.get("iat", 0)

    if now > exp + config.max_clock_skew:
        raise ProofVerificationError(
            "PROOF_EXPIRED",
            f"Proof expired at {exp}; now={now}.",
        )
    if iat > now + config.max_clock_skew:
        raise ProofVerificationError(
            "PROOF_NOT_YET_VALID",
            f"iat={iat} is more than {config.max_clock_skew}s in the future (now={now}).",
        )

    # ------------------------------------------------------------------ 5
    # TTL-length check
    # ------------------------------------------------------------------ 5
    proof_ttl = exp - iat
    if proof_ttl > config.max_proof_ttl:
        raise ProofVerificationError(
            "PROOF_TTL_TOO_LONG",
            f"exp - iat = {proof_ttl}s exceeds max {config.max_proof_ttl}s.",
        )

    # ------------------------------------------------------------------ 6
    # Audience check
    # ------------------------------------------------------------------ 6
    if claims_raw.get("aud") != producer_did:
        raise ProofVerificationError(
            "AUD_MISMATCH",
            f"aud={claims_raw.get('aud')!r} != expected {producer_did!r}.",
        )

    # ------------------------------------------------------------------ 7
    # Environment check
    # ------------------------------------------------------------------ 7
    if claims_raw.get("env") != producer_env:
        raise ProofVerificationError(
            "ENV_MISMATCH",
            f"env={claims_raw.get('env')!r} != expected {producer_env!r}.",
        )

    # ------------------------------------------------------------------ 8
    # Body hash verification
    # ------------------------------------------------------------------ 8
    req_raw = claims_raw.get("req", {})
    claimed_body_hash = req_raw.get("body_hash", "")
    actual_body_hash = hash_bytes(body)
    if not _constant_time_compare(claimed_body_hash, actual_body_hash):
        raise ProofVerificationError(
            "BODY_HASH_MISMATCH",
            "Recomputed body hash does not match req.body_hash.",
        )

    # ------------------------------------------------------------------ 9 & 10
    # Replay detection — check THEN insert (TOCTOU-safe via lock in impl)
    # ------------------------------------------------------------------ 9 & 10
    jti = claims_raw.get("jti", "")
    iss = claims_raw.get("iss", "")
    cache_key = make_cache_key(jti, iss)

    # TTL = proof_ttl + clock_skew + buffer(5)
    cache_ttl = proof_ttl + config.max_clock_skew + 5

    # mark_seen returns False if the key already existed → replay
    inserted = replay_cache.mark_seen(cache_key, cache_ttl)
    if not inserted:
        raise ProofVerificationError(
            "REPLAY_DETECTED",
            f"jti={jti!r} has already been seen in the replay window.",
        )

    # ------------------------------------------------------------------ 11
    # Optional nonce validation
    # ------------------------------------------------------------------ 11
    if expected_nonce is not None:
        proof_nonce = claims_raw.get("nonce")
        if proof_nonce is None or not _constant_time_compare(proof_nonce, expected_nonce):
            raise ProofVerificationError(
                "NONCE_INVALID",
                "Proof nonce is absent or does not match the expected session nonce.",
            )

    # ------------------------------------------------------------------ 12
    # Parse and return typed ProofClaims
    # ------------------------------------------------------------------ 12
    try:
        return ProofClaims.model_validate(claims_raw)
    except Exception as exc:
        raise ProofVerificationError("PROOF_SIGNATURE_INVALID", str(exc)) from exc


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time to prevent timing oracles."""
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())
