"""ProofVerifier — producer-side security envelope verification (TASK-043).

Implements the 12-step verification procedure:
  1.  Extract `Authorization: SentinelProof <jwt>`
  2.  Decode JWT header (no sig yet) → get iss/kid
  3.  Resolve consumer DID via DIDResolver
  4.  Verify JWT Ed25519 signature
  5.  Check exp > now (PROOF_EXPIRED)
  6.  Check iat <= now + max_clock_skew (CLOCK_SKEW_EXCEEDED)
  7.  Check aud == expected_aud (AUD_MISMATCH — 403)
  8.  Check env == expected_env (ENV_MISMATCH — 403)
  9.  Recompute body_hash and compare with bh claim (BODY_HASH_MISMATCH)
  10. Recompute query_hash and compare with qsh claim (QUERY_HASH_MISMATCH)
  11. Check jti not in replay cache (REPLAY_DETECTED); insert if new
  12. Verify SentinelVP (VP nonce == proof.jti)
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import time
from typing import List, Optional

from common.security_envelope.builder import compute_body_hash, compute_query_hash
from common.security_envelope.errors import ProofError, ProofErrorCode
from common.security_envelope.replay_cache import ReplayCache

logger = logging.getLogger(__name__)

_SENTINEL_PROOF_PREFIX = "SentinelProof "
_DEFAULT_MAX_CLOCK_SKEW = 300  # seconds


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class VerificationContext:
    """Successful proof verification result."""
    consumer_did: str
    jti: str
    proof_claims: dict
    verified_vcs: list = dataclasses.field(default_factory=list)


# ---------------------------------------------------------------------------
# JWT decoding helpers
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(padded)


def _decode_jwt_unverified(jwt_str: str) -> tuple[dict, dict, bytes, bytes]:
    """Return (header, payload, signature_bytes, signing_input_bytes)."""
    parts = jwt_str.split(".")
    if len(parts) != 3:
        raise ProofError(ProofErrorCode.SIGNATURE_INVALID, "Not a compact JWT")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        signature = _b64url_decode(parts[2])
        signing_input = f"{parts[0]}.{parts[1]}".encode()
    except (ValueError, Exception) as exc:
        raise ProofError(ProofErrorCode.SIGNATURE_INVALID, f"JWT parse error: {exc}") from exc
    return header, payload, signature, signing_input


def _verify_ed25519(pub_bytes: bytes, signing_input: bytes, signature: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(signature, signing_input)
    except InvalidSignature:
        raise ProofError(ProofErrorCode.SIGNATURE_INVALID, "Ed25519 signature verification failed")
    except Exception as exc:
        raise ProofError(ProofErrorCode.SIGNATURE_INVALID, str(exc)) from exc


# ---------------------------------------------------------------------------
# ProofVerifier
# ---------------------------------------------------------------------------

class ProofVerifier:
    """Verify a ProofClaims JWT and its accompanying VP.

    Args:
        max_clock_skew: Maximum seconds the producer accepts for forward clock drift.
    """

    def __init__(self, max_clock_skew: int = _DEFAULT_MAX_CLOCK_SKEW) -> None:
        self._max_clock_skew = max_clock_skew

    async def verify(
        self,
        *,
        proof_header_value: str,
        vp_header_value: str,
        body: Optional[bytes],
        url: str,
        method: str,
        expected_aud: str,
        expected_env: str,
        resolver,
        replay_cache: ReplayCache,
        trusted_issuer_dids=None,
        now: Optional[float] = None,
    ) -> VerificationContext:
        """Verify the complete security envelope.

        Args:
            proof_header_value:  Full value of the ``Authorization`` header.
            vp_header_value:     Full value of the ``SentinelVP`` header.
            body:                Raw request body bytes.
            url:                 Full request URL (with query string).
            method:              HTTP method (uppercase).
            expected_aud:        Producer's service DID.
            expected_env:        Expected deployment environment.
            resolver:            DIDResolver instance.
            replay_cache:        ReplayCache instance.
            trusted_issuer_dids: Optional set of trusted issuer DIDs for VP/VC verification.
            now:                 Override current time (for testing).

        Returns:
            VerificationContext on success.

        Raises:
            ProofError: on any verification failure.
        """
        now = now if now is not None else time.time()

        # ── Step 1: Extract proof JWT ────────────────────────────────────
        if not proof_header_value.startswith(_SENTINEL_PROOF_PREFIX):
            raise ProofError(ProofErrorCode.MISSING_PROOF, "Missing SentinelProof prefix")
        proof_jwt = proof_header_value[len(_SENTINEL_PROOF_PREFIX):]

        # ── Step 2: Decode header (unverified) ───────────────────────────
        header, claims, signature, signing_input = _decode_jwt_unverified(proof_jwt)

        # Extract consumer DID from the kid claim or iss claim
        kid = header.get("kid", "")
        iss = claims.get("iss", kid.split("#")[0] if kid else "")
        consumer_did = iss or kid.split("#")[0]
        if not consumer_did:
            raise ProofError(ProofErrorCode.SIGNATURE_INVALID, "Cannot determine consumer DID from JWT")

        # ── Step 3+4: Resolve DID and verify signature ───────────────────
        try:
            did_doc = await resolver.resolve(consumer_did)
        except Exception as exc:
            raise ProofError(ProofErrorCode.SIGNATURE_INVALID, f"DID resolution failed: {exc}") from exc

        vm = did_doc.first_verification_method
        if vm is None:
            raise ProofError(ProofErrorCode.SIGNATURE_INVALID, "No verification method for DID")

        _verify_ed25519(vm.public_key_bytes, signing_input, signature)

        # ── Step 5: Check exp ────────────────────────────────────────────
        exp = claims.get("exp")
        if exp is None or float(exp) < now:
            raise ProofError(ProofErrorCode.PROOF_EXPIRED, f"Proof expired at {exp}")

        # ── Step 6: Check iat (clock skew) ───────────────────────────────
        iat = claims.get("iat", 0)
        if float(iat) > now + self._max_clock_skew:
            raise ProofError(
                ProofErrorCode.CLOCK_SKEW_EXCEEDED,
                f"iat={iat} exceeds max_clock_skew={self._max_clock_skew}",
            )

        # ── Step 7: Check aud (constant-time) ────────────────────────────
        proof_aud = claims.get("aud", "")
        if not hmac.compare_digest(proof_aud, expected_aud):
            raise ProofError(ProofErrorCode.AUD_MISMATCH, "aud mismatch")

        # ── Step 8: Check env ────────────────────────────────────────────
        proof_env = claims.get("env", "")
        if proof_env != expected_env:
            raise ProofError(ProofErrorCode.ENV_MISMATCH, f"env mismatch: {proof_env!r} != {expected_env!r}")

        # ── Step 9: Body hash ────────────────────────────────────────────
        expected_bh = compute_body_hash(body)
        if claims.get("bh", "") != expected_bh:
            raise ProofError(ProofErrorCode.BODY_HASH_MISMATCH, "Body hash does not match")

        # ── Step 10: Query hash ──────────────────────────────────────────
        expected_qsh = compute_query_hash(url)
        if claims.get("qsh", "") != expected_qsh:
            raise ProofError(ProofErrorCode.QUERY_HASH_MISMATCH, "Query hash does not match")

        # ── Step 11: Replay cache ────────────────────────────────────────
        jti = claims.get("jti", "")
        ttl = max(1, int(float(exp) - float(iat)) + self._max_clock_skew)
        is_new = await replay_cache.check_and_insert(jti, iss=consumer_did, aud=expected_aud, ttl_seconds=ttl)
        if not is_new:
            raise ProofError(ProofErrorCode.REPLAY_DETECTED, f"JTI {jti!r} already seen")

        # ── Step 12: Verify VP ───────────────────────────────────────────
        if not vp_header_value:
            raise ProofError(ProofErrorCode.MISSING_VP, "SentinelVP header missing")

        from common.vc_engine.errors import VCError, VPError

        if "~" in vp_header_value:
            # SD-JWT presentation path (KB-JWT binds the same jti as nonce)
            from common.vc_engine.sd_jwt import verify_sd_jwt_with_kb

            try:
                verified_vc = await verify_sd_jwt_with_kb(
                    presentation=vp_header_value,
                    trusted_issuer_dids=trusted_issuer_dids or set(),
                    resolver=resolver,
                    aud=expected_aud,
                    nonce=jti,
                    now=now,
                )
            except VCError as exc:
                raise ProofError(ProofErrorCode.VP_INVALID, str(exc)) from exc
            except Exception as exc:
                raise ProofError(ProofErrorCode.VP_INVALID, str(exc)) from exc

            return VerificationContext(
                consumer_did=consumer_did,
                jti=jti,
                proof_claims=claims,
                verified_vcs=[verified_vc],
            )

        # W3C VP path (classic SentinelVP)
        from common.vc_engine.verifier import verify_vp

        try:
            verified_vcs_set = trusted_issuer_dids or set()
            vp = await verify_vp(
                vp_jwt=vp_header_value,
                expected_aud=expected_aud,
                expected_nonce=jti,
                expected_env=expected_env,
                resolver=resolver,
                trusted_issuer_dids=verified_vcs_set,
                now=now,
            )
        except VPError as exc:
            raise ProofError(ProofErrorCode.VP_INVALID, str(exc)) from exc
        except VCError as exc:
            raise ProofError(ProofErrorCode.VP_VC_INVALID, str(exc)) from exc
        except Exception as exc:
            raise ProofError(ProofErrorCode.VP_INVALID, str(exc)) from exc

        return VerificationContext(
            consumer_did=consumer_did,
            jti=jti,
            proof_claims=claims,
            verified_vcs=vp.vcs,
        )
