"""Security pipeline for the Sentinel Node (TASK-037).

Provides:
- ``VerificationPipeline``: validate inbound requests in producer mode.
- ``SigningPipeline``:       build VP envelopes for consumer mode outbound calls.

Both are designed to be extended with real DID/VP verification logic.
The stubs below provide safe, testable skeletons.
"""
from __future__ import annotations

import dataclasses
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi import Request
    from sentinel.config import SentinelSettings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class VerificationResult:
    passed: bool
    reason: str = ""
    consumer_did: str = ""


# ---------------------------------------------------------------------------
# VerificationPipeline — producer mode
# ---------------------------------------------------------------------------

class VerificationPipeline:
    """Validate an inbound HTTP request.

    Current checks (extensible):
    1. Presence of ``Authorization: Bearer <token>`` header.
    2. Token format validation (stub — replace with real DID/VP check).
    3. Optional: check token is not in revocation list.
    """

    def __init__(self, settings: "SentinelSettings") -> None:
        self._settings = settings

    async def verify(self, request: "Request") -> VerificationResult:
        auth = request.headers.get("Authorization", "")

        if auth.startswith("Bearer "):
            token = auth[7:]
            if not token:
                return VerificationResult(passed=False, reason="Empty Bearer token")
            consumer_did = _extract_did(token)
            logger.debug(
                "VerificationPipeline: Bearer token accepted consumer_did=%s",
                consumer_did or "<unknown>",
            )
            return VerificationResult(passed=True, consumer_did=consumer_did)

        if auth.startswith("SentinelProof "):
            return await self._verify_proof_envelope(request, auth)

        return VerificationResult(passed=False, reason="Missing Bearer token")

    async def _verify_proof_envelope(self, request: "Request", auth: str) -> VerificationResult:
        """Verify a SentinelProof + SentinelVP envelope using ProofVerifier."""
        from common.security_envelope.replay_cache import ReplayCache
        from common.security_envelope.verifier import ProofVerifier
        from common.vc_engine.resolver import DIDResolver

        vp_header = request.headers.get("SentinelVP", "")
        body = await request.body()
        url = str(request.url)
        method = request.method

        replay_cache = getattr(request.app.state, "replay_cache", None) or ReplayCache()
        trusted_dids: set = set()

        verifier = ProofVerifier()
        try:
            ctx = await verifier.verify(
                proof_header_value=auth,
                vp_header_value=vp_header,
                body=body,
                url=url,
                method=method,
                expected_aud=self._settings.sentinel_did or "",
                expected_env=self._settings.env,
                resolver=DIDResolver(),
                replay_cache=replay_cache,
                trusted_issuer_dids=trusted_dids,
            )
            logger.debug(
                "VerificationPipeline: SentinelProof verified consumer_did=%s",
                ctx.consumer_did,
            )
            return VerificationResult(passed=True, consumer_did=ctx.consumer_did)
        except Exception as exc:
            logger.warning("SentinelProof verification failed: %s", exc)
            return VerificationResult(passed=False, reason=str(exc))


# ---------------------------------------------------------------------------
# SigningPipeline — consumer mode
# ---------------------------------------------------------------------------

class SigningPipeline:
    """Build a Verifiable Presentation for outbound requests."""

    def __init__(self, settings: "SentinelSettings") -> None:
        self._settings = settings

    async def build_vp(self, descriptor: dict) -> str:
        """Build and sign a Verifiable Presentation token.

        Returns a compact JWT (stub — replace with real LD/JWT-VP signing).
        """
        import base64
        import json
        import time

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()

        payload_data = {
            "iss": self._settings.sentinel_did or self._settings.sentinel_id,
            "sub": descriptor.get("service_did", ""),
            "iat": int(time.time()),
            "exp": int(time.time()) + self._settings.delta_seconds,
            "vp": {"@context": ["https://www.w3.org/2018/credentials/v1"]},
        }
        payload = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode()
        ).rstrip(b"=").decode()

        # Stub: unsigned JWT (alg=none) — replace with real signing
        return f"{header}.{payload}."


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_did(token: str) -> str:
    """Best-effort extraction of 'iss' (DID) from a JWT without verification."""
    import base64
    import json

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return ""
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        return payload.get("iss", "") or payload.get("sub", "")
    except Exception:
        return ""
