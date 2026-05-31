"""Onboarding Proof-of-Possession (PoP) JWT creation and verification.

The PoP proof is a compact JWS signed by the Sentinel's DID private key.
It binds together: the Sentinel's DID, the Discovery service DID (aud),
the enrollment token JTI (token_id), and a one-time challenge.

Security invariants enforced here:

* ``proof.exp - proof.iat`` must not exceed :data:`PROOF_MAX_TTL` (120 s) —
  longer-lived proofs are unconditionally rejected.
* ``proof.aud`` must exactly match the expected Discovery DID.
* ``proof.challenge`` is compared in constant-time via ``hmac.compare_digest``
  to prevent timing-based oracle attacks against the challenge value.
* ``proof.token_id`` must exactly match the enrollment token ``jti``.
"""

from __future__ import annotations

import hmac
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, Field

from common.crypto.jws import JWSVerificationError, sign_jws, verify_jws

# Maximum allowed lifetime for a PoP proof JWT (seconds).
PROOF_MAX_TTL = 120


class OnboardingProofError(ValueError):
    """Raised when a PoP proof fails any validation check."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


class OnboardingProofClaims(BaseModel):
    """Decoded and validated claims from an onboarding PoP proof JWT."""

    model_config = {"frozen": True}

    iss: str = Field(pattern=r"^did:", description="Sentinel DID.")
    aud: str = Field(pattern=r"^did:", description="Discovery DID.")
    iat: int = Field(ge=0)
    exp: int = Field(ge=0)
    token_id: str = Field(description="jti from the accompanying enrollment token.")
    challenge: str = Field(description="base64url challenge received from Discovery.")


def create_onboarding_proof(
    private_key: Ed25519PrivateKey,
    *,
    sentinel_did: str,
    kid: str,
    discovery_did: str,
    token_id: str,
    challenge: str,
    ttl: int = PROOF_MAX_TTL,
) -> str:
    """Create and sign a PoP proof JWT.

    Args:
        private_key: Sentinel's Ed25519 DID private key.
        sentinel_did: ``did:key:z6Mk...`` — becomes ``iss``.
        kid: Verification method ID (``did:key:...#...``).
        discovery_did: Discovery service DID — becomes ``aud``.
        token_id: ``jti`` from the enrollment token — bound into proof.
        challenge: Server challenge received in Phase 1 response.
        ttl: Proof lifetime in seconds; capped at :data:`PROOF_MAX_TTL`.

    Returns:
        Compact JWS string.
    """
    if ttl <= 0 or ttl > PROOF_MAX_TTL:
        raise ValueError(f"ttl must be 1–{PROOF_MAX_TTL} seconds, got {ttl}.")
    now = int(time.time())
    claims: dict = {
        "iss": sentinel_did,
        "aud": discovery_did,
        "iat": now,
        "exp": now + ttl,
        "token_id": token_id,
        "challenge": challenge,
    }
    return sign_jws(claims, private_key, kid=kid, extra_headers={"typ": "onboard-proof+jwt"})


def verify_onboarding_proof(
    proof_jwt: str,
    sentinel_public_key: Ed25519PublicKey,
    *,
    expected_discovery_did: str,
    expected_token_id: str,
    expected_challenge: str,
) -> OnboardingProofClaims:
    """Verify a PoP proof JWT and return :class:`OnboardingProofClaims`.

    Performs, in order:

    1. JWS signature verification.
    2. Expiry check.
    3. Proof TTL check (``exp - iat ≤ 120``).
    4. Audience check (``aud == expected_discovery_did``).
    5. Challenge comparison (constant-time).
    6. Token-ID comparison.

    :raises OnboardingProofError: with a machine-readable ``code`` on any failure.
    """
    try:
        payload = verify_jws(proof_jwt, sentinel_public_key)
    except JWSVerificationError as exc:
        raise OnboardingProofError("PROOF_SIGNATURE_INVALID", str(exc)) from exc

    now = int(time.time())

    # Expiry check.
    if payload.get("exp", 0) < now:
        raise OnboardingProofError("PROOF_INVALID", "Proof JWT has expired.")

    # Proof TTL must not exceed PROOF_MAX_TTL.
    iat = payload.get("iat", 0)
    exp = payload.get("exp", 0)
    if exp - iat > PROOF_MAX_TTL:
        raise OnboardingProofError(
            "PROOF_INVALID",
            f"Proof TTL {exp - iat}s exceeds maximum {PROOF_MAX_TTL}s.",
        )

    # Audience check — must exactly match Discovery DID.
    if payload.get("aud", "") != expected_discovery_did:
        raise OnboardingProofError(
            "PROOF_INVALID",
            "proof.aud does not match Discovery DID.",
        )

    # Challenge comparison — constant-time to prevent timing oracles.
    received_challenge = payload.get("challenge", "")
    if not hmac.compare_digest(
        received_challenge.encode(),
        expected_challenge.encode(),
    ):
        raise OnboardingProofError("PROOF_INVALID", "Challenge mismatch.")

    # Token-ID binding.
    if payload.get("token_id", "") != expected_token_id:
        raise OnboardingProofError("TOKEN_MISMATCH", "proof.token_id does not match enrollment token jti.")

    try:
        return OnboardingProofClaims(**payload)
    except Exception as exc:
        raise OnboardingProofError("PROOF_INVALID", str(exc)) from exc
