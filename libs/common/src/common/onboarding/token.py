"""Enrollment token and migration ticket creation and validation.

Enrollment tokens are one-time-use JWTs issued by Discovery to authorise
a Sentinel onboarding attempt.  They carry the (service_id, role, env)
binding so that a token issued for a CONSUMER in dev cannot be used to
onboard a PRODUCER in prod.

Security invariants enforced here:

* Token TTL ≤ 600 s by default (configurable, never 0).
* ``hash_token()`` implements SHA-256 of the raw compact token — Discovery
  stores this, never the plaintext.
* ``validate_enrollment_token()`` raises :class:`EnrollmentTokenError` for
  any structural, signature, or expiry failure so callers always get a
  typed, machine-readable reason code.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
import uuid
from typing import Literal, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, Field

from common.crypto.jws import JWSVerificationError, sign_jws, verify_jws
from common.vc_schemas.base import ENV_TYPE, ROLE_TYPE

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TOKEN_TTL = 600        # 10 minutes
DEFAULT_MIGRATION_TTL = 1800   # 30 minutes
PROOF_MAX_TTL = 120            # proof exp - iat must not exceed this


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class EnrollmentTokenError(ValueError):
    """Raised when an enrollment token or migration ticket fails validation."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


# ---------------------------------------------------------------------------
# Pydantic models for JWT claim sets
# ---------------------------------------------------------------------------

class EnrollmentTokenClaims(BaseModel):
    """Decoded and validated claims from an enrollment token JWT."""

    model_config = {"frozen": True}

    iss: str = Field(description="Discovery DID — issuer.")
    jti: str = Field(description="UUIDv4 token ID.")
    iat: int = Field(ge=0)
    exp: int = Field(ge=0)
    service_id: str = Field(pattern=r"^[a-z0-9_-]{1,128}$")
    role: ROLE_TYPE
    env: ENV_TYPE
    nonce: str = Field(description="base64url of 32 random bytes.")
    required_approval: bool = True
    instance_metadata_constraints: Optional[dict] = None  # type: ignore[type-arg]


class MigrationTicketClaims(BaseModel):
    """Decoded and validated claims from a migration ticket JWT."""

    model_config = {"frozen": True}

    iss: str = Field(description="Discovery DID — issuer.")
    jti: str = Field(description="UUIDv4 ticket ID.")
    iat: int = Field(ge=0)
    exp: int = Field(ge=0)
    sentinel_id: str = Field(description="UUID of the existing sentinel record.")
    sentinel_did: str = Field(pattern=r"^did:", description="Known Sentinel DID.")
    reason: str = Field(min_length=1, max_length=500)


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def hash_token(token: str) -> str:
    """Return the hex-encoded SHA-256 digest of *token*.

    Discovery stores this hash in the database — never the plaintext token.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def _b64url_nonce(n_bytes: int = 32) -> str:
    return base64.urlsafe_b64encode(os.urandom(n_bytes)).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# Enrollment token
# ---------------------------------------------------------------------------

def create_enrollment_token(
    private_key: Ed25519PrivateKey,
    *,
    issuer_did: str,
    kid: str,
    service_id: str,
    role: Literal["PRODUCER", "CONSUMER"],
    env: Literal["dev", "test", "prod"],
    ttl: int = DEFAULT_TOKEN_TTL,
    required_approval: bool = True,
    instance_metadata_constraints: Optional[dict] = None,  # type: ignore[type-arg]
) -> str:
    """Create and sign an enrollment token JWT.

    Returns the compact JWS string.  The caller must return this exactly
    once to the requesting admin and discard it — only ``hash_token()``
    of the result should be persisted.
    """
    if ttl <= 0:
        raise ValueError("ttl must be positive.")
    now = int(time.time())
    claims: dict = {
        "iss": issuer_did,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + ttl,
        "service_id": service_id,
        "role": role,
        "env": env,
        "nonce": _b64url_nonce(32),
        "required_approval": required_approval,
        "instance_metadata_constraints": instance_metadata_constraints,
    }
    return sign_jws(claims, private_key, kid=kid, extra_headers={"typ": "enrollment+jwt"})


def validate_enrollment_token(
    token: str,
    public_key: Ed25519PublicKey,
) -> EnrollmentTokenClaims:
    """Verify *token* signature and claims; return :class:`EnrollmentTokenClaims`.

    :raises EnrollmentTokenError: with a machine-readable ``code`` on any failure.
    """
    try:
        payload = verify_jws(token, public_key)
    except JWSVerificationError as exc:
        raise EnrollmentTokenError("ENROLLMENT_TOKEN_INVALID", str(exc)) from exc

    now = int(time.time())
    if payload.get("exp", 0) < now:
        raise EnrollmentTokenError(
            "ENROLLMENT_TOKEN_EXPIRED",
            f"Token expired at {payload.get('exp')}; now={now}",
        )

    try:
        return EnrollmentTokenClaims(**payload)
    except Exception as exc:
        raise EnrollmentTokenError("ENROLLMENT_TOKEN_INVALID", str(exc)) from exc


# ---------------------------------------------------------------------------
# Migration ticket
# ---------------------------------------------------------------------------

def create_migration_ticket(
    private_key: Ed25519PrivateKey,
    *,
    issuer_did: str,
    kid: str,
    sentinel_id: str,
    sentinel_did: str,
    reason: str,
    ttl: int = DEFAULT_MIGRATION_TTL,
) -> str:
    """Create and sign a migration ticket JWT for re-onboarding an existing Sentinel."""
    if ttl <= 0:
        raise ValueError("ttl must be positive.")
    now = int(time.time())
    claims: dict = {
        "iss": issuer_did,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + ttl,
        "sentinel_id": sentinel_id,
        "sentinel_did": sentinel_did,
        "reason": reason,
    }
    return sign_jws(claims, private_key, kid=kid, extra_headers={"typ": "migration-ticket+jwt"})


def validate_migration_ticket(
    ticket: str,
    public_key: Ed25519PublicKey,
) -> MigrationTicketClaims:
    """Verify *ticket* signature and claims; return :class:`MigrationTicketClaims`.

    :raises EnrollmentTokenError: with code ``ENROLLMENT_TOKEN_INVALID`` or
        ``ENROLLMENT_TOKEN_EXPIRED`` on failure.
    """
    try:
        payload = verify_jws(ticket, public_key)
    except JWSVerificationError as exc:
        raise EnrollmentTokenError("ENROLLMENT_TOKEN_INVALID", str(exc)) from exc

    now = int(time.time())
    if payload.get("exp", 0) < now:
        raise EnrollmentTokenError("ENROLLMENT_TOKEN_EXPIRED")

    try:
        return MigrationTicketClaims(**payload)
    except Exception as exc:
        raise EnrollmentTokenError("ENROLLMENT_TOKEN_INVALID", str(exc)) from exc
