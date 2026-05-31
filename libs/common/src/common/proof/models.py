"""Pydantic models for the Request Security Envelope (ProofClaims + ReqBinding).

These models define the shape of the JWT payload carried in the
``Authorization: SentinelProof <jws>`` HTTP header.  They are used by both
the Consumer Sentinel (builder) and the Producer Sentinel (verifier).

See: docs/protocols/request-security-envelope.md
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator

from common.vc_schemas.base import ENV_TYPE

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROOF_TYP = "sentinel-proof+jwt"
DEFAULT_PROOF_TTL = 30   # seconds
MAX_PROOF_TTL = 30       # hard cap; configurable on-chain via TrustPolicyRegistry
MAX_PATH_LEN = 2048

HTTP_METHODS = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


# ---------------------------------------------------------------------------
# ReqBinding
# ---------------------------------------------------------------------------


class ReqBinding(BaseModel):
    """HTTP request binding embedded in ProofClaims.

    The ``query_hash`` and ``body_hash`` fields are base64url-encoded
    SHA-256 digests of the raw (un-decoded) query string and body bytes
    respectively.  Use :func:`~common.proof.hash_utils.hash_bytes` to
    compute them.
    """

    model_config = {"frozen": True}

    method: HTTP_METHODS = Field(description="Uppercase HTTP method.")
    path: str = Field(
        min_length=1,
        max_length=MAX_PATH_LEN,
        pattern=r"^/",
        description="URL-decoded path with leading slash; query is excluded.",
    )
    query_hash: str = Field(
        description=(
            "base64url(SHA-256(raw_query_string)). "
            "Use EMPTY_HASH when there is no query string."
        ),
        min_length=1,
    )
    body_hash: str = Field(
        description=(
            "base64url(SHA-256(raw_body_bytes)). "
            "Use EMPTY_HASH for GET/HEAD/OPTIONS or empty bodies."
        ),
        min_length=1,
    )
    content_type: Optional[str] = Field(
        default=None,
        description=(
            "Normalized Content-Type without parameters "
            "(e.g. 'application/json').  Null for GET/HEAD/OPTIONS/DELETE."
        ),
        max_length=256,
    )


# ---------------------------------------------------------------------------
# ProofClaims
# ---------------------------------------------------------------------------


class ProofClaims(BaseModel):
    """JWT payload of a Consumer Sentinel request proof.

    Carried as ``Authorization: SentinelProof <compact_jws>``.

    Security constraints enforced here:
    * ``exp`` must be strictly greater than ``iat``.
    * ``exp - iat`` must not exceed :data:`MAX_PROOF_TTL` seconds.
    """

    model_config = {"frozen": True}

    # Standard claims
    iss: str = Field(pattern=r"^did:", description="Consumer Sentinel DID.")
    aud: str = Field(pattern=r"^did:", description="Producer Service DID.")
    env: ENV_TYPE = Field(description="Deployment environment.")
    iat: int = Field(ge=0, description="Issued at (Unix timestamp).")
    exp: int = Field(ge=0, description="Expiry (Unix timestamp).")
    jti: str = Field(
        min_length=1,
        max_length=128,
        description="UUIDv4 unique per proof.",
    )

    # Request binding
    req: ReqBinding

    # Optional defence-in-depth
    nonce: Optional[str] = Field(
        default=None,
        max_length=512,
        description="Session nonce issued by the Producer in a prior response.",
    )
    trace_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="OpenTelemetry W3C trace-id for observability.",
    )

    @model_validator(mode="after")
    def _validate_timing(self) -> "ProofClaims":
        if self.exp <= self.iat:
            raise ValueError("exp must be strictly greater than iat.")
        if (self.exp - self.iat) > MAX_PROOF_TTL:
            raise ValueError(
                f"exp - iat ({self.exp - self.iat}s) exceeds MAX_PROOF_TTL ({MAX_PROOF_TTL}s)."
            )
        return self
