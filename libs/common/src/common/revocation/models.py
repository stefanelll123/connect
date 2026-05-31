"""Pydantic models for the Revocation and Status Mechanism.

Covers:
* :class:`CredentialStatusEntry` — the ``credentialStatus`` object embedded
  in each VerifiableCredential.
* :class:`StatusListInfo` — parsed claims from a BitstringStatusListCredential.
* :class:`StalenessMode` — policy modes for when the status list is stale.
* :class:`StalenessPolicy` — runtime configuration for freshness enforcement.
* :class:`StatusCheckResult` — outcome of a credential revocation check.
* :class:`StatusAnchor` — on-chain anchor record (rootHash + updatedAt).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# credentialStatus object (embedded in each VC)
# ---------------------------------------------------------------------------


class CredentialStatusEntry(BaseModel):
    """The ``credentialStatus`` object in a Verifiable Credential.

    Conforms to W3C Bitstring Status List v1.0 §2.

    Example::

        {
          "id": "https://discovery.example.gov/api/v1/status/list-001#42",
          "type": "BitstringStatusListEntry",
          "statusListIndex": "42",
          "statusListCredential": "https://discovery.example.gov/api/v1/status/list-001",
          "statusPurpose": "revocation"
        }
    """

    model_config = {"frozen": True}

    id: str = Field(description="Status entry URL, typically <list_url>#<index>.")
    type: Literal["BitstringStatusListEntry"] = "BitstringStatusListEntry"
    statusListIndex: str = Field(
        description="Decimal string — the zero-based index into the status list bitstring.",
        pattern=r"^\d+$",
    )
    statusListCredential: str = Field(
        description="URL of the BitstringStatusListCredential JWT.",
        min_length=1,
    )
    statusPurpose: Literal["revocation", "suspension"] = "revocation"

    @property
    def index(self) -> int:
        """Parsed integer index."""
        return int(self.statusListIndex)


# ---------------------------------------------------------------------------
# Parsed claims from a BitstringStatusListCredential JWT
# ---------------------------------------------------------------------------


class StatusListInfo(BaseModel):
    """Decoded claims from a ``BitstringStatusListCredential`` JWT.

    Populated after downloading and verifying the status list JWT from
    the Discovery service endpoint.
    """

    model_config = {"frozen": True}

    jti: str = Field(description="UUID of this status list credential.")
    iss: str = Field(pattern=r"^did:", description="Discovery service DID.")
    sub: str = Field(description="Status list URL (canonical identifier).")
    iat: int = Field(ge=0)
    exp: int = Field(ge=0)
    status_purpose: Literal["revocation", "suspension"]
    encoded_list: str = Field(description="base64url(gzip(bitstring_bytes)).")

    # ---------------------------------------------------------------------------
    # Factory helpers
    # ---------------------------------------------------------------------------

    @classmethod
    def from_jwt_claims(cls, claims: dict) -> "StatusListInfo":
        """Build a :class:`StatusListInfo` from a decoded JWT claim dict."""
        vc = claims.get("vc", {})
        cs = vc.get("credentialSubject", {})
        return cls(
            jti=claims["jti"],
            iss=claims["iss"],
            sub=claims["sub"],
            iat=claims["iat"],
            exp=claims["exp"],
            status_purpose=cs.get("statusPurpose", "revocation"),
            encoded_list=cs["encodedList"],
        )


# ---------------------------------------------------------------------------
# Staleness policy
# ---------------------------------------------------------------------------


class StalenessMode(str, Enum):
    """Behaviour when the cached status list exceeds the Δ freshness bound."""

    FAIL_CLOSED = "FAIL_CLOSED"
    """(Default for prod) Reject ALL requests with STATUS_STALE_FAIL_CLOSED."""

    FAIL_OPEN_DEGRADED = "FAIL_OPEN_DEGRADED"
    """Allow only read-only (GET/HEAD) requests; deny write operations."""

    ALLOW_WITH_WARNING = "ALLOW_WITH_WARNING"
    """Allow all requests but emit a warning metric."""


@dataclass(frozen=True)
class StalenessPolicy:
    """Freshness policy for cached status lists.

    Attributes:
        delta_seconds: Maximum age of the cached status list anchor before
            staleness mode kicks in.
        mode: What to do when the status list exceeds *delta_seconds*.
    """

    delta_seconds: int = 600  # 10 minutes (prod default)
    mode: StalenessMode = StalenessMode.FAIL_CLOSED


# Default policies by environment
_ENV_DEFAULTS: dict[str, StalenessPolicy] = {
    "prod": StalenessPolicy(delta_seconds=600, mode=StalenessMode.FAIL_CLOSED),
    "test": StalenessPolicy(delta_seconds=1800, mode=StalenessMode.FAIL_OPEN_DEGRADED),
    "dev": StalenessPolicy(delta_seconds=3600, mode=StalenessMode.ALLOW_WITH_WARNING),
}


def default_policy_for_env(env: str) -> StalenessPolicy:
    """Return the default :class:`StalenessPolicy` for *env*."""
    return _ENV_DEFAULTS.get(env, _ENV_DEFAULTS["prod"])


# ---------------------------------------------------------------------------
# On-chain anchor record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StatusAnchor:
    """On-chain anchor for a status list (from StatusRegistry contract).

    Attributes:
        status_list_id: keccak256 of the status list URL (hex string).
        root_hash: SHA-256 of the JWT bytes at time of publication (hex).
        updated_at: Unix timestamp of the on-chain write.
        issuer_id: keccak256 of the issuer DID (hex).
    """

    status_list_id: str
    root_hash: str
    updated_at: int
    issuer_id: str = ""


# ---------------------------------------------------------------------------
# Status check result
# ---------------------------------------------------------------------------


class StatusCheckResult(str, Enum):
    """Result of a credential revocation/status check."""

    NOT_REVOKED = "NOT_REVOKED"
    REVOKED = "REVOKED"
    EMERGENCY_REVOKED = "EMERGENCY_REVOKED"
    STALE_FAIL_CLOSED = "STALE_FAIL_CLOSED"
    HASH_MISMATCH = "HASH_MISMATCH"
    INDEX_OUT_OF_RANGE = "INDEX_OUT_OF_RANGE"
    LIST_UNAVAILABLE = "LIST_UNAVAILABLE"
