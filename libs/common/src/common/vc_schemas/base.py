"""Base classes and shared types for VC schema models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Shared literal types
# ---------------------------------------------------------------------------

ENV_TYPE = Literal["dev", "test", "prod"]
ROLE_TYPE = Literal["PRODUCER", "CONSUMER"]
HTTP_METHOD_TYPE = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
STATUS_PURPOSE_TYPE = Literal["revocation", "suspension"]

# ---------------------------------------------------------------------------
# Maximum credential lifetimes (seconds)
# ---------------------------------------------------------------------------

MAX_LIFETIME_SENTINEL_IDENTITY = 365 * 24 * 3600   # 365 days
MAX_LIFETIME_SERVICE_BINDING_PROD = 90 * 24 * 3600  # 90 days
MAX_LIFETIME_ACCESS_GRANT_PROD = 30 * 24 * 3600     # 30 days


# ---------------------------------------------------------------------------
# CredentialStatus model (W3C Bitstring Status List v1.0)
# ---------------------------------------------------------------------------

class CredentialStatus(BaseModel):
    """Bitstring Status List entry pointer embedded in a revocable VC.

    Per W3C Bitstring Status List v1.0.  Each entry points to a position
    inside a compressed bitstring hosted as a separate status-list VC.
    """

    model_config = {"frozen": True}

    id: str = Field(
        description=(
            "URL with index fragment, e.g. "
            "https://discovery.example.gov/status/list-001#42"
        ),
        min_length=1,
        max_length=2048,
    )
    type: Literal["BitstringStatusListEntry"]
    statusListIndex: str = Field(
        description="String representation of the integer bit position.",
        pattern=r"^\d+$",
    )
    statusListCredential: str = Field(
        description="URL pointing to the Bitstring Status List VC.",
        min_length=1,
        max_length=2048,
    )
    statusPurpose: STATUS_PURPOSE_TYPE
