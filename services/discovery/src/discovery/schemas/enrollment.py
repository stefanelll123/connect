"""Pydantic v2 schemas for Enrollment Token resources (TASK-025)."""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

_SERVICE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-_]{0,62}[a-z0-9]$")


class EnrollmentTokenConstraints(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_ips: list[str] = Field(default_factory=list)
    instance_metadata_hint: Optional[str] = None


class CreateEnrollmentTokenRequest(BaseModel):
    """Request to issue a new enrollment token."""

    model_config = ConfigDict(extra="forbid")

    service_id: str = Field(..., min_length=2, max_length=64)
    role: Literal["producer", "consumer"]
    env: Literal["dev", "test", "prod"]
    expires_in_seconds: int = Field(default=600, ge=60, le=3600)
    constraints: Optional[EnrollmentTokenConstraints] = None

    @field_validator("service_id")
    @classmethod
    def _validate_service_id(cls, v: str) -> str:
        if not _SERVICE_ID_RE.match(v):
            raise ValueError(
                "service_id must match ^[a-z0-9][a-z0-9\\-_]{0,62}[a-z0-9]$"
            )
        return v


class EnrollmentTokenResponse(BaseModel):
    """Enrollment token metadata — raw token is included ONLY on creation (201)."""

    model_config = ConfigDict(from_attributes=True)

    token_id: uuid.UUID
    service_id: str
    role: str
    env: str
    status: str
    expires_at: datetime
    created_by: Optional[str]
    approved_by: Optional[str]
    approved_at: Optional[datetime]
    created_at: Optional[datetime]
    # Raw JWT: only present in the 201 creation response, never in GET responses.
    token: Optional[str] = Field(None, exclude=False)
    note: Optional[str] = None


class EnrollmentTokenListResponse(BaseModel):
    items: list[EnrollmentTokenResponse]
    total_count: int
    next_cursor: Optional[str]
