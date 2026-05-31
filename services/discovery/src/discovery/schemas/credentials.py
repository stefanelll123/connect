"""Pydantic schemas for VC credential payloads and API responses (TASK-028)."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Issue request schemas
# ---------------------------------------------------------------------------

class IssueSentinelIdentityRequest(BaseModel):
    sentinel_id: uuid.UUID


class IssueAccessGrantRequest(BaseModel):
    consumer_sentinel_id: uuid.UUID
    producer_service_id: str
    env: str
    scope: list[str]
    expires_in_days: int = Field(default=30, ge=1, le=365)


class IssueServiceBindingRequest(BaseModel):
    sentinel_id: uuid.UUID
    service_id: str


# ---------------------------------------------------------------------------
# Credential record response
# ---------------------------------------------------------------------------

class CredentialResponse(BaseModel):
    credential_id: uuid.UUID
    jti: str
    credential_type: str
    subject_did: str
    issuer_did: str
    env: str
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    status: str
    status_list_id: Optional[str] = None
    status_list_index: Optional[int] = None
    jwt_vc: str  # signed JWT-VC string

    model_config = {"from_attributes": True}


class CredentialListResponse(BaseModel):
    items: list[CredentialResponse]
    total: int
