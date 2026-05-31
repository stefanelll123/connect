"""Credential feed response schemas (TASK-029)."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class CredentialFeedItem(BaseModel):
    credential_id: uuid.UUID
    jti: str
    credential_type: str
    subject_did: str
    expires_at: Optional[datetime]
    status: str
    deprecated_until: Optional[datetime] = None
    jwt_vc: str  # full signed JWT-VC

    model_config = {"from_attributes": True}


class CredentialFeedResponse(BaseModel):
    credentials: list[CredentialFeedItem]
    fetched_at: datetime
    next_poll_after: datetime


class RotateCredentialRequest(BaseModel):
    new_expires_in_days: Optional[int] = None


class RotateCredentialResponse(BaseModel):
    old_credential_id: uuid.UUID
    old_jti: str
    old_status: str
    deprecated_until: datetime
    new_credential_id: uuid.UUID
    new_jti: str
    new_jwt_vc: str
    new_expires_at: datetime
