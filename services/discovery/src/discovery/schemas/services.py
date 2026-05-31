"""Pydantic v2 schemas for Service resources."""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

# service_id: lowercase alphanumeric, hyphens, underscores.
# Must start and end with alphanumeric. Length 2-64.
_SERVICE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-_]{0,62}[a-z0-9]$")


class CreateServiceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    app_id: uuid.UUID
    service_id: str = Field(..., min_length=2, max_length=64)
    env: Literal["dev", "test", "prod"]
    display_name: str = Field(..., min_length=1, max_length=256)
    description: Optional[str] = Field(None, max_length=2000)
    owner_did: Optional[str] = Field(None, max_length=512)
    # Base URL of the service endpoint — required for on-chain registration.
    # On prod must start with https://. On local (chain-id 31337) any non-empty value is accepted.
    base_url: Optional[str] = Field(None, max_length=2048)

    @field_validator("service_id")
    @classmethod
    def _validate_service_id(cls, v: str) -> str:
        if not _SERVICE_ID_RE.match(v):
            raise ValueError(
                "service_id must match ^[a-z0-9][a-z0-9\\-_]{0,62}[a-z0-9]$"
            )
        return v

    @field_validator("display_name", "description", mode="before")
    @classmethod
    def _strip_and_reject_nullbytes(cls, v: object) -> object:
        if isinstance(v, str):
            v = v.strip()
            if "\x00" in v:
                raise ValueError("Null bytes are not permitted")
        return v


class UpdateServiceRequest(BaseModel):
    """Only display_name and description are mutable after creation."""

    model_config = ConfigDict(extra="forbid")

    display_name: Optional[str] = Field(None, min_length=1, max_length=256)
    description: Optional[str] = Field(None, max_length=2000)

    @field_validator("display_name", "description", mode="before")
    @classmethod
    def _strip_and_reject_nullbytes(cls, v: object) -> object:
        if isinstance(v, str):
            v = v.strip()
            if "\x00" in v:
                raise ValueError("Null bytes are not permitted")
        return v


class ServiceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    app_id: Optional[uuid.UUID]
    service_id: str
    env: str
    display_name: Optional[str]
    description: Optional[str]
    owner_did: Optional[str]
    base_url: Optional[str]
    is_active: bool
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    chain_sync_pending: bool = False
    chain_tx_hash: Optional[str] = None


class ServiceListResponse(BaseModel):
    items: list[ServiceResponse]
    total_count: int
    next_cursor: Optional[str]
