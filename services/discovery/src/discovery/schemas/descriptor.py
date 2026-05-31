"""ServiceDescriptor Pydantic schemas (TASK-032)."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import AnyHttpUrl, BaseModel, Field, model_validator

_MAX_ENDPOINT_URL_LEN = 2048
_MAX_TTL_SECONDS = 600  # 10 minutes


class EndpointEntry(BaseModel):
    url: str = Field(..., max_length=_MAX_ENDPOINT_URL_LEN, description="Endpoint URL")
    protocol: Literal["http", "https", "grpc", "mqtt"] = "https"
    weight: int = Field(default=100, ge=1, le=100, description="Load weight 1-100")
    instance_id: Optional[str] = Field(None, max_length=128)


class ServiceDescriptorPayload(BaseModel):
    """The unsigned descriptor payload (embedded inside the JWS)."""

    descriptor_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    service_id: str = Field(..., max_length=64)
    env: Literal["dev", "test", "prod"]
    producer_sentinel_did: str
    producer_service_did: str
    endpoints: list[EndpointEntry] = Field(..., min_length=1, max_length=10)
    valid_from: datetime
    valid_until: datetime
    issued_at: datetime

    @model_validator(mode="after")
    def _validate_ttl(self) -> "ServiceDescriptorPayload":
        delta = (self.valid_until - self.valid_from).total_seconds()
        if delta > _MAX_TTL_SECONDS:
            raise ValueError(
                f"Descriptor TTL cannot exceed {_MAX_TTL_SECONDS}s (got {delta:.0f}s)"
            )
        return self


class PublishDescriptorRequest(BaseModel):
    signed_descriptor_jws: str = Field(..., description="Producer-signed JWS of the descriptor")


class PublishDescriptorResponse(BaseModel):
    descriptor_id: str
    accepted_at: datetime
    valid_until: datetime


class ResolveDescriptorResponse(BaseModel):
    service_id: str
    env: str
    signed_descriptor_jws: str
    descriptor_hash: Optional[str]
    valid_until: datetime
    producer_sentinel_did: Optional[str]
    published_at: datetime


class InspectDescriptorResponse(BaseModel):
    id: str
    service_id: str
    env: str
    producer_sentinel_did: Optional[str]
    producer_service_did: Optional[str]
    descriptor_hash: Optional[str]
    valid_from: Optional[datetime]
    valid_until: Optional[datetime]
    issued_at: Optional[datetime]
    published_at: Optional[datetime]
    is_active: bool
    endpoints: list[EndpointEntry]
