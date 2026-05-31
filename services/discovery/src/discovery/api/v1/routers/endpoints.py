"""PATCH endpoint for per-instance endpoint self-registration (TASK-048).

Sentinel instances call this after startup (or during graceful shutdown) to
add/update their own endpoint entry in the ``service_descriptor_endpoints``
table.  Each entry is keyed by ``(service_id, env, instance_id)`` so instances
cannot overwrite each other's data.

Route:  PATCH /api/v1/services/{service_id}/descriptor/endpoints
Auth:   Requires "operator" or "security-admin" role (same as descriptor publish).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.auth.rbac import require_roles
from discovery.db.models.service_descriptor_endpoints import ServiceDescriptorEndpoint
from discovery.dependencies import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/services", tags=["Endpoint Registry"])

_VALID_STATUSES = {"active", "draining", "offline", "unhealthy"}


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class EndpointUpsertRequest(BaseModel):
    instance_id: str = Field(..., min_length=1, max_length=128)
    endpoint_url: Optional[str] = Field(None, max_length=2048)
    weight: int = Field(default=100, ge=1, le=100)
    health_status: str = Field(default="active")
    env: str = Field(default="dev", max_length=64)

    @field_validator("health_status")
    @classmethod
    def validate_health_status(cls, v: str) -> str:
        if v not in _VALID_STATUSES:
            raise ValueError(f"health_status must be one of {_VALID_STATUSES}")
        return v


class EndpointUpsertResponse(BaseModel):
    id: str
    service_id: str
    instance_id: str
    health_status: str
    updated_at: datetime


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


@router.patch("/{service_id}/descriptor/endpoints", response_model=EndpointUpsertResponse)
async def upsert_endpoint(
    service_id: str,
    body: EndpointUpsertRequest,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_roles("operator", "security-admin")),
) -> EndpointUpsertResponse:
    """Create or update an endpoint entry for a specific sentinel instance.

    Each instance owns exactly one row identified by
    ``(service_id, env, instance_id)``.  This endpoint is idempotent — calling
    it multiple times with the same payload is safe.
    """
    # Try to find existing row
    stmt = select(ServiceDescriptorEndpoint).where(
        ServiceDescriptorEndpoint.service_id == service_id,
        ServiceDescriptorEndpoint.env == body.env,
        ServiceDescriptorEndpoint.instance_id == body.instance_id,
    )
    result = await session.execute(stmt)
    endpoint = result.scalar_one_or_none()

    if endpoint is None:
        endpoint = ServiceDescriptorEndpoint(
            service_id=service_id,
            env=body.env,
            instance_id=body.instance_id,
            endpoint_url=body.endpoint_url,
            weight=body.weight,
            health_status=body.health_status,
        )
        session.add(endpoint)
        logger.info(
            "event=endpoint_created service_id=%s instance=%s status=%s",
            service_id,
            body.instance_id[:8],
            body.health_status,
        )
    else:
        if body.endpoint_url is not None:
            endpoint.endpoint_url = body.endpoint_url
        endpoint.weight = body.weight
        endpoint.health_status = body.health_status
        # Mark as active unless being sent offline
        endpoint.is_active = body.health_status not in ("offline",)
        logger.info(
            "event=endpoint_updated service_id=%s instance=%s status=%s",
            service_id,
            body.instance_id[:8],
            body.health_status,
        )

    await session.flush()

    return EndpointUpsertResponse(
        id=str(endpoint.id),
        service_id=service_id,
        instance_id=body.instance_id,
        health_status=body.health_status,
        updated_at=endpoint.updated_at or datetime.now(timezone.utc),
    )
