"""Service descriptors router — producer publish and admin inspect (TASK-032)."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.auth.rbac import require_roles
from discovery.dependencies import get_db, get_settings
from discovery.schemas.descriptor import (
    InspectDescriptorResponse,
    PublishDescriptorRequest,
    PublishDescriptorResponse,
)
from discovery.services import descriptor_service
from discovery.services.descriptor_service import DescriptorValidationError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/services", tags=["Service Descriptors"])


@router.post("/{service_id}/descriptor", response_model=PublishDescriptorResponse)
async def publish_descriptor(
    service_id: str,
    body: PublishDescriptorRequest,
    env: str = "dev",
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    current_user=Depends(require_roles("operator", "security-admin", "sentinel")),
) -> PublishDescriptorResponse:
    """Accept a signed service descriptor from a producer sentinel."""
    try:
        sd = await descriptor_service.validate_and_publish(
            session,
            service_id=service_id,
            env=env,
            signed_descriptor_jws=body.signed_descriptor_jws,
        )
    except DescriptorValidationError as exc:
        raise HTTPException(status_code=exc.status, detail={"code": exc.code, "message": str(exc)})

    return PublishDescriptorResponse(
        descriptor_id=str(sd.id),
        accepted_at=sd.published_at or datetime.now(timezone.utc),
        valid_until=sd.valid_until or datetime.now(timezone.utc),
    )


@router.get("/{service_id}/descriptor", response_model=InspectDescriptorResponse)
async def inspect_descriptor(
    service_id: str,
    env: str = "dev",
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_roles("operator", "security-admin")),
) -> InspectDescriptorResponse:
    """Admin-only: inspect current descriptor metadata with decoded endpoints."""
    try:
        sd = await descriptor_service.resolve_descriptor(session, service_id=service_id, env=env)
    except DescriptorValidationError as exc:
        raise HTTPException(status_code=exc.status, detail={"code": exc.code, "message": str(exc)})

    # Decode JWS payload to extract endpoints and timing fields
    try:
        payload = descriptor_service._extract_jws_payload(sd.signed_descriptor_jws)
    except Exception:
        payload = {}

    from discovery.schemas.descriptor import EndpointEntry
    raw_endpoints = payload.get("endpoints", [])
    endpoints = [EndpointEntry(**e) for e in raw_endpoints if isinstance(e, dict)]

    def _parse_dt(val) -> "datetime | None":
        if not val:
            return None
        from datetime import datetime, timezone
        if isinstance(val, datetime):
            return val
        try:
            return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
        except Exception:
            return None

    return InspectDescriptorResponse(
        id=str(sd.id),
        service_id=sd.service_id,
        env=sd.env,
        producer_sentinel_did=sd.producer_sentinel_did,
        producer_service_did=payload.get("producer_service_did"),
        descriptor_hash=sd.descriptor_hash,
        valid_from=_parse_dt(payload.get("valid_from")),
        valid_until=sd.valid_until,
        issued_at=_parse_dt(payload.get("issued_at")),
        published_at=sd.published_at,
        is_active=sd.is_active,
        endpoints=endpoints,
    )
