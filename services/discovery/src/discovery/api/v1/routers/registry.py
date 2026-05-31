"""Registry router — consumer resolve API (TASK-032)."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.auth.rbac import require_roles
from discovery.dependencies import get_db
from discovery.schemas.descriptor import ResolveDescriptorResponse
from discovery.services import descriptor_service
from discovery.services.descriptor_service import DescriptorValidationError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/registry", tags=["Registry"])


@router.get("/resolve", response_model=ResolveDescriptorResponse)
async def resolve_service(
    service_id: str = Query(..., max_length=64, description="Target service ID"),
    env: str = Query("dev", description="Environment: dev|test|prod"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_roles("operator", "security-admin", "viewer", "sentinel")),
) -> ResolveDescriptorResponse:
    """Resolve the current signed service descriptor for a service.

    Consumer sentinels MUST verify the JWS signature using producer_sentinel_did
    before trusting any endpoint in the descriptor.
    """
    try:
        sd = await descriptor_service.resolve_descriptor(session, service_id=service_id, env=env)
    except DescriptorValidationError as exc:
        raise HTTPException(status_code=exc.status, detail={"code": exc.code, "message": str(exc)})

    return ResolveDescriptorResponse(
        service_id=sd.service_id,
        env=sd.env,
        signed_descriptor_jws=sd.signed_descriptor_jws,
        descriptor_hash=sd.descriptor_hash,
        valid_until=sd.valid_until,
        producer_sentinel_did=sd.producer_sentinel_did,
        published_at=sd.published_at,
    )
