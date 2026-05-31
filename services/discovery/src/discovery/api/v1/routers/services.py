"""Services router — manage service registrations per (service_id, env)."""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.auth.models import CurrentUser
from discovery.auth.rbac import require_roles
from discovery.dependencies import get_db
from discovery.repositories.apps import AppRepository
from discovery.repositories.services import (
    ServiceAlreadyExistsError,
    ServiceNotFoundError,
    ServiceRepository,
)
from discovery.schemas.services import (
    CreateServiceRequest,
    ServiceListResponse,
    ServiceResponse,
    UpdateServiceRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/services", tags=["Services"])


# ---------------------------------------------------------------------------
# POST /api/v1/services
# ---------------------------------------------------------------------------
@router.post("", response_model=ServiceResponse, status_code=201)
async def create_service(
    body: CreateServiceRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_roles("operator")),
    session: AsyncSession = Depends(get_db),
) -> ServiceResponse:
    # Verify the app exists
    app = await AppRepository.get_by_id(session, body.app_id)
    if app is None or not app.is_active:
        raise HTTPException(
            status_code=404,
            detail={"code": "APP_NOT_FOUND", "message": f"App {body.app_id} not found"},
        )

    settings = request.app.state.settings
    svc_registry = getattr(request.app.state, "service_registry_client", None)
    # Mark chain_sync_pending=True upfront when on-chain registration is enabled
    # and a base_url is provided (contract requires non-empty URL)
    wants_chain = bool(
        settings.register_service_on_chain
        and svc_registry is not None
        and body.base_url
    )

    try:
        svc = await ServiceRepository.create(
            session,
            app_id=body.app_id,
            service_id=body.service_id,
            env=body.env,
            display_name=body.display_name,
            description=body.description,
            owner_did=body.owner_did,
            base_url=body.base_url,
            chain_sync_pending=wants_chain,
        )
    except ServiceAlreadyExistsError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "SERVICE_ALREADY_EXISTS",
                "message": str(exc),
            },
        )

    from discovery.repositories.audit import audit_log
    await audit_log(
        session,
        actor_type=current_user.actor_type,
        actor_id=current_user.sub,
        action="create_service",
        target_type="service",
        target_id=str(svc.id),
        summary={"service_id": svc.service_id, "env": svc.env},
        request_id=getattr(request.state, "request_id", ""),
    )

    # Attempt immediate on-chain registration in a background task.
    # Uses its own DB session so the HTTP response is not blocked.
    # On failure the retry worker (60s loop) will pick it up.
    if wants_chain:
        db_engine = request.app.state.db_engine
        svc_id_pk = svc.id
        svc_service_id = svc.service_id
        svc_owner_did = svc.owner_did or ""
        svc_base_url = svc.base_url or ""
        svc_description = svc.description or ""

        async def _register_on_chain() -> None:
            from discovery.db.session import get_session_factory
            session_factory = get_session_factory(db_engine)
            try:
                tx_hash = await svc_registry.register_service(
                    service_id=svc_service_id,
                    did=svc_owner_did,
                    base_url=svc_base_url,
                    role="producer",
                    description=svc_description,
                )
                async with session_factory() as db:
                    await ServiceRepository.mark_chain_synced(db, svc_id_pk, tx_hash=tx_hash)
                    await db.commit()
                logger.info(
                    "Service '%s' registered on-chain immediately (tx=%s)",
                    svc_service_id,
                    tx_hash,
                )
            except Exception as exc:
                # Leave chain_sync_pending=True — the retry worker will pick it up
                async with session_factory() as db:
                    await ServiceRepository.mark_chain_sync_failed(db, svc_id_pk)
                    await db.commit()
                logger.warning(
                    "Immediate on-chain registration failed for service '%s': %s — "
                    "retry worker will pick it up",
                    svc_service_id,
                    exc,
                )

        asyncio.create_task(_register_on_chain())

    return ServiceResponse.model_validate(svc)


# ---------------------------------------------------------------------------
# GET /api/v1/services
# ---------------------------------------------------------------------------
@router.get("", response_model=ServiceListResponse)
async def list_services(
    current_user: CurrentUser = Depends(require_roles("viewer", "operator", "security-admin", "chain-admin")),
    session: AsyncSession = Depends(get_db),
    env: Optional[Literal["dev", "test", "prod"]] = None,
    app_id: Optional[uuid.UUID] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    cursor: Optional[str] = None,
) -> ServiceListResponse:
    rows, next_cursor = await ServiceRepository.list_paginated(
        session, limit=limit, cursor=cursor, env=env, app_id=app_id
    )
    total = await ServiceRepository.count(session, env=env, app_id=app_id)
    return ServiceListResponse(
        items=[ServiceResponse.model_validate(r) for r in rows],
        total_count=total,
        next_cursor=next_cursor,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/services/{service_pk}
# ---------------------------------------------------------------------------
@router.get("/{service_pk}", response_model=ServiceResponse)
async def get_service(
    service_pk: uuid.UUID,
    current_user: CurrentUser = Depends(require_roles("viewer", "operator", "security-admin", "chain-admin")),
    session: AsyncSession = Depends(get_db),
) -> ServiceResponse:
    svc = await ServiceRepository.get_by_id(session, service_pk)
    if svc is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "SERVICE_NOT_FOUND", "message": f"Service {service_pk} not found"},
        )
    return ServiceResponse.model_validate(svc)


# ---------------------------------------------------------------------------
# PATCH /api/v1/services/{service_pk}
# ---------------------------------------------------------------------------
@router.patch("/{service_pk}", response_model=ServiceResponse)
async def update_service(
    service_pk: uuid.UUID,
    body: UpdateServiceRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_roles("operator")),
    session: AsyncSession = Depends(get_db),
) -> ServiceResponse:
    try:
        svc = await ServiceRepository.update(
            session,
            service_pk,
            display_name=body.display_name,
            description=body.description,
        )
    except ServiceNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={"code": "SERVICE_NOT_FOUND", "message": f"Service {service_pk} not found"},
        )
    from discovery.repositories.audit import audit_log
    await audit_log(
        session,
        actor_type=current_user.actor_type,
        actor_id=current_user.sub,
        action="update_service",
        target_type="service",
        target_id=str(service_pk),
        summary={"display_name": body.display_name},
        request_id=getattr(request.state, "request_id", ""),
    )
    return ServiceResponse.model_validate(svc)


# ---------------------------------------------------------------------------
# POST /api/v1/services/{service_pk}/deactivate
# ---------------------------------------------------------------------------
@router.post("/{service_pk}/deactivate", status_code=204, response_class=Response)
async def deactivate_service(
    service_pk: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(require_roles("security-admin")),
    session: AsyncSession = Depends(get_db),
) -> Response:
    try:
        await ServiceRepository.deactivate(session, service_pk)
    except ServiceNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={"code": "SERVICE_NOT_FOUND", "message": f"Service {service_pk} not found"},
        )
    from discovery.repositories.audit import audit_log
    await audit_log(
        session,
        actor_type=current_user.actor_type,
        actor_id=current_user.sub,
        action="deactivate_service",
        target_type="service",
        target_id=str(service_pk),
        request_id=getattr(request.state, "request_id", ""),
    )
    return Response(status_code=204)
