"""Apps router — CRUD for top-level application entities."""
from __future__ import annotations

import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.auth.models import CurrentUser
from discovery.auth.rbac import require_roles
from discovery.dependencies import get_db
from discovery.repositories.apps import (
    AppNameConflictError,
    AppNotFoundError,
    AppRepository,
)
from discovery.schemas.apps import (
    AppListResponse,
    AppResponse,
    CreateAppRequest,
    UpdateAppRequest,
)

router = APIRouter(prefix="/apps", tags=["Apps"])


# ---------------------------------------------------------------------------
# POST /api/v1/apps
# ---------------------------------------------------------------------------
@router.post("", response_model=AppResponse, status_code=201)
async def create_app(
    body: CreateAppRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_roles("operator")),
    session: AsyncSession = Depends(get_db),
) -> AppResponse:
    try:
        app = await AppRepository.create(session, name=body.name, owner=body.owner)
    except AppNameConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "APP_ALREADY_EXISTS", "message": str(exc)},
        )
    from discovery.repositories.audit import audit_log
    await audit_log(
        session,
        actor_type=current_user.actor_type,
        actor_id=current_user.sub,
        action="create_app",
        target_type="app",
        target_id=str(app.id),
        summary={"name": app.name},
        request_id=getattr(request.state, "request_id", ""),
    )
    return AppResponse.model_validate(app)


# ---------------------------------------------------------------------------
# GET /api/v1/apps
# ---------------------------------------------------------------------------
@router.get("", response_model=AppListResponse)
async def list_apps(
    current_user: CurrentUser = Depends(require_roles("viewer", "operator", "security-admin", "chain-admin")),
    session: AsyncSession = Depends(get_db),
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    cursor: Optional[str] = None,
) -> AppListResponse:
    rows, next_cursor = await AppRepository.list_paginated(
        session, limit=limit, cursor=cursor
    )
    total = await AppRepository.count(session)
    return AppListResponse(
        items=[AppResponse.model_validate(r) for r in rows],
        total_count=total,
        next_cursor=next_cursor,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/apps/{app_id}
# ---------------------------------------------------------------------------
@router.get("/{app_id}", response_model=AppResponse)
async def get_app(
    app_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_roles("viewer", "operator", "security-admin", "chain-admin")),
    session: AsyncSession = Depends(get_db),
) -> AppResponse:
    app = await AppRepository.get_by_id(session, app_id)
    if app is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "APP_NOT_FOUND", "message": f"App {app_id} not found"},
        )
    return AppResponse.model_validate(app)


# ---------------------------------------------------------------------------
# PATCH /api/v1/apps/{app_id}
# ---------------------------------------------------------------------------
@router.patch("/{app_id}", response_model=AppResponse)
async def update_app(
    app_id: uuid.UUID,
    body: UpdateAppRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_roles("operator")),
    session: AsyncSession = Depends(get_db),
) -> AppResponse:
    try:
        app = await AppRepository.update(
            session, app_id, name=body.name, owner=body.owner
        )
    except AppNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={"code": "APP_NOT_FOUND", "message": f"App {app_id} not found"},
        )
    except AppNameConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "APP_ALREADY_EXISTS", "message": str(exc)},
        )
    from discovery.repositories.audit import audit_log
    await audit_log(
        session,
        actor_type=current_user.actor_type,
        actor_id=current_user.sub,
        action="update_app",
        target_type="app",
        target_id=str(app_id),
        summary={"name": body.name, "owner": body.owner},
        request_id=getattr(request.state, "request_id", ""),
    )
    return AppResponse.model_validate(app)


# ---------------------------------------------------------------------------
# DELETE /api/v1/apps/{app_id}  (soft delete)
# ---------------------------------------------------------------------------
@router.delete("/{app_id}", status_code=204, response_class=Response)
async def deactivate_app(
    app_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(require_roles("security-admin")),
    session: AsyncSession = Depends(get_db),
) -> Response:
    try:
        await AppRepository.deactivate(session, app_id)
    except AppNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={"code": "APP_NOT_FOUND", "message": f"App {app_id} not found"},
        )
    from discovery.repositories.audit import audit_log
    await audit_log(
        session,
        actor_type=current_user.actor_type,
        actor_id=current_user.sub,
        action="deactivate_app",
        target_type="app",
        target_id=str(app_id),
        request_id=getattr(request.state, "request_id", ""),
    )
    return Response(status_code=204)

