"""Status-lists router — public status list publication endpoint (TASK-030)."""
from __future__ import annotations

import hashlib
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select, func as sa_func
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.auth.rbac import require_roles
from discovery.db.models.status_lists import StatusList
from discovery.dependencies import get_db, get_settings
from discovery.services.status_list_service import get_status_list_jwt

logger = logging.getLogger(__name__)

# NOTE: prefix is empty here because the public status endpoint is at /status/{id}
# (no /api/v1/ prefix — accessible without VPN/auth per spec)
router = APIRouter(tags=["Status Lists"])

# ---------------------------------------------------------------------------
# Admin router — mounted at /api/v1/status-lists
# ---------------------------------------------------------------------------
admin_router = APIRouter(prefix="/status-lists", tags=["Status Lists"])


class StatusListResponse(BaseModel):
    status_list_id: str
    issuer_did: str
    env: str
    credential_type: Optional[str]
    top_index: int
    max_size: int
    is_frozen: bool
    dirty: bool
    published_at: Optional[str]
    version: int

    model_config = {"from_attributes": True}


class StatusListListResponse(BaseModel):
    items: List[StatusListResponse]
    total: int


@admin_router.get("", response_model=StatusListListResponse)
async def list_status_lists(
    env: str = Query(default=""),
    credential_type: str = Query(default=""),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_roles("operator", "security-admin", "viewer")),
) -> StatusListListResponse:
    base_q = select(StatusList)
    if env:
        base_q = base_q.where(StatusList.env == env)
    if credential_type:
        base_q = base_q.where(StatusList.credential_type == credential_type)

    total: int = (await session.execute(
        select(sa_func.count()).select_from(base_q.subquery())
    )).scalar_one()

    rows = list((await session.execute(
        base_q.order_by(StatusList.version.desc()).offset(skip).limit(limit)
    )).scalars().all())

    items = [
        StatusListResponse(
            status_list_id=sl.status_list_id,
            issuer_did=sl.issuer_did,
            env=sl.env,
            credential_type=sl.credential_type,
            top_index=sl.top_index,
            max_size=sl.max_size,
            is_frozen=sl.is_frozen,
            dirty=sl.dirty,
            published_at=sl.published_at.isoformat() if sl.published_at else None,
            version=sl.version,
        )
        for sl in rows
    ]
    return StatusListListResponse(items=items, total=total)


# ---------------------------------------------------------------------------
# GET /status/{status_list_id}  — public, no auth required
# ---------------------------------------------------------------------------
@router.get("/status/{status_list_id}", include_in_schema=True)
async def get_status_list(
    status_list_id: str,
    request: Request,
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
) -> Response:
    jwt_str = await get_status_list_jwt(session, status_list_id, settings)
    if jwt_str is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "STATUS_LIST_NOT_FOUND", "message": f"Status list '{status_list_id}' not found"},
        )

    # Compute ETag from the JWT payload hash
    etag = f'"{hashlib.sha256(jwt_str.encode()).hexdigest()[:16]}"'
    if_none_match = request.headers.get("if-none-match", "")
    if if_none_match and if_none_match == etag:
        return Response(status_code=304, headers={"ETag": etag})

    return Response(
        content=jwt_str,
        media_type="application/jwt",
        headers={
            "ETag": etag,
            "Cache-Control": "public, max-age=60, must-revalidate",
        },
    )
