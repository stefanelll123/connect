"""Config bundles router — versioned config delivery and rollback (TASK-027)."""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.auth.rbac import require_roles
from discovery.dependencies import get_db, get_settings
from discovery.repositories.config_bundles import ConfigBundleRepository
from discovery.schemas.config_bundle import (
    ConfigBundleHistoryResponse,
    ConfigBundleHistoryItem,
    ConfigBundleResponse,
    RollbackResponse,
)
from discovery.services import config_bundle_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sentinels", tags=["Config Bundles"])


def _require_sentinel_id(sentinel_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(sentinel_id)
    except ValueError:
        raise HTTPException(status_code=422, detail={"code": "INVALID_ID", "message": "Invalid sentinel_id"})


# ---------------------------------------------------------------------------
# GET /api/v1/sentinels/{sentinel_id}/config
# ---------------------------------------------------------------------------
@router.get("/{sentinel_id}/config", response_model=ConfigBundleResponse)
async def get_config(
    sentinel_id: str,
    request: Request,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_roles("operator", "security-admin", "viewer", "sentinel")),
) -> Response:
    sid = _require_sentinel_id(sentinel_id)
    # A sentinel token may only fetch its own config
    if current_user.actor_type == "SENTINEL" and current_user.sub != str(sid):
        raise HTTPException(
            status_code=403,
            detail={"code": "FORBIDDEN", "message": "Sentinels may only read their own config"},
        )
    bundle = await ConfigBundleRepository.get_current(session, sid)
    if bundle is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "CONFIG_NOT_YET_GENERATED", "message": "No config bundle has been generated for this sentinel"},
        )

    # ETag support
    etag = f'"{bundle.bundle_hash}"'
    if_none_match = request.headers.get("if-none-match", "")
    if if_none_match and if_none_match == etag:
        return Response(status_code=304, headers={"ETag": etag})

    return Response(
        content=bundle.signed_bundle_jws,
        media_type="application/jwt",
        headers={"ETag": etag},
    )


# ---------------------------------------------------------------------------
# GET /api/v1/sentinels/{sentinel_id}/config/history
# ---------------------------------------------------------------------------
@router.get("/{sentinel_id}/config/history", response_model=ConfigBundleHistoryResponse)
async def get_config_history(
    sentinel_id: str,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_roles("operator", "security-admin")),
) -> ConfigBundleHistoryResponse:
    sid = _require_sentinel_id(sentinel_id)
    bundles = await ConfigBundleRepository.get_history(session, sid)
    items = [
        ConfigBundleHistoryItem(
            version=b.version,
            bundle_hash=b.bundle_hash or "",
            issued_at=b.issued_at,
            is_current=b.is_current,
        )
        for b in bundles
    ]
    return ConfigBundleHistoryResponse(items=items)


# ---------------------------------------------------------------------------
# GET /api/v1/sentinels/{sentinel_id}/config/{version}
# ---------------------------------------------------------------------------
@router.get("/{sentinel_id}/config/{version}", response_model=ConfigBundleResponse)
async def get_config_version(
    sentinel_id: str,
    version: int,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_roles("operator", "security-admin")),
) -> Response:
    sid = _require_sentinel_id(sentinel_id)
    bundle = await ConfigBundleRepository.get_by_version(session, sid, version)
    if bundle is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "VERSION_NOT_FOUND", "message": f"Config bundle version {version} does not exist"},
        )
    return Response(content=bundle.signed_bundle_jws, media_type="application/jwt")


# ---------------------------------------------------------------------------
# POST /api/v1/sentinels/{sentinel_id}/config/generate
# ---------------------------------------------------------------------------
@router.post("/{sentinel_id}/config/generate", response_model=ConfigBundleResponse, status_code=201)
async def generate_config(
    sentinel_id: str,
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    current_user=Depends(require_roles("security-admin", "operator")),
) -> ConfigBundleResponse:
    sid = _require_sentinel_id(sentinel_id)
    try:
        bundle = await config_bundle_service.generate_and_sign(sid, session, settings)
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "SENTINEL_NOT_FOUND", "message": str(exc)},
        )
    except Exception:
        logger.exception("Config bundle generation failed for sentinel %s", sentinel_id)
        raise HTTPException(
            status_code=503,
            detail={"code": "SIGNING_KEY_UNAVAILABLE", "message": "Config bundle signing temporarily unavailable"},
        )
    return ConfigBundleResponse(
        signed_bundle_jws=bundle.signed_bundle_jws,
        bundle_hash=bundle.bundle_hash or "",
        version=bundle.version,
        issued_at=bundle.issued_at,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/sentinels/{sentinel_id}/config/rollback
# ---------------------------------------------------------------------------
@router.post("/{sentinel_id}/config/rollback", response_model=RollbackResponse)
async def rollback_config(
    sentinel_id: str,
    to_version: int = Query(..., description="Version number to roll back to"),
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    current_user=Depends(require_roles("security-admin")),
) -> RollbackResponse:
    sid = _require_sentinel_id(sentinel_id)
    try:
        bundle = await config_bundle_service.rollback(sid, to_version, session, settings)
    except ValueError as exc:
        msg = str(exc)
        if "already current" in msg:
            raise HTTPException(
                status_code=409,
                detail={"code": "ALREADY_CURRENT", "message": msg},
            )
        raise HTTPException(
            status_code=404,
            detail={"code": "VERSION_NOT_FOUND", "message": msg},
        )

    # Write audit event
    from discovery.repositories.audit import audit_log

    await audit_log(
        session,
        actor_type="admin",
        actor_id=current_user.sub,
        action="config_rollback",
        target_type="config_bundle",
        target_id=str(sid),
        summary={
            "to_version": to_version,
            "new_version": bundle.version,
            "sentinel_id": str(sid),
        },
    )

    return RollbackResponse(
        new_version=bundle.version,
        rolled_back_to_content_version=to_version,
        bundle_hash=bundle.bundle_hash or "",
        issued_at=bundle.issued_at,
    )
