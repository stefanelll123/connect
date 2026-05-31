"""Sentinel credentials router — credential feed and rotation (TASK-029)."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.auth.models import CurrentUser
from discovery.auth.rbac import get_current_user, require_roles
from discovery.dependencies import get_db, get_redis, get_settings
from discovery.repositories.sentinels import SentinelRepository
from discovery.schemas.credential_feed import (
    CredentialFeedItem,
    CredentialFeedResponse,
    RotateCredentialRequest,
    RotateCredentialResponse,
)
from discovery.services import credential_distribution, credential_issuer

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sentinels", tags=["Sentinel Credentials"])

_FULL_SYNC_RATE_LIMIT = 10  # per hour per sentinel
_FULL_SYNC_WINDOW = 3600


async def _check_full_sync_rate(redis, sentinel_id: str) -> None:
    if redis is None:
        return
    key = f"ratelimit:fullsync:{sentinel_id}"
    pipe = redis.pipeline()
    pipe.incr(key)
    pipe.expire(key, _FULL_SYNC_WINDOW)
    results = await pipe.execute()
    if results[0] > _FULL_SYNC_RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "FULL_SYNC_RATE_LIMIT",
                "message": "Maximum full syncs (10/hour) exceeded. Use incremental sync with 'since' parameter.",
            },
            headers={"Retry-After": "3600"},
        )


def _cred_to_feed_item(cred, jwt_vc: str) -> CredentialFeedItem:
    return CredentialFeedItem(
        credential_id=cred.id,
        jti=cred.jti or "",
        credential_type=cred.credential_type,
        subject_did=cred.subject_did,
        expires_at=cred.expires_at,
        status=cred.status,
        deprecated_until=getattr(cred, "deprecated_until", None),
        jwt_vc=jwt_vc,
    )


def _require_sentinel_id(sentinel_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(sentinel_id)
    except ValueError:
        raise HTTPException(status_code=422, detail={"code": "INVALID_ID", "message": "Invalid sentinel_id"})


async def _require_credential_access(
    sentinel_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """Allow operators/admins OR the sentinel itself to read its credential feed."""
    if current_user.actor_type == "SENTINEL" and current_user.sub == sentinel_id:
        return current_user
    if any(r in current_user.roles for r in ("operator", "security-admin", "viewer")):
        return current_user
    raise HTTPException(
        status_code=403,
        detail={
            "code": "INSUFFICIENT_ROLE",
            "message": "Requires operator/security-admin/viewer role or matching sentinel identity",
        },
    )


# ---------------------------------------------------------------------------
# GET /api/v1/sentinels/{sentinel_id}/credentials
# ---------------------------------------------------------------------------
@router.get("/{sentinel_id}/credentials", response_model=CredentialFeedResponse)
async def get_credential_feed(
    sentinel_id: str,
    request: Request,
    since: Optional[str] = Query(None, description="ISO-8601 timestamp for incremental sync"),
    type: Optional[str] = Query(None, description="Filter by credential_type"),
    status: Optional[str] = Query(None, description="Status filter: active|deprecated"),
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    current_user: CurrentUser = Depends(_require_credential_access),
) -> Response:
    sid = _require_sentinel_id(sentinel_id)
    sentinel = await SentinelRepository.get_by_id(session, sid)
    if sentinel is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "SENTINEL_NOT_FOUND", "message": "Sentinel not found"},
        )

    since_dt: Optional[datetime] = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail={"code": "INVALID_SINCE", "message": "Invalid ISO-8601 timestamp for 'since'"},
            )

    status_filter = None
    if status:
        status_filter = [s.strip() for s in status.split(",")]

    creds = await credential_distribution.get_credentials_for_sentinel(
        session,
        sentinel,
        since=since_dt,
        credential_type=type,
        status_filter=status_filter,
    )

    # ETag support
    etag = f'"{credential_distribution._compute_feed_etag(creds)}"'
    if_none_match = request.headers.get("if-none-match", "")
    if if_none_match and if_none_match == etag:
        return Response(status_code=304, headers={"ETag": etag})

    fetched_at = datetime.now(timezone.utc)
    next_poll_after = fetched_at + timedelta(minutes=5)

    items = [
        _cred_to_feed_item(c, credential_distribution.reconstruct_jwt_vc(c, settings))
        for c in creds
    ]

    data = CredentialFeedResponse(
        credentials=items,
        fetched_at=fetched_at,
        next_poll_after=next_poll_after,
    )
    import json

    return Response(
        content=data.model_dump_json(),
        media_type="application/json",
        headers={"ETag": etag},
    )


# ---------------------------------------------------------------------------
# GET /api/v1/sentinels/{sentinel_id}/credentials/sync-full
# ---------------------------------------------------------------------------
@router.get("/{sentinel_id}/credentials/sync-full", response_model=CredentialFeedResponse)
async def full_sync(
    sentinel_id: str,
    request: Request,
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    redis=Depends(get_redis),
    current_user=Depends(require_roles("operator", "security-admin", "viewer")),
) -> CredentialFeedResponse:
    await _check_full_sync_rate(redis, sentinel_id)
    sid = _require_sentinel_id(sentinel_id)
    sentinel = await SentinelRepository.get_by_id(session, sid)
    if sentinel is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "SENTINEL_NOT_FOUND", "message": "Sentinel not found"},
        )

    creds = await credential_distribution.get_credentials_for_sentinel(
        session, sentinel, since=None, status_filter=["active", "deprecated"]
    )

    fetched_at = datetime.now(timezone.utc)
    items = [
        _cred_to_feed_item(c, credential_distribution.reconstruct_jwt_vc(c, settings))
        for c in creds
    ]
    return CredentialFeedResponse(
        credentials=items,
        fetched_at=fetched_at,
        next_poll_after=fetched_at + timedelta(minutes=5),
    )


# ---------------------------------------------------------------------------
# POST /api/v1/sentinels/{sentinel_id}/credentials/{credential_id}/rotate
# ---------------------------------------------------------------------------
@router.post(
    "/{sentinel_id}/credentials/{credential_id}/rotate",
    response_model=RotateCredentialResponse,
    status_code=201,
)
async def rotate_credential(
    sentinel_id: str,
    credential_id: str,
    body: RotateCredentialRequest,
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    current_user=Depends(require_roles("security-admin")),
) -> RotateCredentialResponse:
    sid = _require_sentinel_id(sentinel_id)
    try:
        cred_uuid = uuid.UUID(credential_id)
    except ValueError:
        raise HTTPException(status_code=422, detail={"code": "INVALID_ID", "message": "Invalid credential_id"})

    # Load the credential
    result = await session.execute(
        select(__import__("discovery.db.models.credentials", fromlist=["Credential"]).Credential)
        .where(__import__("discovery.db.models.credentials", fromlist=["Credential"]).Credential.id == cred_uuid)
    )
    # Use direct import instead
    from discovery.db.models.credentials import Credential as CredModel

    result2 = await session.execute(select(CredModel).where(CredModel.id == cred_uuid))
    old_cred = result2.scalar_one_or_none()
    if old_cred is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "CREDENTIAL_NOT_FOUND", "message": "Credential not found or does not belong to this sentinel"},
        )

    # Verify credential belongs to this sentinel
    sentinel = await SentinelRepository.get_by_id(session, sid)
    if sentinel is None or old_cred.subject_did != sentinel.did:
        raise HTTPException(
            status_code=404,
            detail={"code": "CREDENTIAL_NOT_FOUND", "message": "Credential not found or does not belong to this sentinel"},
        )

    if old_cred.status == "deprecated":
        raise HTTPException(
            status_code=409,
            detail={"code": "ALREADY_IN_ROTATION", "message": "Credential is already being rotated."},
        )

    # Re-issue
    new_cred, jwt_vc = await credential_issuer.reissue_on_rotation(
        cred_uuid, session, settings, body.new_expires_in_days
    )

    # Deprecate old credential
    await credential_distribution.start_rotation(old_cred, new_cred, session)

    # Write audit event
    from discovery.repositories.audit import audit_log

    await audit_log(
        session,
        actor_type="admin",
        actor_id=current_user.sub,
        action="credential_rotated",
        target_type="credential",
        target_id=str(cred_uuid),
        summary={
            "old_jti": old_cred.jti,
            "new_jti": new_cred.jti,
            "sentinel_id": sentinel_id,
        },
    )

    return RotateCredentialResponse(
        old_credential_id=old_cred.id,
        old_jti=old_cred.jti or "",
        old_status="deprecated",
        deprecated_until=old_cred.deprecated_until,
        new_credential_id=new_cred.id,
        new_jti=new_cred.jti or "",
        new_jwt_vc=jwt_vc,
        new_expires_at=new_cred.expires_at,
    )
