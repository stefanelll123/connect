"""Credentials router — VC issuance and metadata management (TASK-028)."""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func as sa_func
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.auth.rbac import require_roles
from discovery.dependencies import get_db, get_settings
from discovery.repositories.sentinels import SentinelRepository
from discovery.schemas.credentials import (
    CredentialListResponse,
    CredentialResponse,
    IssueSentinelIdentityRequest,
    IssueAccessGrantRequest,
    IssueServiceBindingRequest,
)
from discovery.services import credential_issuer
from discovery.services.credential_distribution import reconstruct_jwt_vc
from discovery.services.credential_issuer import (
    CredentialIssuanceError,
    IssuerKeyUnavailableError,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credentials", tags=["Credentials"])


def _cred_to_response(record, jwt_vc: str) -> CredentialResponse:
    return CredentialResponse(
        credential_id=record.id,
        jti=record.jti or "",
        credential_type=record.credential_type,
        subject_did=record.subject_did,
        issuer_did=record.issuer_did,
        env=record.env or "",
        expires_at=record.expires_at,
        revoked_at=record.revoked_at,
        status=record.status,
        status_list_id=record.status_list_id,
        status_list_index=record.status_list_index,
        jwt_vc=jwt_vc,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/credentials/sentinel-identity
# ---------------------------------------------------------------------------
@router.post("/sentinel-identity", response_model=CredentialResponse, status_code=201)
async def issue_sentinel_identity(
    body: IssueSentinelIdentityRequest,
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    current_user=Depends(require_roles("security-admin")),
) -> CredentialResponse:
    sentinel = await SentinelRepository.get_by_id(session, body.sentinel_id)
    if sentinel is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "SENTINEL_NOT_FOUND", "message": f"Sentinel {body.sentinel_id} not found"},
        )
    try:
        record, jwt_vc = await credential_issuer.issue_sentinel_identity(sentinel, session, settings)
    except CredentialIssuanceError as exc:
        raise HTTPException(status_code=500, detail={"code": "ISSUANCE_FAILED", "message": str(exc)})
    except IssuerKeyUnavailableError as exc:
        raise HTTPException(status_code=503, detail={"code": "ISSUER_KEY_UNAVAILABLE", "message": str(exc)})
    return _cred_to_response(record, jwt_vc)


# ---------------------------------------------------------------------------
# POST /api/v1/credentials/access-grant
# ---------------------------------------------------------------------------
@router.post("/access-grant", response_model=CredentialResponse, status_code=201)
async def issue_access_grant(
    body: IssueAccessGrantRequest,
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    current_user=Depends(require_roles("security-admin")),
) -> CredentialResponse:
    sentinel = await SentinelRepository.get_by_id(session, body.consumer_sentinel_id)
    if sentinel is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "SENTINEL_NOT_FOUND", "message": f"Sentinel {body.consumer_sentinel_id} not found"},
        )
    try:
        record, jwt_vc = await credential_issuer.issue_access_grant(
            consumer_sentinel=sentinel,
            producer_service_id=body.producer_service_id,
            env=body.env,
            scope=body.scope,
            expires_in_days=body.expires_in_days,
            session=session,
            settings=settings,
            granted_by=current_user.sub,
        )
    except CredentialIssuanceError as exc:
        raise HTTPException(status_code=500, detail={"code": "ISSUANCE_FAILED", "message": str(exc)})
    return _cred_to_response(record, jwt_vc)


# ---------------------------------------------------------------------------
# POST /api/v1/credentials/service-binding
# ---------------------------------------------------------------------------
@router.post("/service-binding", response_model=CredentialResponse, status_code=201)
async def issue_service_binding(
    body: IssueServiceBindingRequest,
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    current_user=Depends(require_roles("security-admin")),
) -> CredentialResponse:
    sentinel = await SentinelRepository.get_by_id(session, body.sentinel_id)
    if sentinel is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "SENTINEL_NOT_FOUND", "message": f"Sentinel {body.sentinel_id} not found"},
        )
    try:
        record, jwt_vc = await credential_issuer.issue_service_binding(
            sentinel=sentinel,
            service_id=body.service_id,
            session=session,
            settings=settings,
        )
    except CredentialIssuanceError as exc:
        raise HTTPException(status_code=500, detail={"code": "ISSUANCE_FAILED", "message": str(exc)})
    return _cred_to_response(record, jwt_vc)


# ---------------------------------------------------------------------------
# GET /api/v1/credentials
# ---------------------------------------------------------------------------
@router.get("", response_model=CredentialListResponse)
async def list_credentials(
    env: str = Query(default=""),
    status: str = Query(default=""),
    credential_type: str = Query(default=""),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    current_user=Depends(require_roles("operator", "security-admin", "viewer")),
) -> CredentialListResponse:
    from discovery.db.models.credentials import Credential as CredentialModel

    base_q = select(CredentialModel)
    if env:
        base_q = base_q.where(CredentialModel.env == env)
    if status:
        base_q = base_q.where(CredentialModel.status == status)
    if credential_type:
        base_q = base_q.where(CredentialModel.credential_type == credential_type)

    total: int = (await session.execute(
        select(sa_func.count()).select_from(base_q.subquery())
    )).scalar_one()

    rows = list((await session.execute(
        base_q.order_by(CredentialModel.issued_at.desc().nullslast()).offset(skip).limit(limit)
    )).scalars().all())

    items = [_cred_to_response(r, reconstruct_jwt_vc(r, settings)) for r in rows]
    return CredentialListResponse(items=items, total=total)
