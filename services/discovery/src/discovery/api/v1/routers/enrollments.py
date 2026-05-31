"""Enrollments router — one-time enrollment token lifecycle (TASK-025).

All paths are under /sentinels/enrollments (nested in sentinels prefix).
"""
from __future__ import annotations

import logging
import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.auth.models import CurrentUser
from discovery.auth.rbac import require_roles
from discovery.dependencies import get_db, get_redis, get_settings
from discovery.repositories.enrollment_tokens import (
    EnrollmentTokenRepository,
    TokenExpiredError,
    TokenNotApprovableError,
    TokenNotCancellableError,
    TokenNotFoundError,
)
from discovery.schemas.enrollment import (
    CreateEnrollmentTokenRequest,
    EnrollmentTokenListResponse,
    EnrollmentTokenResponse,
)
from discovery.services.enrollment_service import (
    ServiceNotFoundForEnrollmentError,
    approve_enrollment_token,
    cancel_enrollment_token,
    create_enrollment_token,
)

logger = logging.getLogger(__name__)

# The prefix nests these endpoints under /api/v1/sentinels/enrollments
router = APIRouter(prefix="/sentinels/enrollments", tags=["Enrollments"])

_RATE_LIMIT_CREATE = 20  # requests per minute per admin sub
_RATE_LIMIT_WINDOW = 60  # seconds


async def _check_rate_limit(redis, sub: str) -> None:
    """Redis sliding-window rate limiter for enrollment creation."""
    if redis is None:
        return  # graceful degradation — no Redis → skip rate limiting
    key = f"ratelimit:admin:{sub}:enrollment_create"
    pipe = redis.pipeline()
    pipe.incr(key)
    pipe.expire(key, _RATE_LIMIT_WINDOW)
    results = await pipe.execute()
    count = results[0]
    if count > _RATE_LIMIT_CREATE:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "RATE_LIMIT_EXCEEDED",
                "message": "Too many enrollment requests. Retry after 60s",
            },
            headers={"Retry-After": str(_RATE_LIMIT_WINDOW)},
        )


def _token_to_response(token, raw_jwt: Optional[str] = None) -> EnrollmentTokenResponse:
    return EnrollmentTokenResponse(
        token_id=token.id,
        service_id=token.service_id,
        role=token.role,
        env=token.env,
        status=token.status,
        expires_at=token.expires_at,
        created_by=token.created_by,
        approved_by=token.approved_by,
        approved_at=token.approved_at,
        created_at=token.created_at,
        token=raw_jwt,
        note="Token will not be shown again. Copy it now." if raw_jwt else None,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/sentinels/enrollments
# ---------------------------------------------------------------------------
@router.post("", response_model=EnrollmentTokenResponse, status_code=201)
async def create_token(
    body: CreateEnrollmentTokenRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_roles("operator")),
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    redis=Depends(get_redis),
) -> EnrollmentTokenResponse:
    await _check_rate_limit(redis, current_user.sub)
    try:
        token, raw_jwt = await create_enrollment_token(
            session,
            settings=settings,
            service_id=body.service_id,
            role=body.role,
            env=body.env,
            expires_in_seconds=body.expires_in_seconds,
            current_user=current_user,
            constraints=body.constraints.model_dump() if body.constraints else None,
            request_id=getattr(request.state, "request_id", ""),
        )
    except ServiceNotFoundForEnrollmentError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "SERVICE_NOT_FOUND", "message": str(exc)},
        )
    # Return raw JWT exactly once
    return _token_to_response(token, raw_jwt)


# ---------------------------------------------------------------------------
# GET /api/v1/sentinels/enrollments
# ---------------------------------------------------------------------------
@router.get("", response_model=EnrollmentTokenListResponse)
async def list_tokens(
    current_user: CurrentUser = Depends(
        require_roles("viewer", "operator", "security-admin", "chain-admin")
    ),
    session: AsyncSession = Depends(get_db),
    status: Optional[str] = None,
    env: Optional[str] = None,
    service_id: Optional[str] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    cursor: Optional[str] = None,
) -> EnrollmentTokenListResponse:
    rows, next_cursor = await EnrollmentTokenRepository.list_paginated(
        session, limit=limit, cursor=cursor, status=status, env=env, service_id=service_id
    )
    total = await EnrollmentTokenRepository.count(
        session, status=status, env=env, service_id=service_id
    )
    return EnrollmentTokenListResponse(
        items=[_token_to_response(r) for r in rows],
        total_count=total,
        next_cursor=next_cursor,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/sentinels/enrollments/{token_id}
# ---------------------------------------------------------------------------
@router.get("/{token_id}", response_model=EnrollmentTokenResponse)
async def get_token(
    token_id: uuid.UUID,
    current_user: CurrentUser = Depends(
        require_roles("viewer", "operator", "security-admin", "chain-admin")
    ),
    session: AsyncSession = Depends(get_db),
) -> EnrollmentTokenResponse:
    token = await EnrollmentTokenRepository.get_by_id(session, token_id)
    if token is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "TOKEN_NOT_FOUND", "message": f"Token {token_id} not found"},
        )
    # Never return raw token in GET
    return _token_to_response(token)


# ---------------------------------------------------------------------------
# POST /api/v1/sentinels/enrollments/{token_id}/approve
# ---------------------------------------------------------------------------
@router.post("/{token_id}/approve", response_model=EnrollmentTokenResponse)
async def approve_token(
    token_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(require_roles("security-admin")),
    session: AsyncSession = Depends(get_db),
) -> EnrollmentTokenResponse:
    try:
        token = await approve_enrollment_token(
            session,
            token_id=token_id,
            current_user=current_user,
            request_id=getattr(request.state, "request_id", ""),
        )
    except TokenNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={"code": "TOKEN_NOT_FOUND", "message": f"Token {token_id} not found"},
        )
    except TokenNotApprovableError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "TOKEN_NOT_APPROVABLE", "message": str(exc)},
        )
    except TokenExpiredError:
        raise HTTPException(
            status_code=409,
            detail={"code": "TOKEN_NOT_APPROVABLE", "message": "Token has already expired"},
        )
    return _token_to_response(token)


# ---------------------------------------------------------------------------
# POST /api/v1/sentinels/enrollments/{token_id}/cancel
# ---------------------------------------------------------------------------
@router.post("/{token_id}/cancel", response_model=EnrollmentTokenResponse)
async def cancel_token(
    token_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(require_roles("operator")),
    session: AsyncSession = Depends(get_db),
) -> EnrollmentTokenResponse:
    try:
        token = await cancel_enrollment_token(
            session,
            token_id=token_id,
            current_user=current_user,
            request_id=getattr(request.state, "request_id", ""),
        )
    except TokenNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={"code": "TOKEN_NOT_FOUND", "message": f"Token {token_id} not found"},
        )
    except TokenNotCancellableError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "TOKEN_NOT_CANCELLABLE", "message": str(exc)},
        )
    return _token_to_response(token)

