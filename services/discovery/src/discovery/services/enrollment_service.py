"""Enrollment token issuance, approval, and cancellation business logic.

SECURITY:
- Raw JWT tokens are returned to the caller ONCE and NEVER persisted.
- Only the SHA-256 hash of the JWT is stored in the DB.
- Rate limiting is enforced by the router via Redis.
- In prod: tokens start as PENDING and require explicit security-admin approval.
- In dev/test (auto_approve_non_prod=True): tokens begin as APPROVED immediately.
"""
from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import jwt  # PyJWT

from discovery.auth.models import CurrentUser
from discovery.config import DiscoverySettings
from discovery.db.models.enrollment_tokens import EnrollmentToken
from discovery.repositories.audit import audit_log
from discovery.repositories.enrollment_tokens import (
    EnrollmentTokenRepository,
    TokenExpiredError,
    TokenNotApprovableError,
    TokenNotCancellableError,
    TokenNotFoundError,
)
from discovery.repositories.services import ServiceNotFoundError, ServiceRepository
from sqlalchemy.ext.asyncio import AsyncSession


class ServiceNotFoundForEnrollmentError(Exception):
    def __init__(self, service_id: str, env: str) -> None:
        super().__init__(f"Service '{service_id}' not found in env '{env}'")
        self.service_id = service_id
        self.env = env


async def create_enrollment_token(
    session: AsyncSession,
    *,
    settings: DiscoverySettings,
    service_id: str,
    role: str,
    env: str,
    expires_in_seconds: int,
    current_user: CurrentUser,
    constraints: Optional[dict] = None,
    request_id: str = "",
) -> tuple[EnrollmentToken, str]:
    """Create and persist a new enrollment token.

    Returns:
        (token_record, raw_jwt) — the raw JWT is returned ONCE; it is not
        stored in the database (only its SHA-256 hash is).

    Raises:
        ServiceNotFoundForEnrollmentError: service_id+env not found or inactive.
    """
    # Validate that the service exists and is active
    svc = await ServiceRepository.get_by_service_id_env(session, service_id, env)
    if svc is None or not svc.is_active:
        raise ServiceNotFoundForEnrollmentError(service_id, env)

    # Determine initial status
    if env == "prod":
        status = "PENDING"
    elif settings.auto_approve_non_prod:
        status = "APPROVED"
    else:
        status = "PENDING"

    jti = str(uuid.uuid4())
    now = int(time.time())
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)

    issuer = settings.jwt_issuer_did or "discovery-local"
    payload = {
        "jti": jti,
        "service_id": service_id,
        "role": role,
        "env": env,
        "iss": issuer,
        "iat": now,
        "exp": now + expires_in_seconds,
        "type": "enrollment",
    }
    raw_jwt = jwt.encode(
        payload,
        settings.local_jwt_secret.get_secret_value(),
        algorithm="HS256",
    )

    # SHA-256 hash — the raw JWT MUST NOT be stored
    token_hash = hashlib.sha256(raw_jwt.encode()).hexdigest()

    token = await EnrollmentTokenRepository.create(
        session,
        jti=jti,
        service_id=service_id,
        role=role,
        env=env,
        status=status,
        token_hash=token_hash,
        expires_at=expires_at,
        created_by=current_user.sub,
        constraints=constraints,
    )

    await audit_log(
        session,
        actor_type=current_user.actor_type,
        actor_id=current_user.sub,
        action="create_enrollment_token",
        target_type="enrollment_token",
        target_id=str(token.id),
        summary={"service_id": service_id, "role": role, "env": env, "status": status},
        request_id=request_id,
    )

    return token, raw_jwt


async def approve_enrollment_token(
    session: AsyncSession,
    *,
    token_id: uuid.UUID,
    current_user: CurrentUser,
    request_id: str = "",
) -> EnrollmentToken:
    """Approve a PENDING enrollment token.

    Raises:
        TokenNotFoundError: token_id not found.
        TokenNotApprovableError: token not in PENDING status.
        TokenExpiredError: token has already expired.
    """
    token = await EnrollmentTokenRepository.approve(
        session,
        token_id,
        approved_by=current_user.sub,
    )
    await audit_log(
        session,
        actor_type=current_user.actor_type,
        actor_id=current_user.sub,
        action="approve_enrollment_token",
        target_type="enrollment_token",
        target_id=str(token_id),
        summary={
            "service_id": token.service_id,
            "role": token.role,
            "env": token.env,
        },
        request_id=request_id,
    )
    return token


async def cancel_enrollment_token(
    session: AsyncSession,
    *,
    token_id: uuid.UUID,
    current_user: CurrentUser,
    request_id: str = "",
) -> EnrollmentToken:
    """Cancel (pre-use revoke) a PENDING or APPROVED token.

    Raises:
        TokenNotFoundError: token_id not found.
        TokenNotCancellableError: token is already CONSUMED or EXPIRED.
    """
    token = await EnrollmentTokenRepository.cancel(session, token_id)
    await audit_log(
        session,
        actor_type=current_user.actor_type,
        actor_id=current_user.sub,
        action="cancel_enrollment_token",
        target_type="enrollment_token",
        target_id=str(token_id),
        summary={"service_id": token.service_id, "env": token.env},
        request_id=request_id,
    )
    return token
