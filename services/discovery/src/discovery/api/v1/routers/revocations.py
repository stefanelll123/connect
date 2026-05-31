"""Revocations router — credential revocation and revocation list endpoints (TASK-030)."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.auth.rbac import require_roles
from discovery.dependencies import get_db, get_settings
from discovery.repositories.status_lists import set_bit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credentials", tags=["Revocations"])


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class RevokeRequest(BaseModel):
    reason: str = Field(..., max_length=500)
    severity: str = Field(..., pattern="^(low|medium|critical)$")
    revoked_by: str


class RevokeResponse(BaseModel):
    credential_id: uuid.UUID
    jti: Optional[str]
    revoked_at: datetime
    status_list_id: Optional[str]
    status_list_index: Optional[int]
    already_revoked: bool = False


# ---------------------------------------------------------------------------
# POST /api/v1/credentials/{credential_id}/revoke
# ---------------------------------------------------------------------------
@router.post("/{credential_id}/revoke", response_model=RevokeResponse)
async def revoke_credential(
    credential_id: str,
    body: RevokeRequest,
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    current_user=Depends(require_roles("security-admin")),
) -> RevokeResponse:
    from discovery.db.models.credentials import Credential

    try:
        cred_uuid = uuid.UUID(credential_id)
    except ValueError:
        raise HTTPException(status_code=422, detail={"code": "INVALID_ID", "message": "Invalid credential_id"})

    result = await session.execute(select(Credential).where(Credential.id == cred_uuid))
    cred = result.scalar_one_or_none()
    if cred is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "CREDENTIAL_NOT_FOUND", "message": "Credential not found"},
        )

    # Idempotent revocation
    if cred.status == "revoked":
        return RevokeResponse(
            credential_id=cred.id,
            jti=cred.jti,
            revoked_at=cred.issued_at or datetime.now(timezone.utc),
            status_list_id=cred.status_list_id,
            status_list_index=cred.status_list_index,
            already_revoked=True,
        )

    # Set revocation bit in status list
    if cred.status_list_id and cred.status_list_index is not None:
        try:
            await set_bit(session, cred.status_list_id, cred.status_list_index, 1)
        except ValueError as exc:
            logger.warning("Status list bit set failed: %s", exc)

    revoked_at = datetime.now(timezone.utc)
    cred.status = "revoked"
    cred.revoked_at = revoked_at
    await session.flush()

    # Write audit event
    from discovery.repositories.audit import audit_log

    await audit_log(
        session,
        actor_type="admin",
        actor_id=current_user.sub,
        action="credential_revoked",
        target_type="credential",
        target_id=str(cred_uuid),
        summary={
            "jti": cred.jti,
            "reason": body.reason,
            "severity": body.severity,
            "revoked_by": body.revoked_by,
        },
    )

    # Trigger async publish (mark dirty — background task will re-sign)
    if cred.status_list_id:
        from discovery.repositories.status_lists import StatusListRepository

        sl = await StatusListRepository.get_by_slug(session, cred.status_list_id)
        if sl is not None:
            sl.dirty = True
            await session.flush()

    return RevokeResponse(
        credential_id=cred.id,
        jti=cred.jti,
        revoked_at=revoked_at,
        status_list_id=cred.status_list_id,
        status_list_index=cred.status_list_index,
        already_revoked=False,
    )
