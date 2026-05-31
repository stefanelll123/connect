"""EnrollmentToken repository — atomic token consumption with SELECT FOR UPDATE.

The consume_atomic() method is the critical path against double-spend:
two concurrent callers for the same JTI — only one wins, the other
gets TokenAlreadyConsumedError.

SECURITY: uses SKIP LOCKED so a contending transaction sees the row
as unavailable rather than waiting and succeeding.
"""
from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.db.models.enrollment_tokens import EnrollmentToken


class TokenNotFoundError(Exception):
    def __init__(self, jti: str) -> None:
        super().__init__(f"Enrollment token not found: {jti!r}")
        self.jti = jti


class TokenAlreadyConsumedError(Exception):
    def __init__(self, jti: str) -> None:
        super().__init__(f"Enrollment token already consumed: {jti!r}")
        self.jti = jti


class TokenExpiredError(Exception):
    def __init__(self, jti: str) -> None:
        super().__init__(f"Enrollment token expired: {jti!r}")
        self.jti = jti


class TokenNotApprovableError(Exception):
    def __init__(self, token_id: uuid.UUID, status: str) -> None:
        super().__init__(f"Token {token_id} is in status {status} and cannot be approved")
        self.token_id = token_id
        self.status = status


class TokenNotCancellableError(Exception):
    def __init__(self, token_id: uuid.UUID, status: str) -> None:
        super().__init__(f"Token {token_id} is in status {status} and cannot be cancelled")
        self.token_id = token_id
        self.status = status


class DuplicateServiceError(Exception):
    """Raised when a UNIQUE(service_id, env) constraint would be violated."""


# ---------------------------------------------------------------------------
# Cursor helpers
# ---------------------------------------------------------------------------

def _encode_cursor(created_at: datetime, row_id: uuid.UUID) -> str:
    data = f"{created_at.isoformat()}|{row_id}"
    return base64.urlsafe_b64encode(data.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    data = base64.urlsafe_b64decode(cursor.encode()).decode()
    ts_str, id_str = data.split("|", 1)
    return datetime.fromisoformat(ts_str), uuid.UUID(id_str)


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------

class EnrollmentTokenRepository:
    """Data access for enrollment_tokens."""

    @staticmethod
    async def create(
        session: AsyncSession,
        *,
        jti: str,
        service_id: str,
        role: str,
        env: str,
        status: str,
        token_hash: str,
        expires_at: datetime,
        created_by: Optional[str] = None,
        constraints: Optional[dict] = None,
    ) -> EnrollmentToken:
        token = EnrollmentToken(
            id=uuid.uuid4(),
            jti=jti,
            service_id=service_id,
            role=role,
            env=env,
            status=status,
            token_hash=token_hash,
            expires_at=expires_at,
            created_by=created_by,
            constraints=constraints,
        )
        session.add(token)
        await session.flush()
        await session.refresh(token)
        return token

    @staticmethod
    async def get_by_id(
        session: AsyncSession, token_id: uuid.UUID
    ) -> Optional[EnrollmentToken]:
        result = await session.execute(
            select(EnrollmentToken).where(EnrollmentToken.id == token_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_jti(
        session: AsyncSession, jti: str
    ) -> Optional[EnrollmentToken]:
        """Return the token for *jti* or None if not found."""
        result = await session.execute(
            select(EnrollmentToken).where(EnrollmentToken.jti == jti)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def approve(
        session: AsyncSession,
        token_id: uuid.UUID,
        *,
        approved_by: str,
    ) -> EnrollmentToken:
        """Set status=APPROVED on a PENDING token."""
        result = await session.execute(
            select(EnrollmentToken).where(EnrollmentToken.id == token_id)
        )
        token = result.scalar_one_or_none()
        if token is None:
            raise TokenNotFoundError(str(token_id))
        if token.status != "PENDING":
            raise TokenNotApprovableError(token_id, token.status)
        if token.expires_at < datetime.now(timezone.utc):
            raise TokenExpiredError(str(token_id))
        token.status = "APPROVED"
        token.approved_by = approved_by
        token.approved_at = datetime.now(timezone.utc)
        await session.flush()
        await session.refresh(token)
        return token

    @staticmethod
    async def cancel(
        session: AsyncSession,
        token_id: uuid.UUID,
    ) -> EnrollmentToken:
        """Pre-use revocation: set status=EXPIRED, cancelled_at=now()."""
        result = await session.execute(
            select(EnrollmentToken).where(EnrollmentToken.id == token_id)
        )
        token = result.scalar_one_or_none()
        if token is None:
            raise TokenNotFoundError(str(token_id))
        if token.status not in ("PENDING", "APPROVED"):
            raise TokenNotCancellableError(token_id, token.status)
        token.status = "EXPIRED"
        token.cancelled_at = datetime.now(timezone.utc)
        await session.flush()
        await session.refresh(token)
        return token

    @staticmethod
    async def list_paginated(
        session: AsyncSession,
        *,
        limit: int = 20,
        cursor: Optional[str] = None,
        status: Optional[str] = None,
        env: Optional[str] = None,
        service_id: Optional[str] = None,
    ) -> tuple[list[EnrollmentToken], Optional[str]]:
        stmt = select(EnrollmentToken)
        if status:
            stmt = stmt.where(EnrollmentToken.status == status)
        if env:
            stmt = stmt.where(EnrollmentToken.env == env)
        if service_id:
            stmt = stmt.where(EnrollmentToken.service_id == service_id)
        if cursor:
            cursor_ts, cursor_id = _decode_cursor(cursor)
            stmt = stmt.where(
                (EnrollmentToken.created_at > cursor_ts)
                | (
                    (EnrollmentToken.created_at == cursor_ts)
                    & (EnrollmentToken.id > cursor_id)
                )
            )
        stmt = (
            stmt.order_by(EnrollmentToken.created_at.asc(), EnrollmentToken.id.asc())
            .limit(limit + 1)
        )
        result = await session.execute(stmt)
        rows = list(result.scalars().all())

        next_cursor: Optional[str] = None
        if len(rows) > limit:
            rows = rows[:limit]
            last = rows[-1]
            if last.created_at:
                next_cursor = _encode_cursor(last.created_at, last.id)
        return rows, next_cursor

    @staticmethod
    async def count(
        session: AsyncSession,
        *,
        status: Optional[str] = None,
        env: Optional[str] = None,
        service_id: Optional[str] = None,
    ) -> int:
        stmt = select(func.count()).select_from(EnrollmentToken)
        if status:
            stmt = stmt.where(EnrollmentToken.status == status)
        if env:
            stmt = stmt.where(EnrollmentToken.env == env)
        if service_id:
            stmt = stmt.where(EnrollmentToken.service_id == service_id)
        result = await session.execute(stmt)
        return result.scalar_one()

    @staticmethod
    async def consume_atomic(session: AsyncSession, jti: str) -> EnrollmentToken:
        """Atomically mark a token as CONSUMED.

        Algorithm:
        1. SELECT ... FOR UPDATE SKIP LOCKED — only one concurrent caller
           acquires the row lock.
        2. Validate status and expiry.
        3. Set consumed_at and status = 'CONSUMED'.
        4. flush() — write within current transaction.

        Raises:
            TokenNotFoundError: JTI does not exist (or was locked by another tx).
            TokenAlreadyConsumedError: status is CONSUMED or EXPIRED.
            TokenExpiredError: ``expires_at < now()``.
        """
        stmt = (
            select(EnrollmentToken)
            .where(EnrollmentToken.jti == jti)
            .with_for_update(skip_locked=True)
        )
        result = await session.execute(stmt)
        token = result.scalar_one_or_none()

        if token is None:
            raise TokenNotFoundError(jti)

        if token.status in ("CONSUMED", "EXPIRED"):
            raise TokenAlreadyConsumedError(jti)

        if token.consumed_at is not None:
            raise TokenAlreadyConsumedError(jti)

        if token.expires_at < datetime.now(timezone.utc):
            raise TokenExpiredError(jti)

        token.consumed_at = datetime.now(timezone.utc)
        token.status = "CONSUMED"
        await session.flush()
        return token

