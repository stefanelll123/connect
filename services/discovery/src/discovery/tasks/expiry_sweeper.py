"""Enrollment token expiry sweeper.

Runs periodically (e.g. every 60 seconds) to batch-expire PENDING/APPROVED
tokens whose ``expires_at`` has passed.

Integration:
    This function is called from a FastAPI BackgroundTask or a standalone
    scheduler (APScheduler / Arq).  The session is provided by the caller.

Note: No per-token audit event is written — bulk expiry is logged at
system level only to avoid audit table bloat.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.db.models.enrollment_tokens import EnrollmentToken

logger = logging.getLogger(__name__)


async def sweep_expired_tokens(session: AsyncSession) -> int:
    """Set status='EXPIRED' for all PENDING/APPROVED tokens past their expiry.

    Returns:
        Number of tokens expired in this sweep.
    """
    now = datetime.now(timezone.utc)
    stmt = (
        update(EnrollmentToken)
        .where(
            EnrollmentToken.status.in_(["PENDING", "APPROVED"]),
            EnrollmentToken.expires_at < now,
        )
        .values(status="EXPIRED")
        .execution_options(synchronize_session="fetch")
    )
    result = await session.execute(stmt)
    count = result.rowcount
    if count:
        logger.info("Expiry sweep: %d enrollment token(s) marked EXPIRED", count)
    return count
