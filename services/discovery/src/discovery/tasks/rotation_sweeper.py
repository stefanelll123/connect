"""Rotation sweeper — transitions deprecated credentials to expired (TASK-029).

Runs periodically (every 60 seconds).  Updates credentials whose
``deprecated_until`` has passed from 'deprecated' → 'expired'.

No per-credential audit event is written — bulk transitions are logged
at system level only.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.db.models.credentials import Credential

logger = logging.getLogger(__name__)


async def sweep_deprecated_credentials(session: AsyncSession) -> int:
    """Expire deprecated credentials whose grace period has passed.

    Returns:
        Number of credentials transitioned to 'expired'.
    """
    now = datetime.now(timezone.utc)
    stmt = (
        update(Credential)
        .where(
            Credential.status == "deprecated",
            Credential.deprecated_until < now,
        )
        .values(status="expired")
        .execution_options(synchronize_session="fetch")
    )
    result = await session.execute(stmt)
    count = result.rowcount
    if count:
        logger.info(
            "Rotation sweeper: %d credential(s) transitioned deprecated → expired",
            count,
        )
    return count
