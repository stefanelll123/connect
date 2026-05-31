"""Heartbeat monitor — background task for status transitions (TASK-033).

Runs every 60 seconds.  For each sentinel, computes the current status
from last_seen and transitions computed_status if changed.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.db.models.sentinels import Sentinel
from discovery.services.lifecycle_service import (
    compute_status_from_last_seen,
    record_lifecycle_event,
)

logger = logging.getLogger(__name__)


async def run_status_sweep(session: AsyncSession) -> dict:
    """Compute status for all sentinels and update computed_status.

    Returns counts per new status.
    """
    result = await session.execute(select(Sentinel))
    sentinels = list(result.scalars().all())

    counts: dict[str, int] = {"active": 0, "degraded": 0, "offline": 0}

    for sentinel in sentinels:
        new_status = compute_status_from_last_seen(sentinel.last_seen)
        old_status = sentinel.computed_status or "active"

        if new_status != old_status:
            sentinel.computed_status = new_status
            await record_lifecycle_event(
                session,
                sentinel_id=sentinel.id,
                event_type="status_change",
                old_status=old_status,
                new_status=new_status,
            )
            logger.info(
                "Sentinel %s transitioned %s → %s", sentinel.id, old_status, new_status
            )

        counts[new_status] = counts.get(new_status, 0) + 1

    await session.flush()
    return counts
