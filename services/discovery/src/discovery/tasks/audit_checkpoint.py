"""Audit checkpoint background task — hourly global chain checkpoint (TASK-034)."""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.db.models.audit_events import AuditEvent
from discovery.db.models.audit import AuditCheckpoint

logger = logging.getLogger(__name__)

_CHECKPOINT_EVENTS = 1000  # number of recent events to hash


async def compute_checkpoint(session: AsyncSession) -> AuditCheckpoint:
    """Compute a global chain checkpoint for the last N events."""
    result = await session.execute(
        select(AuditEvent.event_hash)
        .order_by(AuditEvent.ts.desc())
        .limit(_CHECKPOINT_EVENTS)
    )
    hashes = [row for row in result.scalars().all()]

    # Deterministic: sort so checkpoint is stable for same set of events
    combined = "|".join(sorted(hashes))
    checkpoint_hash = hashlib.sha256(combined.encode()).hexdigest()

    checkpoint = AuditCheckpoint(
        checkpoint_hash=checkpoint_hash,
        events_count=len(hashes),
        computed_at=datetime.now(timezone.utc),
    )
    session.add(checkpoint)
    await session.flush()
    logger.info(
        "Audit checkpoint written: %s (%d events)", checkpoint_hash[:16], len(hashes)
    )
    return checkpoint
