"""AuditEvent repository — append-only access to the audit log.

SECURITY: This class intentionally exposes NO update() or delete() methods.
The audit log is immutable at the application layer.  Any attempt to modify
audit events must go through a DB-level privileged migration, which requires
explicit approval and leaves a trail.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Union

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.db.models.audit_events import AuditEvent


class AuditRepository:
    """Append-only repository for AuditEvent records."""

    @staticmethod
    async def append_event(session: AsyncSession, event: AuditEvent) -> AuditEvent:
        """Persist a new audit event.

        This is the **only** write operation available on this repository.
        """
        session.add(event)
        await session.flush()
        await session.refresh(event)
        return event

    @staticmethod
    async def get_by_event_id(
        session: AsyncSession, event_id: str
    ) -> AuditEvent | None:
        result = await session.execute(
            select(AuditEvent).where(AuditEvent.event_id == event_id)
        )
        return result.scalar_one_or_none()


async def audit_log(
    session: AsyncSession,
    *,
    actor_type: str,
    actor_id: str,
    action: str,
    target_type: str = "",
    target_id: str = "",
    summary: Union[dict, str] = "",
    request_id: str = "",
    ip_address: str = "",
) -> AuditEvent:
    """Create and persist an immutable audit event with a content hash.

    This is the canonical way to write audit events from service/router code.
    The ``sub`` field from CurrentUser should always be passed as ``actor_id``.
    """
    event_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc)
    summary_str = json.dumps(summary, default=str) if isinstance(summary, dict) else str(summary)

    canonical = json.dumps(
        {
            "event_id": event_id,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "ts": ts.isoformat(),
        },
        sort_keys=True,
    )
    event_hash = hashlib.sha256(canonical.encode()).hexdigest()

    event = AuditEvent(
        event_id=event_id,
        ts=ts,
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        summary=summary_str,
        request_id=request_id,
        ip_address=ip_address,
        event_hash=event_hash,
    )
    return await AuditRepository.append_event(session, event)

