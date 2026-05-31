"""Sentinel lifecycle service — state machine, decommission cascade (TASK-033)."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.db.models.sentinel_lifecycle import SentinelLifecycleEvent
from discovery.db.models.sentinels import Sentinel, SentinelInstance

logger = logging.getLogger(__name__)

# Heartbeat timeout thresholds (seconds)
_DEGRADED_THRESHOLD = 90    # active → degraded after 90 s without heartbeat
_OFFLINE_THRESHOLD = 300    # degraded → offline after 300 s


def compute_status_from_last_seen(last_seen: Optional[datetime]) -> str:
    """Pure function: derive status from last_seen timestamp."""
    if last_seen is None:
        return "offline"
    age = (datetime.now(timezone.utc) - last_seen).total_seconds()
    if age <= _DEGRADED_THRESHOLD:
        return "active"
    elif age <= _OFFLINE_THRESHOLD:
        return "degraded"
    return "offline"


async def record_lifecycle_event(
    session: AsyncSession,
    *,
    sentinel_id: uuid.UUID,
    event_type: str,
    old_status: Optional[str],
    new_status: Optional[str],
    instance_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    reason: Optional[str] = None,
) -> SentinelLifecycleEvent:
    event = SentinelLifecycleEvent(
        sentinel_id=sentinel_id,
        event_type=event_type,
        old_status=old_status,
        new_status=new_status,
        instance_id=instance_id,
        actor_id=actor_id,
        ts=datetime.now(timezone.utc),
        reason=reason,
    )
    session.add(event)
    await session.flush()
    return event


async def process_heartbeat(
    session: AsyncSession,
    *,
    sentinel_id: uuid.UUID,
    instance_id: str,
    version: str,
    health: dict,
    heartbeat_interval: int = 30,
) -> dict:
    """Update last_seen on sentinel + instance, compute new status."""
    now = datetime.now(timezone.utc)

    # Load sentinel
    result = await session.execute(
        select(Sentinel).where(Sentinel.id == sentinel_id)
    )
    sentinel = result.scalar_one_or_none()
    if sentinel is None:
        raise ValueError(f"Sentinel {sentinel_id} not found")

    old_status = sentinel.computed_status
    sentinel.last_seen = now
    new_status = "active"
    sentinel.computed_status = new_status

    # Upsert instance row
    result2 = await session.execute(
        select(SentinelInstance).where(SentinelInstance.instance_id == instance_id)
    )
    instance = result2.scalar_one_or_none()
    if instance is None:
        instance = SentinelInstance(
            sentinel_id=sentinel_id,
            instance_id=instance_id,
            status="active",
            last_seen=now,
            metadata_={"version": version, "health": health},
        )
        session.add(instance)
    else:
        instance.last_seen = now
        instance.status = "active"
        instance.metadata_ = {"version": version, "health": health}

    await session.flush()

    # Record lifecycle event only if status changed
    if old_status != new_status:
        await record_lifecycle_event(
            session,
            sentinel_id=sentinel_id,
            event_type="status_change",
            old_status=old_status,
            new_status=new_status,
            instance_id=instance_id,
        )

    next_expected = now + timedelta(seconds=heartbeat_interval)
    return {
        "acknowledged_at": now.isoformat(),
        "next_expected_at": next_expected.isoformat(),
    }


async def decommission_sentinel(
    session: AsyncSession,
    *,
    sentinel_id: uuid.UUID,
    reason: str,
    revoke_credentials: bool,
    invalidate_descriptor: bool,
    actor_id: str,
    settings,
) -> dict:
    """Cascade decommission: mark inactive, revoke creds, invalidate descriptor."""
    result = await session.execute(
        select(Sentinel).where(Sentinel.id == sentinel_id)
    )
    sentinel = result.scalar_one_or_none()
    if sentinel is None:
        raise ValueError("Sentinel not found")

    old_status = sentinel.computed_status

    # Cascade: revoke all active credentials
    if revoke_credentials:
        from discovery.db.models.credentials import Credential
        from sqlalchemy import update

        await session.execute(
            select(Credential).where(
                Credential.subject_did == sentinel.did,
                Credential.env == sentinel.env,
                Credential.status == "active",
            )
        )
        # Bulk mark revoked
        from sqlalchemy import update as sa_update
        await session.execute(
            sa_update(Credential)
            .where(
                Credential.subject_did == sentinel.did,
                Credential.env == sentinel.env,
                Credential.status == "active",
            )
            .values(status="revoked")
        )

    # Cascade: invalidate descriptor if service association exists
    if invalidate_descriptor and sentinel.service_id:
        from discovery.services import descriptor_service
        from discovery.db.models.services import Service

        result_svc = await session.execute(
            select(Service).where(Service.id == sentinel.service_id)
        )
        svc = result_svc.scalar_one_or_none()
        if svc:
            await descriptor_service.invalidate(
                session, service_id=svc.service_id, env=sentinel.env
            )

    # Mark all instances offline
    result_inst = await session.execute(
        select(SentinelInstance).where(SentinelInstance.sentinel_id == sentinel_id)
    )
    for inst in result_inst.scalars().all():
        inst.status = "offline"

    # Mark sentinel inactive
    sentinel.is_active = False
    sentinel.computed_status = "offline"

    await session.flush()

    # Record lifecycle event
    await record_lifecycle_event(
        session,
        sentinel_id=sentinel_id,
        event_type="decommission",
        old_status=old_status,
        new_status="offline",
        actor_id=actor_id,
        reason=reason,
    )

    return {
        "sentinel_id": str(sentinel_id),
        "status": "DECOMMISSIONED",
        "revoked_credentials": revoke_credentials,
        "invalidated_descriptor": invalidate_descriptor,
    }


async def rejoin_sentinel(
    session: AsyncSession,
    *,
    sentinel_id: uuid.UUID,
    did: str,
    new_instance_id: str,
    new_base_url: Optional[str],
    actor_id: str,
) -> Sentinel:
    """Reactivate a sentinel after recovery or migration."""
    result = await session.execute(
        select(Sentinel).where(Sentinel.id == sentinel_id)
    )
    sentinel = result.scalar_one_or_none()
    if sentinel is None:
        raise ValueError("Sentinel not found")

    if sentinel.did != did:
        raise ValueError("DID_MISMATCH")

    old_status = sentinel.computed_status
    now = datetime.now(timezone.utc)
    sentinel.is_active = True
    sentinel.computed_status = "active"
    sentinel.last_seen = now

    # Register new instance
    instance = SentinelInstance(
        sentinel_id=sentinel_id,
        instance_id=new_instance_id,
        base_url=new_base_url,
        status="active",
        last_seen=now,
    )
    session.add(instance)
    await session.flush()

    await record_lifecycle_event(
        session,
        sentinel_id=sentinel_id,
        event_type="rejoin",
        old_status=old_status,
        new_status="active",
        instance_id=new_instance_id,
        actor_id=actor_id,
    )
    return sentinel
