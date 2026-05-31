"""AuditLogger service — hash-chained, append-only audit events (TASK-034).

AuditAction enum defines all permitted audit action strings.
AuditLogger.log() computes:
  - prev_hash: SHA-256 of the most recent event_hash for this actor_id
  - event_hash: SHA-256(event_id + ts + actor_id + action + target_id + summary_canonical + prev_hash)

Both the triggering action and the audit record commit atomically (same transaction).
"""
from __future__ import annotations

import enum
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, Union

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.db.models.audit_events import AuditEvent
from discovery.repositories.audit import AuditRepository

logger = logging.getLogger(__name__)

# Sensitive keys that MUST be redacted from summary
_REDACTED_KEYS = frozenset(
    {"token", "secret", "password", "key", "private_key", "api_key", "auth", "credential", "jwt"}
)
_MAX_VALUE_LEN = 1000


class AuditAction(str, enum.Enum):
    CREATE_SERVICE = "CREATE_SERVICE"
    UPDATE_SERVICE = "UPDATE_SERVICE"
    DEACTIVATE_SERVICE = "DEACTIVATE_SERVICE"
    CREATE_ENROLLMENT_TOKEN = "CREATE_ENROLLMENT_TOKEN"
    APPROVE_ENROLLMENT_TOKEN = "APPROVE_ENROLLMENT_TOKEN"
    CANCEL_ENROLLMENT_TOKEN = "CANCEL_ENROLLMENT_TOKEN"
    SENTINEL_ONBOARDED = "SENTINEL_ONBOARDED"
    SENTINEL_DECOMMISSIONED = "SENTINEL_DECOMMISSIONED"
    SENTINEL_REJOINED = "SENTINEL_REJOINED"
    ISSUE_CREDENTIAL = "ISSUE_CREDENTIAL"
    REVOKE_CREDENTIAL = "REVOKE_CREDENTIAL"
    ROTATE_CREDENTIAL = "ROTATE_CREDENTIAL"
    PUBLISH_STATUS_LIST = "PUBLISH_STATUS_LIST"
    ANCHOR_STATUS_ON_CHAIN = "ANCHOR_STATUS_ON_CHAIN"
    ROLLBACK_CONFIG = "ROLLBACK_CONFIG"
    ADMIN_LOGIN = "ADMIN_LOGIN"
    ADMIN_LOGOUT = "ADMIN_LOGOUT"
    BREAK_GLASS_ACCESS = "BREAK_GLASS_ACCESS"
    KEY_ROTATION = "KEY_ROTATION"
    AUDIT_EXPORT_INITIATED = "AUDIT_EXPORT_INITIATED"
    DESCRIPTOR_PUBLISHED = "DESCRIPTOR_PUBLISHED"
    DESCRIPTOR_INVALIDATED = "DESCRIPTOR_INVALIDATED"


def sanitize_summary(summary: dict) -> dict:
    """Strip sensitive keys and truncate long values."""
    clean: dict = {}
    for k, v in summary.items():
        k_lower = k.lower()
        if any(sensitive in k_lower for sensitive in _REDACTED_KEYS):
            clean[k] = "<REDACTED>"
        elif isinstance(v, str) and len(v) > _MAX_VALUE_LEN:
            clean[k] = v[:_MAX_VALUE_LEN] + "...<truncated>"
        elif isinstance(v, dict):
            clean[k] = sanitize_summary(v)
        else:
            clean[k] = v
    return clean


def _canonical_summary(summary: dict) -> str:
    return json.dumps(summary, sort_keys=True, separators=(",", ":"), default=str)


def _compute_event_hash(
    event_id: str,
    ts: datetime,
    actor_id: str,
    action: str,
    target_id: str,
    summary_canonical: str,
    prev_hash: str,
) -> str:
    data = "|".join([event_id, ts.isoformat(), actor_id, action, target_id, summary_canonical, prev_hash])
    return hashlib.sha256(data.encode()).hexdigest()


async def _get_prev_hash(session: AsyncSession, actor_id: str) -> str:
    """Return the hash of the most recent event for this actor, or empty string."""
    result = await session.execute(
        select(AuditEvent.event_hash)
        .where(AuditEvent.actor_id == actor_id)
        .order_by(AuditEvent.ts.desc())
        .limit(1)
    )
    row = result.scalar_one_or_none()
    return row or ""


class AuditLogger:
    """Append-only, hash-chained audit log writer."""

    @staticmethod
    async def log(
        session: AsyncSession,
        *,
        actor_type: str,
        actor_id: str,
        action: Union[AuditAction, str],
        target_type: str = "",
        target_id: str = "",
        summary: Union[dict, str] = "",
        request_id: str = "",
        ip_address: str = "",
    ) -> AuditEvent:
        """Create and persist an audit event.  Raises on failure (rolls back with caller)."""
        ts = datetime.now(timezone.utc)
        event_id = f"urn:uuid:{uuid.uuid4()}"
        action_str = action.value if isinstance(action, AuditAction) else str(action)

        # Sanitize summary
        if isinstance(summary, dict):
            safe_summary = sanitize_summary(summary)
            summary_canonical = _canonical_summary(safe_summary)
            summary_str = json.dumps(safe_summary, default=str)
        else:
            summary_str = str(summary)
            summary_canonical = summary_str

        # Compute hash chain
        prev_hash = await _get_prev_hash(session, actor_id)
        event_hash = _compute_event_hash(
            event_id, ts, actor_id, action_str, target_id, summary_canonical, prev_hash
        )

        event = AuditEvent(
            event_id=event_id,
            ts=ts,
            actor_type=actor_type,
            actor_id=actor_id,
            action=action_str,
            target_type=target_type,
            target_id=target_id,
            summary=summary_str,
            request_id=request_id,
            ip_address=ip_address,
            prev_hash=prev_hash,
            event_hash=event_hash,
        )
        return await AuditRepository.append_event(session, event)
