"""AuditEvent ORM model — append-only audit log.

SECURITY: This table has NO application-level UPDATE or DELETE path.
All write access goes through AuditRepository.append_event() only.
The event_hash / prev_hash chain provides tamper detection.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Text, func
from sqlalchemy.dialects.postgresql import TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column

from discovery.db.base import Base


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    event_id: Mapped[Optional[str]] = mapped_column(Text, unique=True, nullable=True)
    ts: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    actor_type: Mapped[str] = mapped_column(Text, nullable=False)
    actor_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    target_type: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    target_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    prev_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    event_hash: Mapped[str] = mapped_column(Text, nullable=False)
