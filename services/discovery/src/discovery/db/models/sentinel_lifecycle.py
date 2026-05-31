"""SentinelLifecycleEvent ORM model — append-only lifecycle audit log (TASK-033)."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Text, func
from sqlalchemy.dialects.postgresql import TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column

from discovery.db.base import Base


class SentinelLifecycleEvent(Base):
    __tablename__ = "sentinel_lifecycle_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sentinel_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    old_status: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    new_status: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    instance_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    actor_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ts: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
