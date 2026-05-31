"""AuditCheckpoint ORM model (TASK-034).

Stores hourly global chain checkpoints used for tamper detection.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Text, func
from sqlalchemy.dialects.postgresql import TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column

from discovery.db.base import Base


class AuditCheckpoint(Base):
    __tablename__ = "audit_checkpoints"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    checkpoint_hash: Mapped[str] = mapped_column(Text, nullable=False)
    events_count: Mapped[int] = mapped_column(default=0)
    computed_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    anchor_tx_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
