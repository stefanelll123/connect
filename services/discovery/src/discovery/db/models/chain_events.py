"""ChainEvent ORM model — immutable log of on-chain contract events (TASK-031)."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column

from discovery.db.base import Base


class ChainEvent(Base):
    __tablename__ = "chain_events"
    __table_args__ = (
        UniqueConstraint("tx_hash", "event_name", name="uq_chain_events_tx_event"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tx_hash: Mapped[str] = mapped_column(Text, nullable=False)
    block_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_name: Mapped[str] = mapped_column(Text, nullable=False)
    contract: Mapped[str] = mapped_column(Text, nullable=False)
    args_json: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    indexed_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
