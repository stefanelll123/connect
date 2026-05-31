"""Service ORM model — service registration per (service_id, env)."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Boolean, CheckConstraint, ForeignKey, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column

from discovery.db.base import Base


class Service(Base):
    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("service_id", "env", name="uq_services_service_env"),
        CheckConstraint("env IN ('dev', 'test', 'prod')", name="ck_services_env"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    app_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("apps.id", ondelete="CASCADE"),
        nullable=True,
    )
    service_id: Mapped[str] = mapped_column(Text, nullable=False)
    env: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owner_did: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    base_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default="true", nullable=False
    )
    created_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )

    # ------------------------------------------------------------------ #
    # Chain sync state — TASK-031 Step 6                                  #
    # ------------------------------------------------------------------ #
    # True while on-chain registration has not yet been confirmed
    chain_sync_pending: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    # tx_hash once the on-chain call succeeds
    chain_tx_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Number of on-chain registration attempts (for exponential back-off)
    chain_sync_attempts: Mapped[int] = mapped_column(
        BigInteger, default=0, server_default="0", nullable=False
    )
    # Earliest time the retry worker should try again (None → try immediately)
    chain_next_retry_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
