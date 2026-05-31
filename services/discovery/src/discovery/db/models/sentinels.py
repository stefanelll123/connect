"""Sentinel and SentinelInstance ORM models."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Integer,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column

from discovery.db.base import Base


class Sentinel(Base):
    __tablename__ = "sentinels"
    __table_args__ = (
        UniqueConstraint("did", "role", "env", name="uq_sentinels_did_role_env"),
        CheckConstraint("role IN ('producer', 'consumer')", name="ck_sentinels_role"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    service_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("services.id", ondelete="CASCADE"),
        nullable=True,
    )
    did: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    env: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default="true", nullable=False
    )
    created_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
    last_seen: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    config_version: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    # Computed status — written by heartbeat_monitor background task (TASK-033)
    computed_status: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default="active"
    )


class SentinelInstance(Base):
    __tablename__ = "sentinel_instances"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'draining', 'offline')",
            name="ck_sentinel_instances_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sentinel_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinels.id", ondelete="CASCADE"),
        nullable=True,
    )
    instance_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    base_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    metadata_: Mapped[Optional[dict]] = mapped_column(
        "metadata", JSONB, nullable=True
    )
