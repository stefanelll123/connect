"""ServiceDescriptor ORM model — service endpoint descriptor storage (TASK-032)."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column

from discovery.db.base import Base


class ServiceDescriptor(Base):
    __tablename__ = "service_descriptors"
    __table_args__ = (
        UniqueConstraint("service_id", "env", name="uq_service_descriptors_service_env"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    service_id: Mapped[str] = mapped_column(Text, nullable=False)
    env: Mapped[str] = mapped_column(Text, nullable=False)
    producer_sentinel_did: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    descriptor_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    signed_descriptor_jws: Mapped[str] = mapped_column(Text, nullable=False)
    valid_until: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    published_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now()
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default="true", nullable=False
    )
    # On-chain anchor tx hash (optional, when ANCHOR_DESCRIPTORS_ON_CHAIN=true)
    anchor_tx_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
