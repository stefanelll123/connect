"""ServiceDescriptorEndpoint ORM model — per-instance endpoint registry (TASK-048).

Each sentinel instance registers its own endpoint URL and health status here.
The GET /registry/resolve endpoint joins this table to include live endpoints
in the resolved descriptor response.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Integer, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column

from discovery.db.base import Base


class ServiceDescriptorEndpoint(Base):
    """One row per (service_id, env, instance_id) — upserted by each sentinel instance."""

    __tablename__ = "service_descriptor_endpoints"
    __table_args__ = (
        UniqueConstraint(
            "service_id", "env", "instance_id",
            name="uq_sde_service_env_instance",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    service_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    env: Mapped[str] = mapped_column(Text, nullable=False)
    instance_id: Mapped[str] = mapped_column(Text, nullable=False)
    endpoint_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    weight: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    # "active" | "draining" | "offline" | "unhealthy"
    health_status: Mapped[str] = mapped_column(
        Text, default="active", nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default="true", nullable=False
    )
