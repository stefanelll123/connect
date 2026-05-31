"""ConfigBundle ORM model — versioned signed configuration pushed to sentinels."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column

from discovery.db.base import Base


class ConfigBundle(Base):
    __tablename__ = "config_bundles"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sentinel_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sentinels.id", ondelete="CASCADE"),
        nullable=True,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    bundle_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Signed JWS of the configuration bundle — never store unsigned payload
    signed_bundle_jws: Mapped[str] = mapped_column(Text, nullable=False)
    issued_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    is_current: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default="true", nullable=False
    )
