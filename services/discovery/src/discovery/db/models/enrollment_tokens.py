"""EnrollmentToken ORM model.

Security note: ``token_hash`` stores SHA-256(JWT) — the raw JWT is NEVER
persisted.  ``consumed_at`` is set atomically via SELECT FOR UPDATE to
prevent double-consumption under concurrent requests.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, CheckConstraint, Text, func
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column

from discovery.db.base import Base


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING', 'APPROVED', 'CONSUMED', 'EXPIRED')",
            name="ck_enrollment_tokens_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # jti is the JWT ID claim — UNIQUE provides replay protection
    jti: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    service_id: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    env: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # SHA-256 of the JWT — the raw token MUST NOT be stored
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False
    )
    consumed_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    cancelled_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    # Optional IP/metadata constraints (JSONB so we can query inside)
    constraints: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

