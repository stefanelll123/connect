"""Credential ORM model — VC metadata only.

Security: VC JWT payload MUST NOT be stored here. Only metadata fields
(jti, type, issuer, subject, exp, status) are persisted.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, CheckConstraint, Integer, LargeBinary, Text, func
from sqlalchemy.dialects.postgresql import TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column

from discovery.db.base import Base


class Credential(Base):
    __tablename__ = "credentials"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'revoked', 'expired', 'deprecated')",
            name="ck_credentials_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    credential_type: Mapped[str] = mapped_column(Text, nullable=False)
    issuer_did: Mapped[str] = mapped_column(Text, nullable=False)
    subject_did: Mapped[str] = mapped_column(Text, nullable=False)
    audience: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    env: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # JWT ID claim — UNIQUE prevents duplicate admission
    jti: Mapped[Optional[str]] = mapped_column(Text, unique=True, nullable=True)
    issued_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(Text, nullable=False)
    status_list_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status_list_index: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    is_latest: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default="true", nullable=False
    )
    # Set when credential enters grace-period rotation (deprecated status)
    deprecated_until: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    # Set when credential is explicitly revoked via the admin API
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    # AES-256-GCM encrypted JWT payload (optional, only if CREDENTIAL_STORAGE_ENCRYPT=true)
    encrypted_payload: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True
    )
