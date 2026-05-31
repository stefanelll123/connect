"""StatusList ORM model — on-chain anchored status list records."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Boolean, Integer, LargeBinary, Text, func
from sqlalchemy.dialects.postgresql import TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column


from discovery.db.base import Base


class StatusList(Base):
    __tablename__ = "status_lists"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    status_list_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    issuer_did: Mapped[str] = mapped_column(Text, nullable=False)
    env: Mapped[str] = mapped_column(Text, nullable=False)
    credential_type: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Raw bitstring bytes — gzip+base64url encoding is applied at JWT generation time
    bitstring: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    top_index: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    max_size: Mapped[int] = mapped_column(
        Integer, default=131072, server_default="131072", nullable=False
    )
    dirty: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    is_frozen: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    current_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    bitstring_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    published_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    version: Mapped[int] = mapped_column(
        Integer, default=1, server_default="1", nullable=False
    )
    anchor_tx_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    anchor_block: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    anchor_pending: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default="true", nullable=False
    )
    anchor_attempts: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    anchor_next_retry_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
