"""Status list repository — atomic index allocation and bit manipulation (TASK-030)."""
from __future__ import annotations

import logging
import uuid
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.db.models.status_lists import StatusList

logger = logging.getLogger(__name__)

_DEFAULT_MAX_SIZE = 131072  # 2^17 entries


class StatusListRepository:
    @staticmethod
    async def get_by_slug(
        session: AsyncSession, status_list_id: str
    ) -> Optional[StatusList]:
        result = await session.execute(
            select(StatusList).where(StatusList.status_list_id == status_list_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_active_bucket(
        session: AsyncSession,
        issuer_did: str,
        env: str,
        credential_type: str,
    ) -> Optional[StatusList]:
        """Return the most-recently created non-frozen list for this bucket."""
        result = await session.execute(
            select(StatusList)
            .where(
                StatusList.issuer_did == issuer_did,
                StatusList.env == env,
                StatusList.credential_type == credential_type,
                StatusList.is_frozen.is_(False),
            )
            .order_by(StatusList.version.desc())
            .limit(1)
            .with_for_update()  # serialized index allocation
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create(session: AsyncSession, sl: StatusList) -> StatusList:
        session.add(sl)
        await session.flush()
        await session.refresh(sl)
        return sl

    @staticmethod
    async def save(session: AsyncSession, sl: StatusList) -> None:
        await session.flush()

    @staticmethod
    async def list_all(session: AsyncSession) -> list[StatusList]:
        result = await session.execute(select(StatusList))
        return list(result.scalars().all())


async def allocate_index(
    session: AsyncSession,
    issuer_did: str,
    env: str,
    credential_type: str,
) -> tuple[str, int]:
    """Atomically allocate the next available index in the status list.

    Returns (status_list_id, index).
    If the current list is full, a new one is created automatically.
    """
    sl = await StatusListRepository.get_active_bucket(
        session, issuer_did, env, credential_type
    )
    if sl is None:
        # Create the first list for this bucket
        slug = f"{env}-{credential_type.lower().replace('credential', '')}-001"
        bitstring_size = _DEFAULT_MAX_SIZE // 8  # bytes
        sl = StatusList(
            status_list_id=slug,
            issuer_did=issuer_did,
            env=env,
            credential_type=credential_type,
            bitstring=bytes(bitstring_size),
            top_index=0,
            max_size=_DEFAULT_MAX_SIZE,
            dirty=False,
            is_frozen=False,
            current_hash="",
            version=1,
            anchor_pending=False,
        )
        sl = await StatusListRepository.create(session, sl)

    if sl.top_index >= sl.max_size:
        # List is full — freeze it and create a new one
        sl.is_frozen = True
        await StatusListRepository.save(session, sl)
        version = (sl.version or 1) + 1
        slug = (
            f"{env}-{credential_type.lower().replace('credential', '')}-{version:03d}"
        )
        bitstring_size = _DEFAULT_MAX_SIZE // 8
        sl = StatusList(
            status_list_id=slug,
            issuer_did=issuer_did,
            env=env,
            credential_type=credential_type,
            bitstring=bytes(bitstring_size),
            top_index=0,
            max_size=_DEFAULT_MAX_SIZE,
            dirty=False,
            is_frozen=False,
            current_hash="",
            version=version,
            anchor_pending=False,
        )
        sl = await StatusListRepository.create(session, sl)

    index = sl.top_index
    sl.top_index = index + 1
    await StatusListRepository.save(session, sl)
    return sl.status_list_id, index


async def set_bit(
    session: AsyncSession,
    status_list_id: str,
    index: int,
    value: int,  # 0 or 1
) -> None:
    """Set a single bit in the status list bitstring (0=valid, 1=revoked)."""
    sl = await StatusListRepository.get_by_slug(session, status_list_id)
    if sl is None:
        raise ValueError(f"Status list '{status_list_id}' not found")
    if sl.bitstring is None:
        raise ValueError("Status list has no bitstring")

    byte_index = index // 8
    bit_offset = index % 8
    bs = bytearray(sl.bitstring)

    if value == 1:
        bs[byte_index] |= 1 << bit_offset
    else:
        bs[byte_index] &= ~(1 << bit_offset)

    sl.bitstring = bytes(bs)
    sl.dirty = True
    await StatusListRepository.save(session, sl)


async def get_bit(
    session: AsyncSession,
    status_list_id: str,
    index: int,
) -> int:
    """Return the bit value (0 or 1) at the given index."""
    sl = await StatusListRepository.get_by_slug(session, status_list_id)
    if sl is None:
        raise ValueError(f"Status list '{status_list_id}' not found")
    if sl.bitstring is None:
        return 0
    byte_index = index // 8
    bit_offset = index % 8
    return (sl.bitstring[byte_index] >> bit_offset) & 1
