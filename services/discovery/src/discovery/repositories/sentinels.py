"""Sentinel repository — basic CRUD and lookup operations."""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.db.models.sentinels import Sentinel, SentinelInstance


class SentinelRepository:
    @staticmethod
    async def get_by_did(
        session: AsyncSession, did: str, env: str
    ) -> list[Sentinel]:
        result = await session.execute(
            select(Sentinel).where(Sentinel.did == did, Sentinel.env == env)
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_by_id(
        session: AsyncSession, sentinel_id: uuid.UUID
    ) -> Sentinel | None:
        result = await session.execute(
            select(Sentinel).where(Sentinel.id == sentinel_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create(session: AsyncSession, sentinel: Sentinel) -> Sentinel:
        session.add(sentinel)
        await session.flush()
        await session.refresh(sentinel)
        return sentinel

    @staticmethod
    async def get_instance_by_id(
        session: AsyncSession, instance_id: str
    ) -> SentinelInstance | None:
        result = await session.execute(
            select(SentinelInstance).where(SentinelInstance.instance_id == instance_id)
        )
        return result.scalar_one_or_none()
