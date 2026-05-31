"""Config bundle repository — DB operations (TASK-027)."""
from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.db.models.config_bundles import ConfigBundle

_MAX_HISTORY = 10


class ConfigBundleRepository:
    @staticmethod
    async def get_current(
        session: AsyncSession, sentinel_id: uuid.UUID
    ) -> Optional[ConfigBundle]:
        result = await session.execute(
            select(ConfigBundle)
            .where(
                ConfigBundle.sentinel_id == sentinel_id,
                ConfigBundle.is_current.is_(True),
            )
            .limit(1)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_version(
        session: AsyncSession, sentinel_id: uuid.UUID, version: int
    ) -> Optional[ConfigBundle]:
        result = await session.execute(
            select(ConfigBundle).where(
                ConfigBundle.sentinel_id == sentinel_id,
                ConfigBundle.version == version,
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_history(
        session: AsyncSession, sentinel_id: uuid.UUID
    ) -> list[ConfigBundle]:
        result = await session.execute(
            select(ConfigBundle)
            .where(ConfigBundle.sentinel_id == sentinel_id)
            .order_by(ConfigBundle.version.desc())
            .limit(_MAX_HISTORY)
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_max_version(
        session: AsyncSession, sentinel_id: uuid.UUID
    ) -> int:
        from sqlalchemy import func as sa_func

        result = await session.execute(
            select(sa_func.coalesce(sa_func.max(ConfigBundle.version), 0)).where(
                ConfigBundle.sentinel_id == sentinel_id
            )
        )
        return result.scalar_one() or 0

    @staticmethod
    async def create(
        session: AsyncSession,
        bundle: ConfigBundle,
    ) -> ConfigBundle:
        # Mark all previous bundles for this sentinel as not current
        await session.execute(
            update(ConfigBundle)
            .where(
                ConfigBundle.sentinel_id == bundle.sentinel_id,
                ConfigBundle.is_current.is_(True),
            )
            .values(is_current=False)
        )
        session.add(bundle)
        await session.flush()
        await session.refresh(bundle)

        # Prune oldest bundles if history exceeds limit
        all_versions = await session.execute(
            select(ConfigBundle.id)
            .where(ConfigBundle.sentinel_id == bundle.sentinel_id)
            .order_by(ConfigBundle.version.desc())
        )
        ids = [row[0] for row in all_versions.all()]
        to_delete = ids[_MAX_HISTORY:]
        if to_delete:
            from sqlalchemy import delete as sa_delete

            await session.execute(
                sa_delete(ConfigBundle).where(ConfigBundle.id.in_(to_delete))
            )

        return bundle
