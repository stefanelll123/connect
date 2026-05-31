"""Service repository — CRUD for the services table."""
from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.db.models.services import Service


class ServiceChainSyncError(Exception):
    pass


class ServiceNotFoundError(Exception):
    def __init__(self, identifier: str) -> None:
        super().__init__(f"Service not found: {identifier}")
        self.identifier = identifier


class ServiceAlreadyExistsError(Exception):
    def __init__(self, service_id: str, env: str) -> None:
        super().__init__(f"Service '{service_id}' already exists in env '{env}'")
        self.service_id = service_id
        self.env = env


def _encode_cursor(created_at: datetime, row_id: uuid.UUID) -> str:
    data = f"{created_at.isoformat()}|{row_id}"
    return base64.urlsafe_b64encode(data.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    data = base64.urlsafe_b64decode(cursor.encode()).decode()
    ts_str, id_str = data.split("|", 1)
    return datetime.fromisoformat(ts_str), uuid.UUID(id_str)


class ServiceRepository:
    @staticmethod
    async def create(
        session: AsyncSession,
        *,
        app_id: uuid.UUID,
        service_id: str,
        env: str,
        display_name: str,
        description: Optional[str] = None,
        owner_did: Optional[str] = None,
        base_url: Optional[str] = None,
        chain_sync_pending: bool = False,
    ) -> Service:
        svc = Service(
            id=uuid.uuid4(),
            app_id=app_id,
            service_id=service_id,
            env=env,
            display_name=display_name,
            description=description,
            owner_did=owner_did,
            base_url=base_url,
            chain_sync_pending=chain_sync_pending,
        )
        session.add(svc)
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise ServiceAlreadyExistsError(service_id, env) from exc
        await session.refresh(svc)
        return svc

    @staticmethod
    async def mark_chain_synced(
        session: AsyncSession,
        service_pk: uuid.UUID,
        *,
        tx_hash: str,
    ) -> None:
        """Mark a service as successfully registered on-chain."""
        result = await session.execute(select(Service).where(Service.id == service_pk))
        svc = result.scalar_one_or_none()
        if svc is None:
            return
        svc.chain_sync_pending = False
        svc.chain_tx_hash = tx_hash
        svc.updated_at = datetime.now(timezone.utc)
        await session.flush()

    @staticmethod
    async def mark_chain_sync_failed(
        session: AsyncSession,
        service_pk: uuid.UUID,
    ) -> None:
        """Increment attempt counter after a failed on-chain registration."""
        result = await session.execute(select(Service).where(Service.id == service_pk))
        svc = result.scalar_one_or_none()
        if svc is None:
            return
        svc.chain_sync_attempts = (svc.chain_sync_attempts or 0) + 1
        svc.updated_at = datetime.now(timezone.utc)
        await session.flush()

    @staticmethod
    async def get_by_id(session: AsyncSession, service_pk: uuid.UUID) -> Optional[Service]:
        result = await session.execute(select(Service).where(Service.id == service_pk))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_service_id_env(
        session: AsyncSession, service_id: str, env: str
    ) -> Optional[Service]:
        result = await session.execute(
            select(Service).where(
                Service.service_id == service_id, Service.env == env
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def list_paginated(
        session: AsyncSession,
        *,
        limit: int = 20,
        cursor: Optional[str] = None,
        env: Optional[Literal["dev", "test", "prod"]] = None,
        app_id: Optional[uuid.UUID] = None,
        active_only: bool = True,
    ) -> tuple[list[Service], Optional[str]]:
        stmt = select(Service)
        if active_only:
            stmt = stmt.where(Service.is_active.is_(True))
        if env:
            stmt = stmt.where(Service.env == env)
        if app_id:
            stmt = stmt.where(Service.app_id == app_id)
        if cursor:
            cursor_ts, cursor_id = _decode_cursor(cursor)
            stmt = stmt.where(
                (Service.created_at > cursor_ts)
                | ((Service.created_at == cursor_ts) & (Service.id > cursor_id))
            )
        stmt = stmt.order_by(Service.created_at.asc(), Service.id.asc()).limit(limit + 1)
        result = await session.execute(stmt)
        rows = list(result.scalars().all())

        next_cursor: Optional[str] = None
        if len(rows) > limit:
            rows = rows[:limit]
            last = rows[-1]
            if last.created_at:
                next_cursor = _encode_cursor(last.created_at, last.id)

        return rows, next_cursor

    @staticmethod
    async def count(
        session: AsyncSession,
        *,
        env: Optional[str] = None,
        app_id: Optional[uuid.UUID] = None,
        active_only: bool = True,
    ) -> int:
        stmt = select(func.count()).select_from(Service)
        if active_only:
            stmt = stmt.where(Service.is_active.is_(True))
        if env:
            stmt = stmt.where(Service.env == env)
        if app_id:
            stmt = stmt.where(Service.app_id == app_id)
        result = await session.execute(stmt)
        return result.scalar_one()

    @staticmethod
    async def update(
        session: AsyncSession,
        service_pk: uuid.UUID,
        *,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Service:
        result = await session.execute(select(Service).where(Service.id == service_pk))
        svc = result.scalar_one_or_none()
        if svc is None:
            raise ServiceNotFoundError(str(service_pk))
        if display_name is not None:
            svc.display_name = display_name
        if description is not None:
            svc.description = description
        svc.updated_at = datetime.now(timezone.utc)
        await session.flush()
        await session.refresh(svc)
        return svc

    @staticmethod
    async def deactivate(session: AsyncSession, service_pk: uuid.UUID) -> Service:
        result = await session.execute(select(Service).where(Service.id == service_pk))
        svc = result.scalar_one_or_none()
        if svc is None:
            raise ServiceNotFoundError(str(service_pk))
        svc.is_active = False
        svc.updated_at = datetime.now(timezone.utc)
        await session.flush()
        await session.refresh(svc)
        return svc
