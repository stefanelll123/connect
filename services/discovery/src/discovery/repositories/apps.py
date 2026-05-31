"""App repository — CRUD operations for the apps table."""
from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.db.models.apps import App


class AppNotFoundError(Exception):
    def __init__(self, app_id: uuid.UUID) -> None:
        super().__init__(f"App not found: {app_id}")
        self.app_id = app_id


class AppNameConflictError(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(f"App name already exists: {name!r}")
        self.name = name


def _encode_cursor(created_at: datetime, row_id: uuid.UUID) -> str:
    data = f"{created_at.isoformat()}|{row_id}"
    return base64.urlsafe_b64encode(data.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    data = base64.urlsafe_b64decode(cursor.encode()).decode()
    ts_str, id_str = data.split("|", 1)
    return datetime.fromisoformat(ts_str), uuid.UUID(id_str)


class AppRepository:
    @staticmethod
    async def create(session: AsyncSession, *, name: str, owner: Optional[str] = None) -> App:
        app = App(id=uuid.uuid4(), name=name, owner=owner)
        session.add(app)
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise AppNameConflictError(name) from exc
        await session.refresh(app)
        return app

    @staticmethod
    async def get_by_id(session: AsyncSession, app_id: uuid.UUID) -> Optional[App]:
        result = await session.execute(select(App).where(App.id == app_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def list_paginated(
        session: AsyncSession,
        *,
        limit: int = 20,
        cursor: Optional[str] = None,
        active_only: bool = True,
    ) -> tuple[list[App], Optional[str]]:
        stmt = select(App)
        if active_only:
            stmt = stmt.where(App.is_active.is_(True))

        if cursor:
            cursor_ts, cursor_id = _decode_cursor(cursor)
            stmt = stmt.where(
                (App.created_at > cursor_ts)
                | ((App.created_at == cursor_ts) & (App.id > cursor_id))
            )

        stmt = stmt.order_by(App.created_at.asc(), App.id.asc()).limit(limit + 1)
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
    async def count(session: AsyncSession, *, active_only: bool = True) -> int:
        stmt = select(func.count()).select_from(App)
        if active_only:
            stmt = stmt.where(App.is_active.is_(True))
        result = await session.execute(stmt)
        return result.scalar_one()

    @staticmethod
    async def update(
        session: AsyncSession,
        app_id: uuid.UUID,
        *,
        name: Optional[str] = None,
        owner: Optional[str] = None,
    ) -> App:
        result = await session.execute(select(App).where(App.id == app_id))
        app = result.scalar_one_or_none()
        if app is None:
            raise AppNotFoundError(app_id)
        if name is not None:
            app.name = name
        if owner is not None:
            app.owner = owner
        app.updated_at = datetime.now(timezone.utc)
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise AppNameConflictError(name or "") from exc
        await session.refresh(app)
        return app

    @staticmethod
    async def deactivate(session: AsyncSession, app_id: uuid.UUID) -> App:
        result = await session.execute(select(App).where(App.id == app_id))
        app = result.scalar_one_or_none()
        if app is None:
            raise AppNotFoundError(app_id)
        app.is_active = False
        app.updated_at = datetime.now(timezone.utc)
        await session.flush()
        await session.refresh(app)
        return app
