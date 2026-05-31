"""Async SQLAlchemy engine and session factory helpers."""
from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def get_engine(database_url: str) -> AsyncEngine:
    """Create an async engine for the given DSN.

    The engine is lazy — no actual TCP connection is made until the first
    query is executed.  ``pool_recycle=3600`` prevents stale connections.
    """
    return create_async_engine(
        database_url,
        pool_size=10,
        max_overflow=20,
        pool_recycle=3600,
        echo=False,
    )


def get_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Return a session factory bound to *engine*."""
    return async_sessionmaker(
        bind=engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )
