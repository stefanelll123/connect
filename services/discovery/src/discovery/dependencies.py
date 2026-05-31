"""FastAPI dependency providers.

Each async generator / function here can be injected via ``Depends()``.
Settings are read from ``request.app.state.settings`` which is populated
by :func:`discovery.app.create_app` — this allows test fixtures to inject
custom settings without touching environment variables.
"""
from __future__ import annotations

from typing import AsyncGenerator

from fastapi import HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.config import DiscoverySettings


def get_settings(request: Request) -> DiscoverySettings:
    """Return the DiscoverySettings instance stored on app state."""
    return request.app.state.settings  # type: ignore[return-value]


async def get_db(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """Yield an async SQLAlchemy session.

    The engine is pulled from ``app.state.db_engine`` which is initialised
    during application startup.  Raises 503 if the DB engine was not
    successfully initialised.
    """
    engine = getattr(request.app.state, "db_engine", None)
    if engine is None:
        raise HTTPException(status_code=503, detail="Database not available")

    from discovery.db.session import get_session_factory

    factory = get_session_factory(engine)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_redis(request: Request):
    """Return the Redis client from app.state.

    Raises 503 if Redis was not successfully initialised at startup.
    """
    redis = getattr(request.app.state, "redis", None)
    if redis is None:
        raise HTTPException(status_code=503, detail="Redis not available")
    return redis
