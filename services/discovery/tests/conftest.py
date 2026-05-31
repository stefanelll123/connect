"""Shared pytest fixtures for the Discovery Service tests."""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from discovery.app import create_app
from discovery.config import DiscoverySettings


@pytest.fixture
def test_settings() -> DiscoverySettings:
    """Minimal settings for tests — no real DB or Redis needed."""
    return DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        redis_url="redis://localhost:6379/15",
        env="dev",
    )


@pytest.fixture
def app(test_settings: DiscoverySettings):
    """Configured FastAPI application with test settings."""
    return create_app(settings=test_settings)


@pytest_asyncio.fixture
async def client(app):
    """AsyncClient pointed at the test app via ASGI transport."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
