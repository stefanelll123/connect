"""Unit tests for TASK-031: Blockchain Integration.

Tests ChainPolicyCache, ChainIndexer, anchor_retry_worker, and chain router
without a real blockchain or database.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from discovery.app import create_app
from discovery.auth.local_jwt import issue_dev_token
from discovery.config import DiscoverySettings
from discovery.dependencies import get_db, get_redis
from discovery.services.chain_policy_cache import ChainPolicyCache, get_chain_policy_cache, set_chain_policy_cache
from discovery.services.chain_indexer import ChainIndexer, get_chain_indexer, set_chain_indexer

SECRET = "test-chain-secret"


@pytest.fixture
def settings() -> DiscoverySettings:
    return DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        env="dev",
        auth_mode="local_jwt",
        local_jwt_secret=SECRET,
        blockchain_integration=False,
    )


@pytest.fixture
def blockchain_settings() -> DiscoverySettings:
    return DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        env="dev",
        auth_mode="local_jwt",
        local_jwt_secret=SECRET,
        blockchain_integration=True,
    )


def _viewer_headers() -> dict:
    token = issue_dev_token("viewer", ["viewer"], SECRET)
    return {"Authorization": f"Bearer {token}"}


def _mock_session():
    session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_result.scalar_one_or_none.return_value = None
    mock_result.scalars.return_value = MagicMock(all=MagicMock(return_value=[]))
    session.execute.return_value = mock_result
    session.flush = AsyncMock()
    session.add = MagicMock()
    return session


# ---------------------------------------------------------------------------
# ChainPolicyCache tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_policy_cache_fail_open_when_empty(settings):
    """is_issuer_active returns True when cache is empty (fail-open design)."""
    cache = ChainPolicyCache(settings)
    assert cache.is_issuer_active("did:key:anyDID") is True


@pytest.mark.asyncio
async def test_policy_cache_get_policy_returns_defaults(settings):
    """get_policy returns default PolicyParams for unknown env."""
    cache = ChainPolicyCache(settings)
    p = cache.get_policy("prod")
    assert p.env == "prod"
    assert p.max_token_ttl_seconds == 3600
    assert p.require_chain_of_trust is False


@pytest.mark.asyncio
async def test_policy_cache_load_when_integration_disabled(settings):
    """Cache load() succeeds quietly when blockchain_integration=False."""
    cache = ChainPolicyCache(settings)
    await cache.load()
    assert cache.is_stale is False
    assert cache.last_loaded_at is not None


@pytest.mark.asyncio
async def test_policy_cache_load_if_stale_triggers_reload(settings):
    """load_if_stale() triggers load when cache is older than TTL."""
    cache = ChainPolicyCache(settings)
    # Simulate stale cache by backdating last_loaded_at
    cache._last_loaded_at = datetime.now(timezone.utc) - timedelta(seconds=400)

    call_count = {"n": 0}
    original_do_load = cache._do_load

    async def _counting_load():
        call_count["n"] += 1
        await original_do_load()

    cache._do_load = _counting_load
    await cache.load_if_stale()
    assert call_count["n"] == 1


@pytest.mark.asyncio
async def test_policy_cache_singleton(settings):
    """Global singleton get/set round-trip."""
    cache = ChainPolicyCache(settings)
    set_chain_policy_cache(cache)
    assert get_chain_policy_cache() is cache


# ---------------------------------------------------------------------------
# ChainIndexer tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_indexer_disabled_when_integration_off(settings):
    """ChainIndexer returns False availability when blockchain_integration=False."""
    indexer = ChainIndexer(settings)
    available = await indexer.check_availability()
    assert available is False
    assert indexer.is_available is False


@pytest.mark.asyncio
async def test_indexer_poll_once_returns_zero_when_disabled(settings):
    """poll_once returns 0 events when blockchain disabled."""
    indexer = ChainIndexer(settings)
    session = _mock_session()
    count = await indexer.poll_once(session)
    assert count == 0


@pytest.mark.asyncio
async def test_indexer_singleton(settings):
    """Global singleton get/set round-trip."""
    indexer = ChainIndexer(settings)
    set_chain_indexer(indexer)
    assert get_chain_indexer() is indexer


# ---------------------------------------------------------------------------
# anchor_retry_worker tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_anchor_worker_skips_when_integration_disabled(settings):
    """anchor_pending_status_lists returns 0 when blockchain_integration=False."""
    from discovery.tasks.anchor_retry_worker import anchor_pending_status_lists
    from discovery.db.models.status_lists import StatusList

    session = _mock_session()
    # Simulate one pending anchor
    fake_sl = MagicMock(spec=StatusList)
    fake_sl.anchor_pending = True
    fake_sl.status_list_id = str(uuid.uuid4())
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [fake_sl]
    session.execute.return_value = mock_result

    count = await anchor_pending_status_lists(session, settings)
    assert count == 0


@pytest.mark.asyncio
async def test_anchor_worker_returns_zero_when_no_pending(settings):
    """anchor_pending_status_lists returns 0 with no pending items."""
    from discovery.tasks.anchor_retry_worker import anchor_pending_status_lists

    session = _mock_session()
    count = await anchor_pending_status_lists(session, settings)
    assert count == 0


# ---------------------------------------------------------------------------
# Chain router tests — via ASGI test client
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def chain_client(settings):
    app = create_app(settings=settings)
    mock_session = _mock_session()

    async def _override_db():
        yield mock_session

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_redis] = lambda: AsyncMock()

    # Install dummy singletons so router doesn't fail on None
    dummy_cache = MagicMock()
    dummy_cache.cache_age_seconds = 120.0
    dummy_cache.is_stale = False
    set_chain_policy_cache(dummy_cache)

    dummy_indexer = MagicMock()
    dummy_indexer.is_available = False
    dummy_indexer.last_indexed_block = 0
    set_chain_indexer(dummy_indexer)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_chain_status_endpoint(chain_client):
    """GET /api/v1/chain/status returns expected fields."""
    resp = await chain_client.get("/api/v1/chain/status", headers=_viewer_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert "is_available" in data
    assert "blockchain_integration_enabled" in data
    assert "policy_cache" in data


@pytest.mark.asyncio
async def test_chain_events_endpoint_empty(chain_client):
    """GET /api/v1/chain/events returns empty list when no events indexed."""
    resp = await chain_client.get("/api/v1/chain/events", headers=_viewer_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["count"] == 0


@pytest.mark.asyncio
async def test_chain_events_requires_auth(chain_client):
    """GET /api/v1/chain/events returns 401 without token."""
    resp = await chain_client.get("/api/v1/chain/events")
    assert resp.status_code == 401
