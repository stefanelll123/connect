"""Unit tests for TASK-029: Credential Distribution and Rotation."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from discovery.app import create_app
from discovery.auth.local_jwt import issue_dev_token
from discovery.config import DiscoverySettings
from discovery.dependencies import get_db, get_redis
from discovery.db.models.credentials import Credential
from discovery.db.models.sentinels import Sentinel

SECRET = "test-secret"


@pytest.fixture
def settings() -> DiscoverySettings:
    return DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        env="dev",
        auth_mode="local_jwt",
        local_jwt_secret=SECRET,
    )


def _operator_headers() -> dict:
    token = issue_dev_token("admin", ["operator"], SECRET)
    return {"Authorization": f"Bearer {token}"}


def _security_admin_headers() -> dict:
    token = issue_dev_token("admin", ["security-admin"], SECRET)
    return {"Authorization": f"Bearer {token}"}


def _mock_session():
    session = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = []
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_result.scalar_one_or_none.return_value = None
    mock_result.scalar_one.return_value = 0
    mock_result.all.return_value = []
    session.execute.return_value = mock_result
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock()
    return session


@pytest_asyncio.fixture
async def app(settings):
    the_app = create_app(settings=settings)
    mock_session = _mock_session()
    the_app.dependency_overrides[get_db] = lambda: mock_session
    the_app.dependency_overrides[get_redis] = lambda: AsyncMock()
    async with AsyncClient(transport=ASGITransport(app=the_app), base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Credential distribution service unit tests
# ---------------------------------------------------------------------------

def test_compute_feed_etag_deterministic():
    from discovery.services.credential_distribution import _compute_feed_etag

    c1 = Credential(jti="urn:uuid:aaa")
    c2 = Credential(jti="urn:uuid:bbb")

    etag1 = _compute_feed_etag([c1, c2])
    etag2 = _compute_feed_etag([c2, c1])  # order shouldn't matter
    assert etag1 == etag2
    assert len(etag1) == 64


def test_compute_feed_etag_empty():
    from discovery.services.credential_distribution import _compute_feed_etag

    etag = _compute_feed_etag([])
    assert isinstance(etag, str)


def test_reconstruct_jwt_vc_produces_jwt(settings):
    from discovery.services.credential_distribution import reconstruct_jwt_vc

    now = datetime.now(timezone.utc)
    cred = Credential(
        id=uuid.uuid4(),
        credential_type="SentinelIdentityCredential",
        issuer_did="did:key:discovery",
        subject_did="did:key:z6MkTest",
        env="dev",
        jti=f"urn:uuid:{uuid.uuid4()}",
        issued_at=now,
        expires_at=now + timedelta(days=30),
        status="active",
        is_latest=True,
    )
    jwt_vc = reconstruct_jwt_vc(cred, settings)
    assert len(jwt_vc.split(".")) == 3


# ---------------------------------------------------------------------------
# Rotation sweeper unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rotation_sweeper_no_deprecated():
    from discovery.tasks.rotation_sweeper import sweep_deprecated_credentials

    session = _mock_session()
    mock_result = MagicMock()
    mock_result.rowcount = 0
    session.execute.return_value = mock_result

    count = await sweep_deprecated_credentials(session)
    assert count == 0


@pytest.mark.asyncio
async def test_rotation_sweeper_transitions_deprecated():
    from discovery.tasks.rotation_sweeper import sweep_deprecated_credentials

    session = _mock_session()
    mock_result = MagicMock()
    mock_result.rowcount = 3
    session.execute.return_value = mock_result

    count = await sweep_deprecated_credentials(session)
    assert count == 3


# ---------------------------------------------------------------------------
# Credential feed endpoint tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_credential_feed_requires_auth(app):
    sentinel_id = str(uuid.uuid4())
    resp = await app.get(f"/api/v1/sentinels/{sentinel_id}/credentials")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_credential_feed_sentinel_not_found(app):
    resp = await app.get(
        f"/api/v1/sentinels/{uuid.uuid4()}/credentials",
        headers=_operator_headers(),
    )
    assert resp.status_code == 404
    assert resp.json()["code"] == "SENTINEL_NOT_FOUND"


@pytest.mark.asyncio
async def test_credential_feed_invalid_sentinel_id(app):
    resp = await app.get(
        "/api/v1/sentinels/not-a-uuid/credentials",
        headers=_operator_headers(),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_credential_feed_empty_result(settings):
    """When sentinel found but no credentials, returns empty list."""
    sentinel = Sentinel(
        id=uuid.uuid4(),
        did="did:key:z6MkFeed",
        role="producer",
        env="dev",
        service_id=None,
        is_active=True,
    )
    the_app = create_app(settings=settings)
    mock_session = _mock_session()
    mock_session.execute.return_value.scalar_one_or_none.return_value = sentinel
    # Second call to execute (for credentials) returns empty
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = []
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_result.scalar_one_or_none.return_value = sentinel
    mock_session.execute.return_value = mock_result

    the_app.dependency_overrides[get_db] = lambda: mock_session
    the_app.dependency_overrides[get_redis] = lambda: AsyncMock()

    async with AsyncClient(transport=ASGITransport(app=the_app), base_url="http://test") as c:
        resp = await c.get(
            f"/api/v1/sentinels/{sentinel.id}/credentials",
            headers=_operator_headers(),
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "credentials" in data
    assert "fetched_at" in data
    assert "next_poll_after" in data


@pytest.mark.asyncio
async def test_full_sync_rate_limited(settings):
    """Full sync endpoint enforces rate limiting."""
    the_app = create_app(settings=settings)
    mock_session = _mock_session()
    the_app.dependency_overrides[get_db] = lambda: mock_session

    # Mock Redis: report that rate limit is exceeded
    mock_pipeline = MagicMock()
    mock_pipeline.execute = AsyncMock(return_value=[11, True])  # >10 = rate limited
    mock_redis = AsyncMock()
    mock_redis.pipeline = MagicMock(return_value=mock_pipeline)
    the_app.dependency_overrides[get_redis] = lambda: mock_redis

    async with AsyncClient(transport=ASGITransport(app=the_app), base_url="http://test") as c:
        resp = await c.get(
            f"/api/v1/sentinels/{uuid.uuid4()}/credentials/sync-full",
            headers=_operator_headers(),
        )
    assert resp.status_code == 429
    assert resp.json()["code"] == "FULL_SYNC_RATE_LIMIT"


@pytest.mark.asyncio
async def test_rotate_credential_requires_security_admin(app):
    resp = await app.post(
        f"/api/v1/sentinels/{uuid.uuid4()}/credentials/{uuid.uuid4()}/rotate",
        json={},
        headers=_operator_headers(),  # operator, not security-admin
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_rotate_credential_not_found(app):
    resp = await app.post(
        f"/api/v1/sentinels/{uuid.uuid4()}/credentials/{uuid.uuid4()}/rotate",
        json={},
        headers=_security_admin_headers(),
    )
    assert resp.status_code == 404
    assert resp.json()["code"] == "CREDENTIAL_NOT_FOUND"
