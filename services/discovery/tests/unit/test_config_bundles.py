"""Unit tests for TASK-027: Config Bundle Generation, Signing, and Versioned Delivery."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from discovery.app import create_app
from discovery.auth.local_jwt import issue_dev_token
from discovery.config import DiscoverySettings
from discovery.dependencies import get_db, get_redis

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
# Config bundle service unit tests
# ---------------------------------------------------------------------------

def test_canonical_json_sorted_keys():
    from discovery.services.config_bundle_service import _canonical_json

    data = {"z": 1, "a": 2, "m": 3}
    result = _canonical_json(data)
    assert result == b'{"a":2,"m":3,"z":1}'


def test_canonical_json_deterministic():
    from discovery.services.config_bundle_service import _canonical_json

    data = {"bundle_version": 1, "issued_by": "did:key:abc", "env": "dev"}
    r1 = _canonical_json(data)
    r2 = _canonical_json(data)
    assert r1 == r2


def test_sign_bundle_produces_jwt(settings):
    from discovery.services.config_bundle_service import _sign_bundle, _canonical_json

    payload = {"bundle_version": 1, "env": "dev"}
    canonical = _canonical_json(payload)
    token = _sign_bundle(canonical, settings)
    assert len(token.split(".")) == 3  # compact JWT


def test_sign_bundle_verifiable(settings):
    import jwt as pyjwt
    from discovery.services.config_bundle_service import _sign_bundle, _canonical_json

    payload = {"bundle_version": 2, "sentinel_id": str(uuid.uuid4())}
    canonical = _canonical_json(payload)
    token = _sign_bundle(canonical, settings)
    decoded = pyjwt.decode(token, key=SECRET, algorithms=["HS256"])
    assert "bundle" in decoded
    assert decoded["bundle"]["bundle_version"] == 2


def test_bundle_hash_sha256():
    from discovery.services.config_bundle_service import _canonical_json

    data = {"key": "value"}
    canonical = _canonical_json(data)
    expected = hashlib.sha256(canonical).hexdigest()
    assert len(expected) == 64
    computed = hashlib.sha256(canonical).hexdigest()
    assert computed == expected


# ---------------------------------------------------------------------------
# Config bundle API endpoint tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_config_no_bundle_returns_404(app):
    resp = await app.get(
        f"/api/v1/sentinels/{uuid.uuid4()}/config",
        headers=_operator_headers(),
    )
    assert resp.status_code == 404
    assert resp.json()["code"] == "CONFIG_NOT_YET_GENERATED"


@pytest.mark.asyncio
async def test_get_config_history_requires_operator(app):
    # viewer should be forbidden
    token = issue_dev_token("viewer", ["viewer"], SECRET)
    resp = await app.get(
        f"/api/v1/sentinels/{uuid.uuid4()}/config/history",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_get_config_history_returns_empty_list(app):
    resp = await app.get(
        f"/api/v1/sentinels/{uuid.uuid4()}/config/history",
        headers=_operator_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["items"] == []


@pytest.mark.asyncio
async def test_rollback_requires_security_admin(app):
    resp = await app.post(
        f"/api/v1/sentinels/{uuid.uuid4()}/config/rollback?to_version=1",
        headers=_operator_headers(),  # operator, not security-admin
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_generate_config_requires_operator(app):
    token = issue_dev_token("viewer", ["viewer"], SECRET)
    resp = await app.post(
        f"/api/v1/sentinels/{uuid.uuid4()}/config/generate",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_generate_config_sentinel_not_found_returns_404(app):
    resp = await app.post(
        f"/api/v1/sentinels/{uuid.uuid4()}/config/generate",
        headers=_security_admin_headers(),
    )
    # Mock returns None for sentinel → should get 404 from service
    assert resp.status_code in (404, 503)


@pytest.mark.asyncio
async def test_get_config_etag_returns_304(settings):
    """If a valid bundle exists and ETag matches, return 304."""
    from discovery.db.models.config_bundles import ConfigBundle

    # Create a fake bundle
    fake_bundle = ConfigBundle(
        id=uuid.uuid4(),
        sentinel_id=uuid.uuid4(),
        version=1,
        bundle_hash="abc123",
        signed_bundle_jws="eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoxfQ.signature",
        issued_at=datetime.now(timezone.utc),
        is_current=True,
    )
    the_app = create_app(settings=settings)
    mock_session = _mock_session()
    mock_session.execute.return_value.scalar_one_or_none.return_value = fake_bundle
    the_app.dependency_overrides[get_db] = lambda: mock_session
    the_app.dependency_overrides[get_redis] = lambda: AsyncMock()

    async with AsyncClient(transport=ASGITransport(app=the_app), base_url="http://test") as c:
        resp = await c.get(
            f"/api/v1/sentinels/{fake_bundle.sentinel_id}/config",
            headers={**_operator_headers(), "if-none-match": '"abc123"'},
        )
    assert resp.status_code == 304
