"""Unit tests for TASK-028: Verifiable Credential Issuance."""
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
from discovery.db.models.sentinels import Sentinel
from discovery.services import credential_issuer

SECRET = "test-secret"


@pytest.fixture
def settings() -> DiscoverySettings:
    return DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        env="dev",
        auth_mode="local_jwt",
        local_jwt_secret=SECRET,
        jwt_issuer_did="did:key:test-discovery",
    )


def _security_admin_headers() -> dict:
    token = issue_dev_token("admin", ["security-admin"], SECRET)
    return {"Authorization": f"Bearer {token}"}


def _viewer_headers() -> dict:
    token = issue_dev_token("viewer", ["viewer"], SECRET)
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
# Credential issuer service unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_issue_sentinel_identity_returns_jwt(settings):
    """Issued credential is a valid compact JWT."""
    sentinel = Sentinel(
        id=uuid.uuid4(),
        did="did:key:z6MkTest",
        role="producer",
        env="dev",
        service_id=uuid.uuid4(),
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )

    session = _mock_session()
    # Simulate DB returning the new credential on refresh
    from discovery.db.models.credentials import Credential

    fake_cred = Credential(
        id=uuid.uuid4(),
        credential_type="SentinelIdentityCredential",
        issuer_did="did:key:test-discovery",
        subject_did=sentinel.did,
        env="dev",
        jti=f"urn:uuid:{uuid.uuid4()}",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=90),
        status="active",
        is_latest=True,
    )
    session.refresh = AsyncMock(side_effect=lambda obj: setattr(obj, "id", fake_cred.id) or None)

    record, jwt_vc = await credential_issuer.issue_sentinel_identity(sentinel, session, settings)
    assert isinstance(jwt_vc, str)
    assert len(jwt_vc.split(".")) == 3


@pytest.mark.asyncio
async def test_issue_sentinel_identity_jwt_structure(settings):
    """Issued JWT-VC has required claims."""
    import jwt as pyjwt

    sentinel = Sentinel(
        id=uuid.uuid4(),
        did="did:key:z6MkHolder",
        role="consumer",
        env="dev",
        service_id=None,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )

    session = _mock_session()
    session.refresh = AsyncMock()

    _, jwt_vc = await credential_issuer.issue_sentinel_identity(sentinel, session, settings)
    decoded = pyjwt.decode(jwt_vc, key=SECRET, algorithms=["HS256"])

    assert decoded["iss"] == "did:key:test-discovery"
    assert decoded["sub"] == sentinel.did
    assert decoded["jti"].startswith("urn:uuid:")
    vc = decoded["vc"]
    assert "VerifiableCredential" in vc["type"]
    assert "SentinelIdentityCredential" in vc["type"]
    assert vc["credentialSubject"]["id"] == sentinel.did


@pytest.mark.asyncio
async def test_issue_access_grant_jwt_has_scope(settings):
    """AccessGrant JWT-VC contains granted scope."""
    import jwt as pyjwt

    sentinel = Sentinel(
        id=uuid.uuid4(),
        did="did:key:consumer",
        role="consumer",
        env="prod",
        service_id=None,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )

    session = _mock_session()
    session.refresh = AsyncMock()

    _, jwt_vc = await credential_issuer.issue_access_grant(
        consumer_sentinel=sentinel,
        producer_service_id="billing-api",
        env="prod",
        scope=["read:invoices", "submit:tax-return"],
        expires_in_days=30,
        session=session,
        settings=settings,
        granted_by="admin@example.gov",
    )
    decoded = pyjwt.decode(jwt_vc, key=SECRET, algorithms=["HS256"], options={"verify_aud": False})
    assert "AccessGrantCredential" in decoded["vc"]["type"]
    cs = decoded["vc"]["credentialSubject"]
    assert "read:invoices" in cs["scope"]


@pytest.mark.asyncio
async def test_ttl_clamped_to_maximum(settings):
    """Requesting 1000 days is clamped to the allowed maximum."""
    import jwt as pyjwt

    sentinel = Sentinel(
        id=uuid.uuid4(),
        did="did:key:clamptest",
        role="producer",
        env="dev",
        service_id=None,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )

    session = _mock_session()
    session.refresh = AsyncMock()

    # SentinelIdentityCredential max is 90 days; request 365 — should clamp
    _, jwt_vc = await credential_issuer.issue_sentinel_identity(
        sentinel, session, settings, expires_in_days=365
    )
    decoded = pyjwt.decode(jwt_vc, key=SECRET, algorithms=["HS256"])
    issued = decoded["iat"]
    exp = decoded["exp"]
    actual_days = (exp - issued) / 86400
    assert actual_days <= 90 + 1  # allow rounding


def test_clamp_days_sentinel_identity():
    from discovery.services.credential_issuer import _clamp_days

    assert _clamp_days(100, "SentinelIdentityCredential") == 90
    assert _clamp_days(60, "SentinelIdentityCredential") == 60


def test_clamp_days_access_grant():
    from discovery.services.credential_issuer import _clamp_days

    assert _clamp_days(400, "AccessGrantCredential") == 365
    assert _clamp_days(30, "AccessGrantCredential") == 30


# ---------------------------------------------------------------------------
# Credential API endpoint tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_issue_sentinel_identity_requires_security_admin(app):
    resp = await app.post(
        "/api/v1/credentials/sentinel-identity",
        json={"sentinel_id": str(uuid.uuid4())},
        headers=_viewer_headers(),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_issue_sentinel_identity_sentinel_not_found(app):
    resp = await app.post(
        "/api/v1/credentials/sentinel-identity",
        json={"sentinel_id": str(uuid.uuid4())},
        headers=_security_admin_headers(),
    )
    assert resp.status_code == 404
    assert resp.json()["code"] == "SENTINEL_NOT_FOUND"


@pytest.mark.asyncio
async def test_issue_access_grant_requires_security_admin(app):
    resp = await app.post(
        "/api/v1/credentials/access-grant",
        json={
            "consumer_sentinel_id": str(uuid.uuid4()),
            "producer_service_id": "billing-api",
            "env": "dev",
            "scope": ["read:data"],
            "expires_in_days": 30,
        },
        headers=_viewer_headers(),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_issue_access_grant_expires_in_days_validation(app):
    """expires_in_days must be between 1 and 365."""
    resp = await app.post(
        "/api/v1/credentials/access-grant",
        json={
            "consumer_sentinel_id": str(uuid.uuid4()),
            "producer_service_id": "billing-api",
            "env": "dev",
            "scope": ["read:data"],
            "expires_in_days": 0,  # invalid
        },
        headers=_security_admin_headers(),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_issue_service_binding_requires_security_admin(app):
    resp = await app.post(
        "/api/v1/credentials/service-binding",
        json={"sentinel_id": str(uuid.uuid4()), "service_id": "billing-api"},
        headers=_viewer_headers(),
    )
    assert resp.status_code == 403
