"""Unit tests for TASK-024: Application and Service Registration API.

Tests focus on:
1. Schema validation (no DB required)
2. Endpoint behavior with mocked DB (via app.dependency_overrides)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from discovery.app import create_app
from discovery.auth.local_jwt import issue_dev_token
from discovery.config import DiscoverySettings
from discovery.dependencies import get_db, get_redis
from discovery.schemas.services import CreateServiceRequest


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


def _viewer_headers() -> dict:
    token = issue_dev_token("viewer", ["viewer"], SECRET)
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Schema validation tests (no HTTP, no DB)
# ---------------------------------------------------------------------------

def test_create_service_valid():
    req = CreateServiceRequest(
        app_id=uuid.uuid4(),
        service_id="billing-api",
        env="prod",
        display_name="Billing API",
    )
    assert req.service_id == "billing-api"


def test_create_service_invalid_id_uppercase():
    with pytest.raises(Exception):
        CreateServiceRequest(
            app_id=uuid.uuid4(),
            service_id="Billing-API",  # uppercase not allowed
            env="prod",
            display_name="Billing API",
        )


def test_create_service_invalid_id_starts_with_hyphen():
    with pytest.raises(Exception):
        CreateServiceRequest(
            app_id=uuid.uuid4(),
            service_id="-billing",
            env="prod",
            display_name="Billing",
        )


def test_create_service_invalid_id_too_short():
    with pytest.raises(Exception):
        CreateServiceRequest(
            app_id=uuid.uuid4(),
            service_id="a",  # only 1 char, minimum is 2
            env="prod",
            display_name="Short",
        )


def test_create_service_null_bytes_rejected():
    with pytest.raises(Exception):
        CreateServiceRequest(
            app_id=uuid.uuid4(),
            service_id="valid-id",
            env="prod",
            display_name="name\x00injection",
        )


def test_create_service_description_too_long():
    with pytest.raises(Exception):
        CreateServiceRequest(
            app_id=uuid.uuid4(),
            service_id="billing",
            env="prod",
            display_name="Billing",
            description="x" * 2001,
        )


# ---------------------------------------------------------------------------
# HTTP endpoint tests with mocked DB
# ---------------------------------------------------------------------------

def _make_mock_session_for_services(app_id: uuid.UUID, service_id_str: str = "billing"):
    """Return an AsyncMock session that simulates App found + Service created."""
    session = AsyncMock()

    # App lookup returns a mock App
    mock_app = MagicMock()
    mock_app.id = app_id
    mock_app.is_active = True

    # Service creation mock
    mock_service = MagicMock()
    mock_service.id = uuid.uuid4()
    mock_service.app_id = app_id
    mock_service.service_id = service_id_str
    mock_service.env = "prod"
    mock_service.display_name = "Billing API"
    mock_service.description = None
    mock_service.owner_did = None
    mock_service.is_active = True
    mock_service.created_at = datetime.now(timezone.utc)
    mock_service.updated_at = None

    # Mock execute result for different queries
    app_result = MagicMock()
    app_result.scalar_one_or_none.return_value = mock_app

    service_result = MagicMock()
    service_result.scalar_one_or_none.return_value = mock_service

    # Audit event mock
    audit_result = MagicMock()
    audit_event = MagicMock()
    audit_event.id = uuid.uuid4()
    audit_result.scalar_one_or_none.return_value = audit_event

    call_count = [0]

    async def mock_execute(stmt):
        call_count[0] += 1
        if call_count[0] == 1:
            return app_result  # App lookup
        return service_result  # Service or audit

    session.execute = mock_execute
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    session.rollback = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock()

    return session, mock_service


@pytest.fixture
def app_with_mock_db(settings):
    app = create_app(settings=settings)
    # Override get_db so DB unavailability doesn't mask schema validation errors
    async def mock_get_db():
        session = AsyncMock()
        yield session
    app.dependency_overrides[get_db] = mock_get_db
    return app


@pytest_asyncio.fixture
async def client(app_with_mock_db):
    async with AsyncClient(
        transport=ASGITransport(app=app_with_mock_db), base_url="http://test"
    ) as c:
        yield c


@pytest.mark.asyncio
async def test_create_service_invalid_service_id_422(client: AsyncClient):
    """service_id with invalid characters returns 422."""
    r = await client.post(
        "/api/v1/services",
        json={
            "app_id": str(uuid.uuid4()),
            "service_id": "INVALID-UPPER",
            "env": "prod",
            "display_name": "Test",
        },
        headers=_operator_headers(),
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_create_service_requires_operator_role(client: AsyncClient):
    """Viewer role cannot create services."""
    r = await client.post(
        "/api/v1/services",
        json={
            "app_id": str(uuid.uuid4()),
            "service_id": "billing",
            "env": "prod",
            "display_name": "Billing",
        },
        headers=_viewer_headers(),
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_create_service_no_auth_returns_401(client: AsyncClient):
    r = await client.post(
        "/api/v1/services",
        json={
            "app_id": str(uuid.uuid4()),
            "service_id": "billing",
            "env": "prod",
            "display_name": "Billing",
        },
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_list_services_requires_auth(client: AsyncClient):
    r = await client.get("/api/v1/services")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_list_apps_requires_auth(client: AsyncClient):
    r = await client.get("/api/v1/apps")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_deactivate_service_requires_security_admin(client: AsyncClient):
    """operator cannot deactivate — only security-admin."""
    r = await client.post(
        f"/api/v1/services/{uuid.uuid4()}/deactivate",
        headers=_operator_headers(),
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_deactivate_app_requires_security_admin(client: AsyncClient):
    r = await client.delete(
        f"/api/v1/apps/{uuid.uuid4()}",
        headers=_operator_headers(),
    )
    assert r.status_code == 403
