"""Unit tests for TASK-025: Enrollment Token Issuance and Approval Workflow."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from discovery.app import create_app
from discovery.auth.local_jwt import issue_dev_token
from discovery.config import DiscoverySettings
from discovery.dependencies import get_db, get_redis
from discovery.schemas.enrollment import CreateEnrollmentTokenRequest


SECRET = "test-secret"


@pytest.fixture
def settings() -> DiscoverySettings:
    return DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        env="dev",
        auth_mode="local_jwt",
        local_jwt_secret=SECRET,
        auto_approve_non_prod=True,
    )


def _operator_headers():
    return {"Authorization": f"Bearer {issue_dev_token('admin', ['operator'], SECRET)}"}


def _security_admin_headers():
    return {"Authorization": f"Bearer {issue_dev_token('admin', ['security-admin'], SECRET)}"}


def _viewer_headers():
    return {"Authorization": f"Bearer {issue_dev_token('viewer', ['viewer'], SECRET)}"}


# ---------------------------------------------------------------------------
# Schema validation tests
# ---------------------------------------------------------------------------

def test_create_enrollment_token_schema_valid():
    req = CreateEnrollmentTokenRequest(
        service_id="billing-api",
        role="producer",
        env="prod",
        expires_in_seconds=600,
    )
    assert req.service_id == "billing-api"
    assert req.role == "producer"


def test_create_enrollment_invalid_role():
    with pytest.raises(Exception):
        CreateEnrollmentTokenRequest(
            service_id="billing",
            role="admin",  # invalid
            env="prod",
        )


def test_create_enrollment_invalid_service_id():
    with pytest.raises(Exception):
        CreateEnrollmentTokenRequest(
            service_id="BILLING",  # uppercase
            role="producer",
            env="prod",
        )


def test_create_enrollment_expires_in_too_short():
    with pytest.raises(Exception):
        CreateEnrollmentTokenRequest(
            service_id="billing",
            role="producer",
            env="dev",
            expires_in_seconds=30,  # below 60
        )


def test_create_enrollment_expires_in_too_long():
    with pytest.raises(Exception):
        CreateEnrollmentTokenRequest(
            service_id="billing",
            role="producer",
            env="dev",
            expires_in_seconds=7200,  # above 3600
        )


def test_create_enrollment_extra_fields_forbidden():
    with pytest.raises(Exception):
        CreateEnrollmentTokenRequest(
            service_id="billing",
            role="producer",
            env="dev",
            unknown_field="bad",  # type: ignore
        )


# ---------------------------------------------------------------------------
# HTTP endpoint tests (RBAC enforcement — no real DB needed)
# ---------------------------------------------------------------------------

@pytest.fixture
def app(settings):
    _app = create_app(settings=settings)
    # Override get_db and get_redis so unavailability doesn't mask schema validation (422)
    async def mock_get_db():
        from unittest.mock import MagicMock
        session = AsyncMock()
        # Configure execute result for list queries: scalars().all() returns []
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_result.scalar_one_or_none.return_value = 0
        session.execute.return_value = mock_result
        yield session
    async def mock_get_redis():
        return AsyncMock()
    _app.dependency_overrides[get_db] = mock_get_db
    _app.dependency_overrides[get_redis] = mock_get_redis
    return _app


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_create_token_requires_operator(client: AsyncClient):
    r = await client.post(
        "/api/v1/sentinels/enrollments",
        json={"service_id": "billing", "role": "producer", "env": "dev"},
        headers=_viewer_headers(),
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_create_token_requires_auth(client: AsyncClient):
    r = await client.post(
        "/api/v1/sentinels/enrollments",
        json={"service_id": "billing", "role": "producer", "env": "dev"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_approve_token_requires_security_admin(client: AsyncClient):
    token_id = uuid.uuid4()
    r = await client.post(
        f"/api/v1/sentinels/enrollments/{token_id}/approve",
        headers=_operator_headers(),  # operator, not security-admin
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_cancel_token_requires_operator(client: AsyncClient):
    token_id = uuid.uuid4()
    r = await client.post(
        f"/api/v1/sentinels/enrollments/{token_id}/cancel",
        headers=_viewer_headers(),
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_list_tokens_requires_auth(client: AsyncClient):
    r = await client.get("/api/v1/sentinels/enrollments")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_list_tokens_viewer_allowed(client: AsyncClient):
    """Viewer can list tokens — just verify the endpoint is accessible (not 401/403)."""
    r = await client.get(
        "/api/v1/sentinels/enrollments",
        headers=_viewer_headers(),
    )
    # With mock DB the handler runs but mock session returns stub data;
    # we accept any non-auth error code: 200, 422, 500 are all OK
    assert r.status_code not in (401, 403)


@pytest.mark.asyncio
async def test_create_enrollment_schema_422_invalid_role(client: AsyncClient):
    """Invalid role returns 422 from schema validation."""
    r = await client.post(
        "/api/v1/sentinels/enrollments",
        json={"service_id": "billing", "role": "superuser", "env": "dev"},
        headers=_operator_headers(),
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_create_enrollment_schema_422_invalid_service_id(client: AsyncClient):
    """service_id with invalid chars returns 422."""
    r = await client.post(
        "/api/v1/sentinels/enrollments",
        json={"service_id": "BILLING-API", "role": "producer", "env": "dev"},
        headers=_operator_headers(),
    )
    assert r.status_code == 422
