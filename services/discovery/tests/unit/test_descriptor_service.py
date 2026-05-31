"""Unit tests for TASK-032: Service Discovery API and Signed Service Descriptors.

Tests descriptor validation, publish, resolve, and expiry without a real DB.
"""
from __future__ import annotations

import base64
import json
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
from discovery.services.descriptor_service import (
    DescriptorValidationError,
    _compute_descriptor_hash,
    _extract_jws_payload,
    validate_and_publish,
    resolve_descriptor,
    invalidate,
)

SECRET = "test-descriptor-secret"


@pytest.fixture
def settings() -> DiscoverySettings:
    return DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        env="dev",
        auth_mode="local_jwt",
        local_jwt_secret=SECRET,
    )


def _operator_headers() -> dict:
    token = issue_dev_token("operator", ["operator"], SECRET)
    return {"Authorization": f"Bearer {token}"}


def _viewer_headers() -> dict:
    token = issue_dev_token("viewer", ["viewer"], SECRET)
    return {"Authorization": f"Bearer {token}"}


def _mock_session():
    session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value = MagicMock(all=MagicMock(return_value=[]))
    mock_result.scalar_one_or_none.return_value = None
    mock_result.scalar_one.return_value = None
    session.execute.return_value = mock_result
    session.flush = AsyncMock()
    session.add = MagicMock()
    return session


def _make_jws(payload: dict) -> str:
    """Create a fake compact JWS with the given payload (unsigned, for testing)."""
    header = base64.urlsafe_b64encode(b'{"alg":"EdDSA"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(b"fakesignature").rstrip(b"=").decode()
    return f"{header}.{body}.{sig}"


def _valid_payload(service_id="svc-1", env="dev", ttl=300) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "service_id": service_id,
        "env": env,
        "producer_sentinel_did": "did:key:z6MkTest",
        "endpoints": [{"url": "https://service.example.com", "protocol": "https"}],
        "valid_from": now.isoformat(),
        "valid_until": (now + timedelta(seconds=ttl)).isoformat(),
    }


# ---------------------------------------------------------------------------
# _extract_jws_payload tests
# ---------------------------------------------------------------------------

def test_extract_jws_payload_valid():
    """Extracting payload from a well-formed JWS returns correct dict."""
    payload = {"service_id": "test", "env": "dev"}
    jws = _make_jws(payload)
    result = _extract_jws_payload(jws)
    assert result["service_id"] == "test"
    assert result["env"] == "dev"


def test_extract_jws_payload_invalid_format():
    """JWS with wrong number of parts raises DescriptorValidationError."""
    with pytest.raises(DescriptorValidationError) as exc_info:
        _extract_jws_payload("only.two")
    assert exc_info.value.code == "INVALID_DESCRIPTOR_SIGNATURE"


def test_extract_jws_payload_non_json():
    """JWS with non-JSON payload raises DescriptorValidationError."""
    junk = base64.urlsafe_b64encode(b"notjson").rstrip(b"=").decode()
    with pytest.raises(DescriptorValidationError):
        _extract_jws_payload(f"header.{junk}.sig")


# ---------------------------------------------------------------------------
# _compute_descriptor_hash tests
# ---------------------------------------------------------------------------

def test_descriptor_hash_deterministic():
    """Same payload always yields same hash."""
    payload = {"env": "dev", "service_id": "svc-1", "x": 42}
    h1 = _compute_descriptor_hash(payload)
    h2 = _compute_descriptor_hash(payload)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_descriptor_hash_key_order_independent():
    """Hash is independent of key order (canonical JSON)."""
    p1 = {"a": 1, "b": 2}
    p2 = {"b": 2, "a": 1}
    assert _compute_descriptor_hash(p1) == _compute_descriptor_hash(p2)


# ---------------------------------------------------------------------------
# validate_and_publish service tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_validate_service_id_mismatch_raises():
    """service_id in descriptor must match path param."""
    session = _mock_session()
    payload = _valid_payload(service_id="wrong-svc")
    jws = _make_jws(payload)

    with pytest.raises(DescriptorValidationError) as exc_info:
        await validate_and_publish(session, service_id="correct-svc", env="dev", signed_descriptor_jws=jws)
    assert exc_info.value.code == "DESCRIPTOR_SERVICE_MISMATCH"


@pytest.mark.asyncio
async def test_validate_env_mismatch_raises():
    """env in descriptor must match query param."""
    session = _mock_session()
    payload = _valid_payload(env="prod")
    jws = _make_jws(payload)

    with pytest.raises(DescriptorValidationError) as exc_info:
        await validate_and_publish(session, service_id="svc-1", env="dev", signed_descriptor_jws=jws)
    assert exc_info.value.code == "DESCRIPTOR_ENV_MISMATCH"


@pytest.mark.asyncio
async def test_validate_ttl_exceeds_max_raises():
    """Descriptor with TTL > 600s is rejected."""
    session = _mock_session()
    payload = _valid_payload(ttl=700)
    jws = _make_jws(payload)

    with pytest.raises(DescriptorValidationError) as exc_info:
        await validate_and_publish(session, service_id="svc-1", env="dev", signed_descriptor_jws=jws)
    assert exc_info.value.code == "TTL_TOO_LONG"


@pytest.mark.asyncio
async def test_validate_empty_endpoints_raises():
    """Descriptor with no endpoints is rejected."""
    session = _mock_session()
    payload = _valid_payload()
    payload["endpoints"] = []
    jws = _make_jws(payload)

    with pytest.raises(DescriptorValidationError) as exc_info:
        await validate_and_publish(session, service_id="svc-1", env="dev", signed_descriptor_jws=jws)
    assert exc_info.value.code == "EMPTY_ENDPOINTS"


@pytest.mark.asyncio
async def test_validate_already_expired_raises():
    """Descriptor with valid_until in the past is rejected."""
    session = _mock_session()
    now = datetime.now(timezone.utc)
    payload = _valid_payload()
    payload["valid_from"] = (now - timedelta(seconds=700)).isoformat()
    payload["valid_until"] = (now - timedelta(seconds=100)).isoformat()
    jws = _make_jws(payload)

    with pytest.raises(DescriptorValidationError) as exc_info:
        await validate_and_publish(session, service_id="svc-1", env="dev", signed_descriptor_jws=jws)
    assert exc_info.value.code in {"DESCRIPTOR_ALREADY_EXPIRED", "TTL_TOO_LONG"}


# ---------------------------------------------------------------------------
# resolve_descriptor tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolve_returns_404_when_not_found():
    """resolve_descriptor raises DescriptorValidationError(404) if no record."""
    session = _mock_session()
    session.execute.return_value.scalar_one_or_none.return_value = None

    with pytest.raises(DescriptorValidationError) as exc_info:
        await resolve_descriptor(session, service_id="unknown", env="dev")
    assert exc_info.value.status == 404
    assert exc_info.value.code == "SERVICE_NOT_RESOLVABLE"


@pytest.mark.asyncio
async def test_resolve_returns_404_when_expired():
    """resolve_descriptor raises DescriptorValidationError(404) if descriptor expired."""
    session = _mock_session()
    from discovery.db.models.service_descriptors import ServiceDescriptor

    fake_sd = MagicMock(spec=ServiceDescriptor)
    fake_sd.id = uuid.uuid4()
    fake_sd.service_id = "svc-1"
    fake_sd.env = "dev"
    fake_sd.is_active = True
    fake_sd.valid_until = datetime.now(timezone.utc) - timedelta(seconds=60)
    fake_sd.signed_descriptor_jws = "h.p.s"
    session.execute.return_value.scalar_one_or_none.return_value = fake_sd

    with pytest.raises(DescriptorValidationError) as exc_info:
        await resolve_descriptor(session, service_id="svc-1", env="dev")
    assert exc_info.value.code == "DESCRIPTOR_EXPIRED"


# ---------------------------------------------------------------------------
# HTTP endpoint tests
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def descriptor_client(settings):
    app = create_app(settings=settings)
    mock_session = _mock_session()

    async def _override_db():
        yield mock_session

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_redis] = lambda: AsyncMock()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_resolve_endpoint_unauthorized_viewer(descriptor_client):
    """GET /registry/resolve responds even for viewers (viewer role is allowed)."""
    # With no record in DB, expect 404 with code SERVICE_NOT_RESOLVABLE
    resp = await descriptor_client.get(
        "/api/v1/registry/resolve?service_id=test&env=dev",
        headers=_viewer_headers(),
    )
    # 404 expected (no descriptor), not 401 or 403
    assert resp.status_code == 404
    assert resp.json()["code"] == "SERVICE_NOT_RESOLVABLE"


@pytest.mark.asyncio
async def test_resolve_endpoint_no_auth_returns_401(descriptor_client):
    """GET /registry/resolve without token returns 401."""
    resp = await descriptor_client.get("/api/v1/registry/resolve?service_id=test&env=dev")
    assert resp.status_code == 401
