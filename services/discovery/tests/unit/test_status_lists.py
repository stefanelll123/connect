"""Unit tests for TASK-030: Bitstring Status List and Revocation."""
from __future__ import annotations

import base64
import gzip
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from discovery.app import create_app
from discovery.auth.local_jwt import issue_dev_token
from discovery.config import DiscoverySettings
from discovery.db.models.credentials import Credential
from discovery.db.models.status_lists import StatusList
from discovery.dependencies import get_db, get_redis

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
# Status list encoding unit tests
# ---------------------------------------------------------------------------

def test_encode_bitstring_gzip_base64url():
    from discovery.services.status_list_service import _encode_bitstring

    raw = bytes(16)  # all zeros
    encoded = _encode_bitstring(raw)
    # Verify it's valid base64url and decodes to gzip content
    decoded = base64.urlsafe_b64decode(encoded + "==")
    decompressed = gzip.decompress(decoded)
    assert decompressed == raw


def test_encode_bitstring_with_set_bit():
    from discovery.services.status_list_service import _encode_bitstring

    raw = bytearray(16)
    raw[2] |= 0b00000001  # set bit at index 16
    encoded = _encode_bitstring(bytes(raw))
    decoded = base64.urlsafe_b64decode(encoded + "==")
    decompressed = gzip.decompress(decoded)
    assert decompressed[2] & 0b00000001 == 1


def test_generate_status_list_jwt_valid(settings):
    from discovery.services.status_list_service import _generate_status_list_jwt
    import jwt as pyjwt

    sl = StatusList(
        id=uuid.uuid4(),
        status_list_id="dev-sentinel-identity-001",
        issuer_did="did:key:test-discovery",
        env="dev",
        credential_type="SentinelIdentityCredential",
        bitstring=bytes(16),
        top_index=0,
        max_size=131072,
        dirty=False,
        is_frozen=False,
        current_hash="",
        version=1,
        anchor_pending=False,
    )
    jwt_str = _generate_status_list_jwt(sl, settings)
    assert len(jwt_str.split(".")) == 3

    decoded = pyjwt.decode(jwt_str, key=SECRET, algorithms=["HS256"])
    assert decoded["iss"] == "did:key:test-discovery"
    vc = decoded["vc"]
    assert "BitstringStatusListCredential" in vc["type"]
    assert "encodedList" in vc["credentialSubject"]


# ---------------------------------------------------------------------------
# Status list repository unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_set_bit_modifies_bitstring():
    """Test bit manipulation logic directly."""
    bs = bytearray(16)
    index = 5
    byte_index = index // 8
    bit_offset = index % 8
    bs[byte_index] |= 1 << bit_offset
    assert bs[0] & (1 << 5) == (1 << 5)


@pytest.mark.asyncio
async def test_set_bit_then_get_bit():
    """Verify bit roundtrip using the repo functions (with mock session)."""
    from discovery.repositories.status_lists import get_bit

    sl = StatusList(
        id=uuid.uuid4(),
        status_list_id="test-list-001",
        issuer_did="did:key:test",
        env="dev",
        credential_type="SentinelIdentityCredential",
        bitstring=bytes(16),
        top_index=0,
        max_size=131072,
        dirty=False,
        is_frozen=False,
        current_hash="",
        version=1,
        anchor_pending=False,
    )

    # Set bit 10
    bs = bytearray(sl.bitstring)
    bs[10 // 8] |= 1 << (10 % 8)
    sl.bitstring = bytes(bs)

    session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = sl
    session.execute.return_value = mock_result

    value = await get_bit(session, "test-list-001", 10)
    assert value == 1

    value_clear = await get_bit(session, "test-list-001", 9)
    assert value_clear == 0


# ---------------------------------------------------------------------------
# Status list publisher unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_publish_sweep_no_dirty(settings):
    from discovery.tasks.status_list_publisher import run_publish_sweep

    sl_clean = StatusList(
        id=uuid.uuid4(),
        status_list_id="dev-001",
        issuer_did="did:key:test",
        env="dev",
        credential_type="SentinelIdentityCredential",
        bitstring=bytes(16),
        top_index=0,
        max_size=131072,
        dirty=False,
        is_frozen=False,
        current_hash="",
        version=1,
        anchor_pending=False,
    )
    session = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [sl_clean]
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    session.execute.return_value = mock_result
    session.flush = AsyncMock()

    count = await run_publish_sweep(session, settings)
    assert count == 0  # nothing was dirty


@pytest.mark.asyncio
async def test_publish_sweep_dirty_list(settings):
    from discovery.tasks.status_list_publisher import run_publish_sweep
    from discovery.repositories.status_lists import StatusListRepository

    sl_dirty = StatusList(
        id=uuid.uuid4(),
        status_list_id="dev-002",
        issuer_did="did:key:test",
        env="dev",
        credential_type="SentinelIdentityCredential",
        bitstring=bytes(16),
        top_index=5,
        max_size=131072,
        dirty=True,
        is_frozen=False,
        current_hash="",
        version=1,
        anchor_pending=False,
    )
    session = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [sl_dirty]
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_result.scalar_one_or_none.return_value = sl_dirty
    session.execute.return_value = mock_result
    session.flush = AsyncMock()

    count = await run_publish_sweep(session, settings)
    assert count == 1
    assert sl_dirty.dirty is False  # publisher cleared the dirty flag
    import hashlib
    assert sl_dirty.current_hash == hashlib.sha256(bytes(16)).hexdigest()


# ---------------------------------------------------------------------------
# Revocation endpoint tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_revoke_requires_security_admin(app):
    resp = await app.post(
        f"/api/v1/credentials/{uuid.uuid4()}/revoke",
        json={"reason": "compromised", "severity": "critical", "revoked_by": "admin"},
        headers=_viewer_headers(),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_revoke_credential_not_found(app):
    resp = await app.post(
        f"/api/v1/credentials/{uuid.uuid4()}/revoke",
        json={"reason": "test", "severity": "low", "revoked_by": "admin"},
        headers=_security_admin_headers(),
    )
    assert resp.status_code == 404
    assert resp.json()["code"] == "CREDENTIAL_NOT_FOUND"


@pytest.mark.asyncio
async def test_revoke_invalid_severity_returns_422(app):
    resp = await app.post(
        f"/api/v1/credentials/{uuid.uuid4()}/revoke",
        json={"reason": "test", "severity": "ultra-severe", "revoked_by": "admin"},
        headers=_security_admin_headers(),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_revoke_idempotent_already_revoked(settings):
    """Revoking an already-revoked credential returns 200 with already_revoked=true."""
    now = datetime.now(timezone.utc)
    existing_cred = Credential(
        id=uuid.uuid4(),
        credential_type="SentinelIdentityCredential",
        issuer_did="did:key:discovery",
        subject_did="did:key:subject",
        env="dev",
        jti=f"urn:uuid:{uuid.uuid4()}",
        issued_at=now,
        expires_at=now,
        status="revoked",  # already revoked
        is_latest=False,
    )
    the_app = create_app(settings=settings)
    mock_session = _mock_session()
    mock_session.execute.return_value.scalar_one_or_none.return_value = existing_cred
    the_app.dependency_overrides[get_db] = lambda: mock_session
    the_app.dependency_overrides[get_redis] = lambda: AsyncMock()

    async with AsyncClient(transport=ASGITransport(app=the_app), base_url="http://test") as c:
        resp = await c.post(
            f"/api/v1/credentials/{existing_cred.id}/revoke",
            json={"reason": "duplicate", "severity": "low", "revoked_by": "admin"},
            headers=_security_admin_headers(),
        )
    assert resp.status_code == 200
    assert resp.json()["already_revoked"] is True


@pytest.mark.asyncio
async def test_revoke_sets_status_to_revoked(settings):
    """Revoking an active credential sets status=revoked."""
    now = datetime.now(timezone.utc)
    existing_cred = Credential(
        id=uuid.uuid4(),
        credential_type="SentinelIdentityCredential",
        issuer_did="did:key:discovery",
        subject_did="did:key:subject",
        env="dev",
        jti=f"urn:uuid:{uuid.uuid4()}",
        issued_at=now,
        expires_at=now,
        status="active",
        is_latest=True,
        status_list_id=None,  # no status list — skip bit set
        status_list_index=None,
    )
    the_app = create_app(settings=settings)
    mock_session = _mock_session()
    mock_session.execute.return_value.scalar_one_or_none.return_value = existing_cred
    the_app.dependency_overrides[get_db] = lambda: mock_session
    the_app.dependency_overrides[get_redis] = lambda: AsyncMock()

    async with AsyncClient(transport=ASGITransport(app=the_app), base_url="http://test") as c:
        resp = await c.post(
            f"/api/v1/credentials/{existing_cred.id}/revoke",
            json={"reason": "compromised", "severity": "critical", "revoked_by": "admin"},
            headers=_security_admin_headers(),
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["already_revoked"] is False
    assert data["credential_id"] == str(existing_cred.id)


# ---------------------------------------------------------------------------
# Public status list endpoint tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_status_list_not_found(app):
    resp = await app.get("/status/nonexistent-list-id")
    assert resp.status_code == 404
    assert resp.json()["code"] == "STATUS_LIST_NOT_FOUND"


@pytest.mark.asyncio
async def test_get_status_list_returns_jwt(settings):
    """GET /status/{id} returns application/jwt with ETag."""
    sl = StatusList(
        id=uuid.uuid4(),
        status_list_id="dev-sentinel-identity-001",
        issuer_did="did:key:test-discovery",
        env="dev",
        credential_type="SentinelIdentityCredential",
        bitstring=bytes(16),
        top_index=0,
        max_size=131072,
        dirty=False,
        is_frozen=False,
        current_hash="",
        version=1,
        anchor_pending=False,
    )
    the_app = create_app(settings=settings)
    mock_session = _mock_session()
    mock_session.execute.return_value.scalar_one_or_none.return_value = sl
    the_app.dependency_overrides[get_db] = lambda: mock_session
    the_app.dependency_overrides[get_redis] = lambda: AsyncMock()

    async with AsyncClient(transport=ASGITransport(app=the_app), base_url="http://test") as c:
        resp = await c.get("/status/dev-sentinel-identity-001")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/jwt"
    assert "ETag" in resp.headers
    assert "Cache-Control" in resp.headers


@pytest.mark.asyncio
async def test_get_status_list_304_on_etag_match(settings):
    """GET /status/{id} returns 304 when ETag matches."""
    import hashlib

    import jwt as pyjwt
    from discovery.services.status_list_service import _generate_status_list_jwt

    sl = StatusList(
        id=uuid.uuid4(),
        status_list_id="dev-sentinel-identity-001",
        issuer_did="did:key:test-discovery",
        env="dev",
        credential_type="SentinelIdentityCredential",
        bitstring=bytes(16),
        top_index=0,
        max_size=131072,
        dirty=False,
        is_frozen=False,
        current_hash="",
        version=1,
        anchor_pending=False,
    )
    settings_obj = settings
    jwt_str = _generate_status_list_jwt(sl, settings_obj)
    etag = f'"{hashlib.sha256(jwt_str.encode()).hexdigest()[:16]}"'

    the_app = create_app(settings=settings_obj)
    mock_session = _mock_session()
    mock_session.execute.return_value.scalar_one_or_none.return_value = sl
    the_app.dependency_overrides[get_db] = lambda: mock_session
    the_app.dependency_overrides[get_redis] = lambda: AsyncMock()

    async with AsyncClient(transport=ASGITransport(app=the_app), base_url="http://test") as c:
        resp = await c.get(
            "/status/dev-sentinel-identity-001",
            headers={"if-none-match": etag},
        )
    assert resp.status_code == 304
