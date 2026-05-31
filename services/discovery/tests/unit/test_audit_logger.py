"""Unit tests for TASK-034: Audit Logging with Hash Chain Integrity and Export API.

Tests AuditLogger hash chain, sanitize_summary, AuditAction enum,
audit_checkpoint task, and audit router endpoints.
"""
from __future__ import annotations

import hashlib
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
from discovery.services.audit_logger import (
    AuditAction,
    AuditLogger,
    sanitize_summary,
    _compute_event_hash,
    _canonical_summary,
)

SECRET = "test-audit-secret"


@pytest.fixture
def settings() -> DiscoverySettings:
    return DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        env="dev",
        auth_mode="local_jwt",
        local_jwt_secret=SECRET,
    )


def _admin_headers() -> dict:
    token = issue_dev_token("admin", ["security-admin"], SECRET)
    return {"Authorization": f"Bearer {token}"}


def _operator_headers() -> dict:
    token = issue_dev_token("op", ["operator"], SECRET)
    return {"Authorization": f"Bearer {token}"}


def _mock_session():
    session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value = MagicMock(all=MagicMock(return_value=[]))
    mock_result.scalar_one_or_none.return_value = None
    session.execute.return_value = mock_result
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock()
    return session


# ---------------------------------------------------------------------------
# AuditAction enum tests
# ---------------------------------------------------------------------------

def test_audit_action_values_are_strings():
    """All AuditAction values are non-empty uppercase strings."""
    for action in AuditAction:
        assert isinstance(action.value, str)
        assert action.value == action.value.upper()
        assert len(action.value) > 0


def test_audit_action_includes_sentinel_events():
    """Key sentinel lifecycle actions are defined."""
    assert AuditAction.SENTINEL_ONBOARDED.value == "SENTINEL_ONBOARDED"
    assert AuditAction.SENTINEL_DECOMMISSIONED.value == "SENTINEL_DECOMMISSIONED"
    assert AuditAction.SENTINEL_REJOINED.value == "SENTINEL_REJOINED"


def test_audit_action_includes_credential_events():
    """Key credential actions are defined."""
    assert AuditAction.ISSUE_CREDENTIAL.value == "ISSUE_CREDENTIAL"
    assert AuditAction.REVOKE_CREDENTIAL.value == "REVOKE_CREDENTIAL"


# ---------------------------------------------------------------------------
# sanitize_summary tests
# ---------------------------------------------------------------------------

def test_sanitize_removes_token_key():
    """Keys containing 'token' are redacted."""
    result = sanitize_summary({"access_token": "super-secret", "name": "value"})
    assert result["access_token"] == "<REDACTED>"
    assert result["name"] == "value"


def test_sanitize_removes_password_key():
    """Keys containing 'password' are redacted."""
    result = sanitize_summary({"password": "hunter2", "ok": "yes"})
    assert result["password"] == "<REDACTED>"
    assert result["ok"] == "yes"


def test_sanitize_removes_jwt_key():
    """Keys containing 'jwt' are redacted."""
    result = sanitize_summary({"jwt_payload": "abc.def.ghi"})
    assert result["jwt_payload"] == "<REDACTED>"


def test_sanitize_truncates_long_values():
    """Values longer than 1000 chars are truncated."""
    long_val = "x" * 1500
    result = sanitize_summary({"data": long_val})
    assert len(result["data"]) < 1500
    assert "truncated" in result["data"]


def test_sanitize_recurses_into_nested_dicts():
    """sanitize_summary applies recursively to nested dicts."""
    result = sanitize_summary({"outer": {"inner_secret": "hide-me"}})
    assert result["outer"]["inner_secret"] == "<REDACTED>"


def test_sanitize_preserves_non_sensitive_data():
    """Non-sensitive keys are preserved unchanged."""
    data = {"service_id": "svc-1", "env": "dev", "count": 42}
    result = sanitize_summary(data)
    assert result == data


# ---------------------------------------------------------------------------
# _compute_event_hash tests
# ---------------------------------------------------------------------------

def test_event_hash_is_deterministic():
    """Same inputs always produce the same hash."""
    ts = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    h1 = _compute_event_hash("eid", ts, "actor", "ACTION", "target", "summary", "prev")
    h2 = _compute_event_hash("eid", ts, "actor", "ACTION", "target", "summary", "prev")
    assert h1 == h2


def test_event_hash_changes_when_data_changes():
    """Different inputs produce different hashes."""
    ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
    h1 = _compute_event_hash("eid", ts, "actor1", "ACTION", "target", "summary", "prev")
    h2 = _compute_event_hash("eid", ts, "actor2", "ACTION", "target", "summary", "prev")
    assert h1 != h2


def test_event_hash_changes_when_prev_hash_changes():
    """Changing prev_hash produces different event_hash (chain integrity)."""
    ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
    h1 = _compute_event_hash("eid", ts, "actor", "ACTION", "target", "s", "prev1")
    h2 = _compute_event_hash("eid", ts, "actor", "ACTION", "target", "s", "prev2")
    assert h1 != h2


def test_event_hash_hex_length():
    """event_hash is a 64-character hex string (SHA-256)."""
    ts = datetime.now(timezone.utc)
    h = _compute_event_hash("eid", ts, "actor", "ACTION", "target", "s", "prev")
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


# ---------------------------------------------------------------------------
# AuditLogger.log tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_logger_log_writes_event():
    """AuditLogger.log() creates an AuditEvent with correct fields."""
    session = _mock_session()
    # prev_hash query returns empty (no prior events)
    prev_result = MagicMock()
    prev_result.scalar_one_or_none.return_value = None

    # append_event will call session.add + flush + refresh
    from discovery.db.models.audit_events import AuditEvent
    fake_event = MagicMock(spec=AuditEvent)
    fake_event.event_hash = "abc123"
    session.execute.return_value = prev_result
    session.refresh.side_effect = lambda obj: None

    with MagicMock() as mock_repo:
        from discovery.repositories import audit as audit_repo_module

        original_append = audit_repo_module.AuditRepository.append_event.__func__ if hasattr(
            audit_repo_module.AuditRepository.append_event, "__func__"
        ) else None

        # Patch append_event to just return the passed event
        import discovery.repositories.audit as audit_repo
        original = audit_repo.AuditRepository.append_event

        async def fake_append(ses, evt):
            ses.add(evt)
            await ses.flush()
            return evt

        audit_repo.AuditRepository.append_event = staticmethod(fake_append)
        try:
            result = await AuditLogger.log(
                session,
                actor_type="ADMIN",
                actor_id="admin@test",
                action=AuditAction.ADMIN_LOGIN,
                target_type="auth",
                target_id="",
                summary={"ip": "127.0.0.1"},
            )
        finally:
            audit_repo.AuditRepository.append_event = original

    # Verify the event object was passed to session.add
    session.add.assert_called_once()
    added_event = session.add.call_args[0][0]
    assert added_event.action == "ADMIN_LOGIN"
    assert added_event.actor_id == "admin@test"
    assert added_event.event_hash is not None
    assert len(added_event.event_hash) == 64


@pytest.mark.asyncio
async def test_audit_logger_sanitizes_summary():
    """AuditLogger.log() sanitizes sensitive keys from summary."""
    session = _mock_session()
    session.execute.return_value.scalar_one_or_none.return_value = None

    import discovery.repositories.audit as audit_repo

    async def fake_append(ses, evt):
        ses.add(evt)
        return evt

    audit_repo.AuditRepository.append_event = staticmethod(fake_append)

    await AuditLogger.log(
        session,
        actor_type="SERVICE",
        actor_id="svc-1",
        action=AuditAction.CREATE_SERVICE,
        summary={"secret_key": "must-hide", "name": "test-service"},
    )

    added_event = session.add.call_args[0][0]
    summary_obj = json.loads(added_event.summary)
    assert summary_obj["secret_key"] == "<REDACTED>"
    assert summary_obj["name"] == "test-service"


# ---------------------------------------------------------------------------
# audit_checkpoint task tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_checkpoint_with_no_events_writes_empty_hash():
    """compute_checkpoint works correctly with no prior audit events."""
    from discovery.tasks.audit_checkpoint import compute_checkpoint

    session = _mock_session()
    empty_hashes = MagicMock()
    empty_hashes.scalars.return_value.all.return_value = []
    session.execute.return_value = empty_hashes

    checkpoint = await compute_checkpoint(session)

    session.add.assert_called_once()
    added = session.add.call_args[0][0]
    assert added.events_count == 0
    # Empty set should still produce a valid SHA-256 hash
    assert len(added.checkpoint_hash) == 64


@pytest.mark.asyncio
async def test_checkpoint_hash_changes_with_different_events():
    """Different event hash sets produce different checkpoints."""
    from discovery.tasks.audit_checkpoint import compute_checkpoint

    # First call
    session1 = _mock_session()
    hashes1 = MagicMock()
    hashes1.scalars.return_value.all.return_value = ["aaa", "bbb"]
    session1.execute.return_value = hashes1

    checkpoint1 = await compute_checkpoint(session1)
    cp1_hash = session1.add.call_args[0][0].checkpoint_hash

    # Second call with different events
    session2 = _mock_session()
    hashes2 = MagicMock()
    hashes2.scalars.return_value.all.return_value = ["ccc", "ddd"]
    session2.execute.return_value = hashes2

    checkpoint2 = await compute_checkpoint(session2)
    cp2_hash = session2.add.call_args[0][0].checkpoint_hash

    assert cp1_hash != cp2_hash


# ---------------------------------------------------------------------------
# Audit router HTTP tests
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def audit_client(settings):
    app = create_app(settings=settings)
    mock_session = _mock_session()

    async def _override_db():
        yield mock_session

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_redis] = lambda: AsyncMock()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_audit_events_requires_security_admin(audit_client):
    """GET /api/v1/audit/events requires security-admin role."""
    resp = await audit_client.get("/api/v1/audit/events", headers=_operator_headers())
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_audit_events_returns_empty_list(audit_client):
    """GET /api/v1/audit/events returns empty list when no events."""
    resp = await audit_client.get("/api/v1/audit/events", headers=_admin_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["count"] == 0


@pytest.mark.asyncio
async def test_audit_verify_integrity_empty_range(audit_client):
    """POST /api/v1/audit/verify-integrity with empty range returns tampered_count=0."""
    resp = await audit_client.post(
        "/api/v1/audit/verify-integrity",
        headers=_admin_headers(),
        json={},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["tampered_count"] == 0
    assert data["events_checked"] == 0


@pytest.mark.asyncio
async def test_audit_export_returns_202(audit_client):
    """POST /api/v1/audit/export returns 202 with export_id."""
    resp = await audit_client.post(
        "/api/v1/audit/export",
        headers=_admin_headers(),
        json={"from_dt": "2025-01-01T00:00:00Z", "to_dt": "2025-01-02T00:00:00Z"},
    )
    assert resp.status_code == 202
    data = resp.json()
    assert "export_id" in data
    assert "events_exported" in data
