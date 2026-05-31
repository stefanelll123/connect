"""Unit tests for TASK-033: Sentinel Lifecycle Manager.

Tests heartbeat processing, status state machine, decommission cascade,
rejoin, and heartbeat_monitor sweep.
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
from discovery.db.models.sentinels import Sentinel, SentinelInstance
from discovery.services.lifecycle_service import (
    compute_status_from_last_seen,
    process_heartbeat,
    decommission_sentinel,
    rejoin_sentinel,
    record_lifecycle_event,
)

SECRET = "test-lifecycle-secret"


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
    mock_result.scalars.return_value.all.return_value = []
    session.execute.return_value = mock_result
    session.flush = AsyncMock()
    session.add = MagicMock()
    return session


def _make_sentinel(
    *,
    is_active: bool = True,
    computed_status: str = "active",
    last_seen: datetime | None = None,
    did: str = "did:key:testSentinel",
    service_id: uuid.UUID | None = None,
    env: str = "dev",
) -> Sentinel:
    s = MagicMock(spec=Sentinel)
    s.id = uuid.uuid4()
    s.did = did
    s.role = "producer"
    s.env = env
    s.is_active = is_active
    s.computed_status = computed_status
    s.last_seen = last_seen or datetime.now(timezone.utc)
    s.service_id = service_id
    return s


# ---------------------------------------------------------------------------
# compute_status_from_last_seen — pure function tests
# ---------------------------------------------------------------------------

def test_status_active_recent():
    """Sentinel seen 30s ago → active."""
    last_seen = datetime.now(timezone.utc) - timedelta(seconds=30)
    assert compute_status_from_last_seen(last_seen) == "active"


def test_status_degraded_90_to_300s():
    """Sentinel seen 150s ago → degraded."""
    last_seen = datetime.now(timezone.utc) - timedelta(seconds=150)
    assert compute_status_from_last_seen(last_seen) == "degraded"


def test_status_offline_over_300s():
    """Sentinel seen 400s ago → offline."""
    last_seen = datetime.now(timezone.utc) - timedelta(seconds=400)
    assert compute_status_from_last_seen(last_seen) == "offline"


def test_status_offline_when_never_seen():
    """Sentinel with last_seen=None → offline."""
    assert compute_status_from_last_seen(None) == "offline"


def test_status_boundary_exactly_90s():
    """Sentinel seen exactly 90s ago is still active (≤ 90 threshold)."""
    last_seen = datetime.now(timezone.utc) - timedelta(seconds=90)
    assert compute_status_from_last_seen(last_seen) == "active"


def test_status_boundary_just_over_90s():
    """Sentinel seen 91s ago → degraded."""
    last_seen = datetime.now(timezone.utc) - timedelta(seconds=91)
    assert compute_status_from_last_seen(last_seen) == "degraded"


# ---------------------------------------------------------------------------
# process_heartbeat tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_heartbeat_sentinel_not_found_raises():
    """process_heartbeat raises ValueError when sentinel doesn't exist."""
    session = _mock_session()
    session.execute.return_value.scalar_one_or_none.return_value = None

    with pytest.raises(ValueError, match="not found"):
        await process_heartbeat(
            session,
            sentinel_id=uuid.uuid4(),
            instance_id="instance-1",
            version="1.0.0",
            health={},
        )


@pytest.mark.asyncio
async def test_heartbeat_updates_last_seen():
    """process_heartbeat updates sentinel.last_seen and returns ack+next."""
    session = _mock_session()
    sentinel = _make_sentinel(computed_status="degraded")

    # First execute: load Sentinel → return sentinel
    # Second execute: load SentinelInstance → return None (new instance)
    sentinel_result = MagicMock()
    sentinel_result.scalar_one_or_none.return_value = sentinel
    instance_result = MagicMock()
    instance_result.scalar_one_or_none.return_value = None
    lifecycle_result = MagicMock()
    # For record_lifecycle_event add()
    session.execute.side_effect = [sentinel_result, instance_result, MagicMock()]

    result = await process_heartbeat(
        session,
        sentinel_id=sentinel.id,
        instance_id="inst-1",
        version="2.0.0",
        health={"cpu_pct": 30.0},
    )

    assert "acknowledged_at" in result
    assert "next_expected_at" in result
    assert sentinel.last_seen is not None
    assert sentinel.computed_status == "active"


@pytest.mark.asyncio
async def test_heartbeat_existing_instance_updated():
    """process_heartbeat updates existing SentinelInstance."""
    session = _mock_session()
    sentinel = _make_sentinel()
    existing_instance = MagicMock(spec=SentinelInstance)
    existing_instance.instance_id = "inst-1"
    existing_instance.status = "degraded"

    sentinel_result = MagicMock()
    sentinel_result.scalar_one_or_none.return_value = sentinel
    instance_result = MagicMock()
    instance_result.scalar_one_or_none.return_value = existing_instance
    session.execute.side_effect = [sentinel_result, instance_result]

    await process_heartbeat(
        session,
        sentinel_id=sentinel.id,
        instance_id="inst-1",
        version="1.0",
        health={},
    )

    assert existing_instance.status == "active"


# ---------------------------------------------------------------------------
# decommission_sentinel tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_decommission_raises_when_not_found():
    """decommission_sentinel raises ValueError if sentinel not found."""
    session = _mock_session()
    session.execute.return_value.scalar_one_or_none.return_value = None

    with pytest.raises(ValueError, match="not found"):
        await decommission_sentinel(
            session,
            sentinel_id=uuid.uuid4(),
            reason="test",
            revoke_credentials=False,
            invalidate_descriptor=False,
            actor_id="admin",
            settings=MagicMock(blockchain_integration=False),
        )


@pytest.mark.asyncio
async def test_decommission_marks_sentinel_inactive():
    """decommission_sentinel sets is_active=False and computed_status=offline."""
    session = _mock_session()
    sentinel = _make_sentinel()
    instance = MagicMock(spec=SentinelInstance)
    instance.status = "active"

    # track execute calls by position
    calls = [0]
    def _side_effect(*args, **kwargs):
        idx = calls[0]
        calls[0] += 1
        r = MagicMock()
        if idx == 0:
            # load Sentinel
            r.scalar_one_or_none.return_value = sentinel
        elif idx == 1:
            # load Credentials (bulk update)
            r.scalars.return_value.all.return_value = []
        elif idx == 2:
            # bulk UPDATE credentials
            r.rowcount = 0
        elif idx == 3:
            # load SentinelInstances
            r.scalars.return_value.all.return_value = [instance]
        else:
            r.scalar_one_or_none.return_value = None
            r.scalars.return_value.all.return_value = []
        return r

    session.execute.side_effect = _side_effect

    result = await decommission_sentinel(
        session,
        sentinel_id=sentinel.id,
        reason="admin decommission",
        revoke_credentials=False,
        invalidate_descriptor=False,
        actor_id="admin",
        settings=MagicMock(blockchain_integration=False),
    )

    assert sentinel.is_active is False
    assert sentinel.computed_status == "offline"
    assert result["status"] == "DECOMMISSIONED"


# ---------------------------------------------------------------------------
# heartbeat_monitor sweep tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_status_sweep_transitions_degraded():
    """run_status_sweep transitions active→degraded for stale sentinel."""
    from discovery.tasks.heartbeat_monitor import run_status_sweep

    session = _mock_session()
    sentinel = _make_sentinel(
        computed_status="active",
        last_seen=datetime.now(timezone.utc) - timedelta(seconds=150),
    )

    result_sentinels = MagicMock()
    result_sentinels.scalars.return_value.all.return_value = [sentinel]
    # Subsequent calls for record_lifecycle_event
    session.execute.side_effect = [result_sentinels, MagicMock()]

    counts = await run_status_sweep(session)

    assert sentinel.computed_status == "degraded"
    assert "degraded" in counts


@pytest.mark.asyncio
async def test_status_sweep_no_change_when_active():
    """run_status_sweep does not emit lifecycle event when status unchanged."""
    from discovery.tasks.heartbeat_monitor import run_status_sweep

    session = _mock_session()
    sentinel = _make_sentinel(
        computed_status="active",
        last_seen=datetime.now(timezone.utc) - timedelta(seconds=10),
    )

    result_sentinels = MagicMock()
    result_sentinels.scalars.return_value.all.return_value = [sentinel]
    session.execute.return_value = result_sentinels

    counts = await run_status_sweep(session)

    assert sentinel.computed_status == "active"
    assert counts.get("active", 0) == 1


# ---------------------------------------------------------------------------
# HTTP endpoint tests
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def lifecycle_client(settings):
    app = create_app(settings=settings)
    mock_session = _mock_session()

    async def _override_db():
        yield mock_session

    app.dependency_overrides[get_db] = _override_db
    app.dependency_overrides[get_redis] = lambda: AsyncMock()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_heartbeat_endpoint_invalid_uuid(lifecycle_client):
    """POST /api/v1/sentinels/heartbeat with invalid UUID returns 422."""
    resp = await lifecycle_client.post(
        "/api/v1/sentinels/heartbeat",
        headers=_operator_headers(),
        json={"sentinel_id": "not-a-uuid", "instance_id": "inst-1", "version": "1.0"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_heartbeat_endpoint_not_found(lifecycle_client):
    """POST /api/v1/sentinels/heartbeat with unknown sentinel returns 404."""
    resp = await lifecycle_client.post(
        "/api/v1/sentinels/heartbeat",
        headers=_operator_headers(),
        json={
            "sentinel_id": str(uuid.uuid4()),
            "instance_id": "inst-1",
            "version": "1.0",
        },
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_decommission_requires_security_admin(lifecycle_client):
    """POST /api/v1/sentinels/{id}/decommission requires security-admin role."""
    resp = await lifecycle_client.post(
        f"/api/v1/sentinels/{uuid.uuid4()}/decommission",
        headers=_operator_headers(),
        json={"reason": "test"},
    )
    assert resp.status_code == 403
