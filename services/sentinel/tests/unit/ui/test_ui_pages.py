"""Unit tests for TASK-054: Sentinel UI pages."""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_settings(**kwargs):
    from sentinel.config import SentinelSettings

    return SentinelSettings(
        sentinel_role="producer",
        backend_url="http://backend:8080",
        discovery_url="http://discovery:8000",
        env="dev",
        sentinel_did="did:key:z6MkTestDID",
        service_id="svc-test",
        sentinel_id="inst-test-001",
        **kwargs,
    )


def _make_app(extra_state: dict | None = None):
    """Create a Sentinel app with UI router registered and fake state."""
    from unittest.mock import AsyncMock

    from sentinel.app import create_app

    settings = _make_settings()
    app = create_app(settings=settings)

    # Patch lifespan state that UI router and other routes read
    app.state.settings = settings
    app.state.http_client = AsyncMock()
    app.state.start_time = 0.0
    app.state.log_ring_buffer = None
    app.state.credential_store = None
    app.state.status_cache = None

    if extra_state:
        for k, v in extra_state.items():
            setattr(app.state, k, v)

    return app


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestUIDIDPage:
    @pytest.mark.asyncio
    async def test_did_page_returns_200(self):
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/did")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_did_page_contains_did_value(self):
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/did")
        assert "did:key:z6MkTestDID" in resp.text

    @pytest.mark.asyncio
    async def test_did_page_has_security_headers(self):
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/did")
        assert resp.headers.get("x-frame-options") == "DENY"
        assert "content-security-policy" in resp.headers


class TestUICredentialsPage:
    @pytest.mark.asyncio
    async def test_credentials_page_returns_200(self):
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/credentials")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_credentials_no_raw_jwt_in_response(self):
        """Raw JWT tokens (header.payload.sig) must not appear in UI output."""
        import re

        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/credentials")
        # JWT pattern: three base64url segments
        jwt_re = re.compile(r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
        assert not jwt_re.search(resp.text), "Raw JWT found in credentials page"


class TestUIHealthPage:
    @pytest.mark.asyncio
    async def test_health_page_returns_200(self):
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/health")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_health_page_contains_instance_id(self):
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/health")
        assert "inst-test-001" in resp.text


class TestUILogsPage:
    @pytest.mark.asyncio
    async def test_logs_page_returns_200(self):
        app = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/logs")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_logs_page_with_ring_buffer_events(self):
        """Events from the ring buffer appear in the logs page."""
        from common.sentinel_logging.schema import SentinelLogEvent
        from common.sentinel_logging.ring_buffer import LogRingBuffer

        buf = LogRingBuffer(maxlen=100)
        ev = SentinelLogEvent(
            ts="2024-01-01T00:00:00Z",
            level="INFO",
            event="request",
            service_id="svc-test",
            env="dev",
            role="producer",
            decision="PERMIT",
            http_method="GET",
            http_path="/api/v1/resource",
            http_status=200,
            latency_ms=42,
        )
        buf.append(ev)

        app = _make_app(extra_state={"log_ring_buffer": buf})
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/logs")
        assert resp.status_code == 200
        assert "/api/v1/resource" in resp.text

    @pytest.mark.asyncio
    async def test_logs_page_decision_filter(self):
        """decision=deny filter shows only DENY events."""
        from common.sentinel_logging.schema import SentinelLogEvent
        from common.sentinel_logging.ring_buffer import LogRingBuffer

        buf = LogRingBuffer(maxlen=100)
        for decision in ("PERMIT", "DENY"):
            buf.append(
                SentinelLogEvent(
                    ts="2024-01-01T00:00:00Z",
                    level="INFO",
                    event="request",
                    service_id="svc-test",
                    env="dev",
                    role="producer",
                    decision=decision,
                    http_method="POST",
                    http_path=f"/api/{decision.lower()}",
                    http_status=200 if decision == "PERMIT" else 403,
                    latency_ms=10,
                )
            )

        app = _make_app(extra_state={"log_ring_buffer": buf})
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/logs?decision=deny")
        assert "/api/deny" in resp.text
        assert "/api/permit" not in resp.text

    @pytest.mark.asyncio
    async def test_no_authorization_header_values_in_ui(self):
        """Authorization header values must never appear in UI output."""
        from common.sentinel_logging.schema import SentinelLogEvent
        from common.sentinel_logging.ring_buffer import LogRingBuffer

        secret_token = "SECRET_BEARER_TOKEN_12345"  # noqa: S105

        buf = LogRingBuffer(maxlen=100)
        ev = SentinelLogEvent(
            ts="2024-01-01T00:00:00Z",
            level="INFO",
            event="request",
            service_id="svc-test",
            env="dev",
            role="producer",
            decision="PERMIT",
            http_method="GET",
            http_path="/api/secret",
            http_status=200,
            latency_ms=5,
        )
        buf.append(ev)

        app = _make_app(extra_state={"log_ring_buffer": buf})
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {secret_token}"},
        ) as client:
            resp = await client.get("/ui/logs")
        assert secret_token not in resp.text
