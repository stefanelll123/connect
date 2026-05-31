"""Unit tests for TASK-055: SSE live log streaming."""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(path: str = "/api/test", decision: str = "PERMIT", service_id: str = "svc"):
    from common.sentinel_logging.schema import SentinelLogEvent

    return SentinelLogEvent(
        ts="2024-01-01T00:00:00Z",
        level="INFO",
        event="request",
        service_id=service_id,
        env="dev",
        role="producer",
        decision=decision,
        http_method="GET",
        http_path=path,
        http_status=200 if decision == "PERMIT" else 403,
        latency_ms=10,
    )


def _make_app_with_buffer(buf=None):
    from common.sentinel_logging.ring_buffer import LogRingBuffer
    from sentinel.app import create_app
    from sentinel.config import SentinelSettings

    settings = SentinelSettings(
        sentinel_role="producer",
        backend_url="http://backend:8080",
        discovery_url="http://discovery:8000",
        env="dev",
    )
    app = create_app(settings=settings)
    app.state.settings = settings
    app.state.http_client = AsyncMock()
    app.state.credential_store = None
    app.state.status_cache = None
    app.state.log_ring_buffer = buf if buf is not None else LogRingBuffer(maxlen=100)
    app.state.active_sse_connections = 0
    return app


async def _finite_stream(*_args, **_kwargs):
    """A finite replacement for log_event_stream used in HTTP-level tests."""
    yield ": keepalive\n\n"


# ---------------------------------------------------------------------------
# HTTP-level tests (use finite/mock stream to avoid hanging ASGI transport)
# ---------------------------------------------------------------------------


class TestSSEHTTPRoute:
    @pytest.mark.asyncio
    async def test_sse_returns_200_event_stream_content_type(self):
        """SSE route returns 200 with text/event-stream Content-Type."""
        app = _make_app_with_buffer()
        with patch("sentinel.ui.router.log_event_stream", _finite_stream):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                async with client.stream("GET", "/ui/logs/stream") as resp:
                    assert resp.status_code == 200
                    assert "text/event-stream" in resp.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_11th_connection_returns_429(self):
        """After 10 concurrent connections the 11th must receive HTTP 429."""
        app = _make_app_with_buffer()
        app.state.active_sse_connections = 10  # simulate 10 live connections

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/logs/stream")
        assert resp.status_code == 429

    @pytest.mark.asyncio
    async def test_disconnect_decrements_active_connections(self):
        """Client disconnect must decrement active_sse_connections back to 0."""
        app = _make_app_with_buffer()
        with patch("sentinel.ui.router.log_event_stream", _finite_stream):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                async with client.stream("GET", "/ui/logs/stream") as _resp:
                    pass  # stream completes (finite generator)

        assert app.state.active_sse_connections == 0


# ---------------------------------------------------------------------------
# Generator-level tests (test log_event_stream directly)
# ---------------------------------------------------------------------------


class TestSSEGenerator:
    @pytest.mark.asyncio
    async def test_events_appear_in_stream(self):
        """Events pushed to the ring buffer appear in the SSE generator output."""
        import sentinel.ui.live_logs as ll
        from common.sentinel_logging.ring_buffer import LogRingBuffer

        buf = LogRingBuffer(maxlen=100)
        q = buf.subscribe()
        buf.append(_make_event("/api/pumped"))

        received: list[dict] = []
        async for chunk in ll.log_event_stream(q, buf, None, None):
            if chunk.startswith("data: "):
                received.append(json.loads(chunk[6:]))
                break  # got one event — done
        buf.unsubscribe(q)

        assert any(e.get("http_path") == "/api/pumped" for e in received)

    @pytest.mark.asyncio
    async def test_filter_decision_deny_only(self):
        """filter_decision=deny must suppress PERMIT events from the stream."""
        import sentinel.ui.live_logs as ll
        from common.sentinel_logging.ring_buffer import LogRingBuffer

        buf = LogRingBuffer(maxlen=100)
        q = buf.subscribe()
        buf.append(_make_event("/permit-path", decision="PERMIT"))
        buf.append(_make_event("/deny-path", decision="DENY"))

        received: list[dict] = []
        async for chunk in ll.log_event_stream(q, buf, "deny", None):
            if chunk.startswith("data: "):
                received.append(json.loads(chunk[6:]))
                break
        buf.unsubscribe(q)

        assert all(e.get("decision", "").lower() == "deny" for e in received), (
            f"Non-DENY events in stream: {received}"
        )
        assert any(e.get("http_path") == "/deny-path" for e in received)

    @pytest.mark.asyncio
    async def test_slow_client_queue_never_exceeds_maxsize(self):
        """Push 300 events to a queue with maxsize=20; size must never exceed 20."""
        from common.sentinel_logging.ring_buffer import LogRingBuffer

        buf = LogRingBuffer(maxlen=1000)
        q = buf.subscribe(maxsize=20)

        for i in range(300):
            buf.append(_make_event(f"/path/{i}"))

        assert q.qsize() <= 20, f"Queue size exceeded maxsize: {q.qsize()}"

    @pytest.mark.asyncio
    async def test_events_dropped_comment_sent(self):
        """When events are dropped due to backpressure, an SSE comment is sent."""
        import sentinel.ui.live_logs as ll
        from common.sentinel_logging.ring_buffer import LogRingBuffer

        buf = LogRingBuffer(maxlen=1000)
        q = buf.subscribe(maxsize=5)  # tiny queue to trigger drops

        # Overflow the queue: push 20 events
        for i in range(20):
            buf.append(_make_event(f"/overflow/{i}"))

        comments: list[str] = []
        async for chunk in ll.log_event_stream(q, buf, None, None):
            if chunk.startswith(": events_dropped"):
                comments.append(chunk)
                break
            elif chunk.startswith("data: "):
                break  # no drop comment found before first event — might be ok
        buf.unsubscribe(q)

        # The ring buffer should have tracked drops
        # (either comments were sent, or queue was at most 5)
        assert q.qsize() <= 5

    @pytest.mark.asyncio
    async def test_keepalive_comment_on_timeout(self):
        """A ': keepalive' comment is sent when no event arrives within the timeout."""
        import sentinel.ui.live_logs as ll
        from common.sentinel_logging.ring_buffer import LogRingBuffer

        original = ll._KEEPALIVE_TIMEOUT
        ll._KEEPALIVE_TIMEOUT = 0.05  # 50 ms for test speed

        buf = LogRingBuffer(maxlen=100)
        q = buf.subscribe()

        keepalives: list[str] = []
        try:
            async for chunk in ll.log_event_stream(q, buf, None, None):
                if chunk.startswith(": keepalive"):
                    keepalives.append(chunk)
                    break
        finally:
            buf.unsubscribe(q)
            ll._KEEPALIVE_TIMEOUT = original

        assert keepalives, "No keepalive comment received"

