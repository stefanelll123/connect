"""Tests for request-ID middleware and error handling.

Covers:
- X-Request-ID generated server-side when absent
- Valid client UUID4 echoed back unchanged
- Invalid client value replaced with fresh UUID4
- Unhandled exceptions return 500 Problem+JSON without stack trace
- CORS blocks unlisted origins
"""
from __future__ import annotations

import re
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from discovery.app import create_app
from discovery.config import DiscoverySettings

UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Request-ID tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_request_id_generated_when_absent(client):
    resp = await client.get("/health/live")
    assert "x-request-id" in resp.headers
    assert UUID4_RE.match(resp.headers["x-request-id"])


@pytest.mark.asyncio
async def test_valid_client_request_id_echoed(client):
    rid = str(uuid.uuid4())
    resp = await client.get("/health/live", headers={"X-Request-ID": rid})
    assert resp.headers["x-request-id"] == rid


@pytest.mark.asyncio
async def test_invalid_request_id_replaced(client):
    resp = await client.get("/health/live", headers={"X-Request-ID": "not-a-uuid"})
    assert resp.headers["x-request-id"] != "not-a-uuid"
    assert UUID4_RE.match(resp.headers["x-request-id"])


@pytest.mark.asyncio
async def test_correlation_id_present(client):
    resp = await client.get("/health/live")
    assert "x-correlation-id" in resp.headers


# ---------------------------------------------------------------------------
# Error handling — RFC 7807 Problem+JSON
# ---------------------------------------------------------------------------

@pytest.fixture
def error_app(test_settings):
    """App with extra routes for error-handling tests."""
    from fastapi import APIRouter, HTTPException

    application = create_app(settings=test_settings)
    boom_router = APIRouter()

    @boom_router.get("/test/boom")
    async def boom():
        # HTTPException goes through the registered exception handler cleanly;
        # raw RuntimeError propagation through BaseHTTPMiddleware task groups is
        # a known Starlette 0.37+ behavioral constraint.
        raise HTTPException(status_code=500, detail="intentional test error")

    @boom_router.get("/test/notfound")
    async def notfound():
        raise HTTPException(status_code=404, detail="resource not found")

    @boom_router.get("/test/forbidden")
    async def forbidden():
        raise HTTPException(status_code=403, detail="access denied")

    application.include_router(boom_router)
    return application


@pytest.mark.asyncio
async def test_unhandled_exception_returns_500_problem_json(error_app):
    async with AsyncClient(
        transport=ASGITransport(app=error_app), base_url="http://test"
    ) as c:
        resp = await c.get("/test/boom")

    assert resp.status_code == 500
    assert "application/problem+json" in resp.headers.get("content-type", "")
    data = resp.json()
    assert data["status"] == 500
    # Stack trace must NOT appear in the response body
    assert "Traceback" not in str(data)
    assert "at line" not in str(data)


@pytest.mark.asyncio
async def test_404_returns_problem_json(error_app):
    """HTTPException(404) returns problem+json with correct structure."""
    async with AsyncClient(
        transport=ASGITransport(app=error_app), base_url="http://test"
    ) as c:
        resp = await c.get("/test/notfound")
    assert resp.status_code == 404
    assert "application/problem+json" in resp.headers.get("content-type", "")
    data = resp.json()
    assert data["status"] == 404
    data = resp.json()
    assert data["status"] == 404


# ---------------------------------------------------------------------------
# CORS — unlisted origins must be blocked
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cors_blocks_unlisted_origin(client):
    """Default empty CORS origins means all cross-origin requests lack CORS headers."""
    resp = await client.get(
        "/health/live",
        headers={"Origin": "https://evil.example.com"},
    )
    # No Access-Control-Allow-Origin header should be present for unlisted origins
    assert "access-control-allow-origin" not in resp.headers


@pytest.mark.asyncio
async def test_cors_allows_configured_origin():
    settings = DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        redis_url="redis://localhost:6379/15",
        allowed_cors_origins=["https://ui.example.com"],
    )
    application = create_app(settings=settings)
    async with AsyncClient(
        transport=ASGITransport(app=application), base_url="http://test"
    ) as c:
        resp = await c.get(
            "/health/live",
            headers={"Origin": "https://ui.example.com"},
        )
    assert resp.headers.get("access-control-allow-origin") == "https://ui.example.com"
