"""Tests for health probe endpoints.

These tests verify:
- /health/live always returns 200 (no external deps required)
- /health/ready returns 503 when DB / Redis are unreachable
"""
import pytest


@pytest.mark.asyncio
async def test_liveness_returns_200(client):
    resp = await client.get("/health/live")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_liveness_body(client):
    resp = await client.get("/health/live")
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "discovery"


@pytest.mark.asyncio
async def test_readiness_without_db_returns_503(client):
    """Readiness endpoint must return 503 when DB is unavailable.

    In test environment no real PostgreSQL server is running, so the DB
    connection will fail inside the readiness handler.
    """
    resp = await client.get("/health/ready")
    # DB will be unreachable (no server) → 503
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_readiness_body_has_checks(client):
    resp = await client.get("/health/ready")
    data = resp.json()
    assert "checks" in data
    assert "db" in data["checks"]
