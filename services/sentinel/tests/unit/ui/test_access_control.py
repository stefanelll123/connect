"""Unit tests for TASK-056: Sentinel UI access control and CSRF protection."""
from __future__ import annotations

import base64
import logging

import pytest
from httpx import ASGITransport, AsyncClient
from unittest.mock import AsyncMock


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
        sentinel_did="did:key:z6MkTest",
        service_id="svc-test",
        sentinel_id="inst-test-001",
        **kwargs,
    )


def _make_app(env_overrides: dict[str, str] | None = None, **settings_kwargs):
    import os
    from sentinel.app import create_app

    env_overrides = env_overrides or {}
    old = {k: os.environ.get(k) for k in env_overrides}
    for k, v in env_overrides.items():
        os.environ[k] = v

    try:
        settings = _make_settings(**settings_kwargs)
        app = create_app(settings=settings)
        app.state.settings = settings
        app.state.http_client = AsyncMock()
        app.state.start_time = 0.0
        app.state.log_ring_buffer = None
        app.state.credential_store = None
        app.state.status_cache = None
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    return app


def _basic_header(password: str) -> str:
    encoded = base64.b64encode(f"sentinel:{password}".encode()).decode()
    return f"Basic {encoded}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestNoAuth:
    @pytest.mark.asyncio
    async def test_no_auth_returns_200(self):
        app = _make_app(env_overrides={"SENTINEL_UI_AUTH": "none"})
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/health")
        assert resp.status_code == 200


class TestBasicAuth:
    @pytest.mark.asyncio
    async def test_valid_credentials_returns_200(self):
        app = _make_app(
            env_overrides={
                "SENTINEL_UI_AUTH": "basic",
                "SENTINEL_UI_PASSWORD": "s3cr3t",
            }
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/ui/health",
                headers={"Authorization": _basic_header("s3cr3t")},
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_wrong_password_returns_401(self):
        app = _make_app(
            env_overrides={
                "SENTINEL_UI_AUTH": "basic",
                "SENTINEL_UI_PASSWORD": "s3cr3t",
            }
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/ui/health",
                headers={"Authorization": _basic_header("wrong")},
            )
        assert resp.status_code == 401
        assert "www-authenticate" in resp.headers

    @pytest.mark.asyncio
    async def test_missing_auth_returns_401(self):
        app = _make_app(
            env_overrides={
                "SENTINEL_UI_AUTH": "basic",
                "SENTINEL_UI_PASSWORD": "s3cr3t",
            }
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/health")
        assert resp.status_code == 401


class TestTokenAuth:
    @pytest.mark.asyncio
    async def test_correct_token_returns_200(self):
        app = _make_app(
            env_overrides={
                "SENTINEL_UI_AUTH": "token",
                "SENTINEL_UI_TOKEN": "my-secret-token",
            }
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/ui/health",
                headers={"Authorization": "Bearer my-secret-token"},
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_wrong_token_returns_401(self):
        app = _make_app(
            env_overrides={
                "SENTINEL_UI_AUTH": "token",
                "SENTINEL_UI_TOKEN": "my-secret-token",
            }
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/ui/health",
                headers={"Authorization": "Bearer wrong-token"},
            )
        assert resp.status_code == 401


class TestSecurityHeaders:
    @pytest.mark.asyncio
    async def test_x_frame_options_present(self):
        app = _make_app(env_overrides={"SENTINEL_UI_AUTH": "none"})
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/health")
        assert resp.headers.get("x-frame-options") == "DENY"

    @pytest.mark.asyncio
    async def test_csp_present(self):
        app = _make_app(env_overrides={"SENTINEL_UI_AUTH": "none"})
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/health")
        assert "content-security-policy" in resp.headers

    @pytest.mark.asyncio
    async def test_security_headers_on_401(self):
        """Security headers must be present even on 401 responses."""
        app = _make_app(
            env_overrides={
                "SENTINEL_UI_AUTH": "token",
                "SENTINEL_UI_TOKEN": "tok",
            }
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/health")
        assert resp.status_code == 401
        assert resp.headers.get("x-frame-options") == "DENY"


class TestCSRF:
    @pytest.mark.asyncio
    async def test_csrf_cookie_set_on_first_get(self):
        app = _make_app(env_overrides={"SENTINEL_UI_AUTH": "none"})
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ui/health")
        assert resp.status_code == 200
        assert "csrf_token" in resp.cookies

    @pytest.mark.asyncio
    async def test_post_without_csrf_returns_403(self):
        """POST to a /ui route without CSRF token must be rejected."""
        app = _make_app(env_overrides={"SENTINEL_UI_AUTH": "none"})
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # First get a valid CSRF cookie
            await client.get("/ui/health")
            # Now POST without the X-CSRF-Token header
            resp = await client.post("/ui/health")
        assert resp.status_code == 403


class TestNonLoopbackWarning:
    def test_non_loopback_without_auth_logs_critical(self, caplog):
        import os

        old_host = os.environ.get("SENTINEL_UI_HOST")
        old_auth = os.environ.get("SENTINEL_UI_AUTH")
        os.environ["SENTINEL_UI_HOST"] = "0.0.0.0"
        os.environ["SENTINEL_UI_AUTH"] = "none"
        try:
            with caplog.at_level(logging.CRITICAL, logger="sentinel.app"):
                _make_app(env_overrides={})
            assert any(
                "ui_insecure_exposure" in r.message for r in caplog.records
            )
        finally:
            if old_host is None:
                os.environ.pop("SENTINEL_UI_HOST", None)
            else:
                os.environ["SENTINEL_UI_HOST"] = old_host
            if old_auth is None:
                os.environ.pop("SENTINEL_UI_AUTH", None)
            else:
                os.environ["SENTINEL_UI_AUTH"] = old_auth
