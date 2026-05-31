"""Unit tests for TASK-035: API Hardening middleware."""
from __future__ import annotations

import json

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_echo_app():
    """Minimal Starlette app that echoes back request info."""
    async def echo(request: Request):
        return JSONResponse({"path": request.url.path, "method": request.method})

    return Starlette(routes=[Route("/{path:path}", echo, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])])


# ---------------------------------------------------------------------------
# SecureHeadersMiddleware
# ---------------------------------------------------------------------------

class TestSecureHeadersMiddleware:
    def test_adds_x_content_type_options(self):
        from discovery.middleware.secure_headers import SecureHeadersMiddleware

        app = _make_echo_app()
        app.add_middleware(SecureHeadersMiddleware)

        with TestClient(app) as client:
            resp = client.get("/test")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    def test_adds_x_frame_options_deny(self):
        from discovery.middleware.secure_headers import SecureHeadersMiddleware

        app = _make_echo_app()
        app.add_middleware(SecureHeadersMiddleware)

        with TestClient(app) as client:
            resp = client.get("/test")
        assert resp.headers.get("x-frame-options") == "DENY"

    def test_adds_referrer_policy(self):
        from discovery.middleware.secure_headers import SecureHeadersMiddleware

        app = _make_echo_app()
        app.add_middleware(SecureHeadersMiddleware)

        with TestClient(app) as client:
            resp = client.get("/test")
        assert "referrer-policy" in resp.headers

    def test_adds_csp_for_api(self):
        from discovery.middleware.secure_headers import SecureHeadersMiddleware

        app = _make_echo_app()
        app.add_middleware(SecureHeadersMiddleware)

        with TestClient(app) as client:
            resp = client.get("/test")
        assert "default-src" in resp.headers.get("content-security-policy", "")

    def test_hsts_absent_in_dev(self):
        from discovery.middleware.secure_headers import SecureHeadersMiddleware

        app = _make_echo_app()
        # env=dev (default): HSTS should NOT be present
        mock_settings = MagicMock()
        mock_settings.env = "dev"
        app.state.settings = mock_settings
        app.add_middleware(SecureHeadersMiddleware)

        with TestClient(app) as client:
            resp = client.get("/test")
        assert "strict-transport-security" not in resp.headers

    def test_hsts_present_in_prod(self):
        from discovery.middleware.secure_headers import SecureHeadersMiddleware

        app = _make_echo_app()
        mock_settings = MagicMock()
        mock_settings.env = "prod"
        app.state.settings = mock_settings
        app.add_middleware(SecureHeadersMiddleware)

        with TestClient(app) as client:
            resp = client.get("/test")
        hsts = resp.headers.get("strict-transport-security", "")
        assert "max-age=63072000" in hsts


# ---------------------------------------------------------------------------
# RequestLimitsMiddleware
# ---------------------------------------------------------------------------

class TestRequestLimitsMiddleware:
    def test_large_content_length_returns_413(self):
        from discovery.middleware.request_limits import RequestLimitsMiddleware

        app = _make_echo_app()
        mock_settings = MagicMock()
        mock_settings.max_request_body_bytes = 100
        mock_settings.max_header_size_bytes = 16384
        app.state.settings = mock_settings
        app.add_middleware(RequestLimitsMiddleware)

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/test",
                content=b"x" * 50,
                headers={"Content-Length": "200"},
            )
        assert resp.status_code == 413
        assert resp.json()["code"] == "REQUEST_TOO_LARGE"

    def test_normal_content_length_passes(self):
        from discovery.middleware.request_limits import RequestLimitsMiddleware

        app = _make_echo_app()
        mock_settings = MagicMock()
        mock_settings.max_request_body_bytes = 10_000
        mock_settings.max_header_size_bytes = 16384
        app.state.settings = mock_settings
        app.add_middleware(RequestLimitsMiddleware)

        with TestClient(app) as client:
            resp = client.post("/test", json={"key": "value"})
        assert resp.status_code == 200

    def test_invalid_content_length_returns_400(self):
        from discovery.middleware.request_limits import RequestLimitsMiddleware

        app = _make_echo_app()
        mock_settings = MagicMock()
        mock_settings.max_request_body_bytes = 10_000
        mock_settings.max_header_size_bytes = 16384
        app.state.settings = mock_settings
        app.add_middleware(RequestLimitsMiddleware)

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/test", headers={"Content-Length": "not-a-number"})
        assert resp.status_code == 400
        assert resp.json()["code"] == "INVALID_CONTENT_LENGTH"


# ---------------------------------------------------------------------------
# RateLimitMiddleware (unit — Redis mocked)
# ---------------------------------------------------------------------------

class TestRateLimitMiddleware:
    @pytest.mark.asyncio
    async def test_rate_limit_fail_closed_when_redis_none(self):
        """When Redis is None and fail_open=False, middleware returns 503."""
        from discovery.middleware.rate_limit import RateLimitMiddleware
        from fastapi import FastAPI

        fast_app = FastAPI()

        @fast_app.post("/api/v1/sentinels/onboard")
        async def onboard():
            return {"status": "ok"}

        fast_app.state.redis = None
        fast_app.state.settings = None
        fast_app.add_middleware(RateLimitMiddleware, fail_open=False)

        async with AsyncClient(
            transport=ASGITransport(app=fast_app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/v1/sentinels/onboard")
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_rate_limit_fail_open_when_redis_none(self):
        """When Redis is None and fail_open=True, requests pass through."""
        from discovery.middleware.rate_limit import RateLimitMiddleware
        from fastapi import FastAPI

        fast_app = FastAPI()

        @fast_app.post("/api/v1/sentinels/onboard")
        async def onboard():
            return {"status": "ok"}

        fast_app.state.redis = None
        fast_app.state.settings = None
        fast_app.add_middleware(RateLimitMiddleware, fail_open=True)

        async with AsyncClient(
            transport=ASGITransport(app=fast_app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/v1/sentinels/onboard")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_health_endpoint_skips_rate_limit(self):
        """Health endpoints must never be rate-limited."""
        from discovery.middleware.rate_limit import RateLimitMiddleware
        from fastapi import FastAPI

        fast_app = FastAPI()

        @fast_app.get("/health/live")
        async def live():
            return {"status": "ok"}

        fast_app.state.redis = None
        fast_app.state.settings = None
        fast_app.add_middleware(RateLimitMiddleware, fail_open=False)

        async with AsyncClient(
            transport=ASGITransport(app=fast_app), base_url="http://test"
        ) as client:
            resp = await client.get("/health/live")
        # Should be 200 even though Redis is None and fail_open=False
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_rate_limit_allows_when_under_limit(self):
        """Requests under the limit pass through."""
        from discovery.middleware.rate_limit import RateLimitMiddleware
        from fastapi import FastAPI

        fast_app = FastAPI()

        @fast_app.post("/api/v1/sentinels/onboard")
        async def onboard():
            return {"status": "ok"}

        # Mock Redis pipeline as async context manager
        mock_pipe = AsyncMock()
        mock_pipe.execute = AsyncMock(return_value=[None, 0, None, None])
        mock_pipe.zremrangebyscore = MagicMock()
        mock_pipe.zadd = MagicMock()
        mock_pipe.zcard = MagicMock()
        mock_pipe.expire = MagicMock()

        class _PipeCtx:
            async def __aenter__(self):
                return mock_pipe
            async def __aexit__(self, *a):
                return False

        mock_redis = AsyncMock()
        mock_redis.pipeline = MagicMock(return_value=_PipeCtx())

        fast_app.state.redis = mock_redis
        fast_app.state.settings = None
        fast_app.add_middleware(RateLimitMiddleware, fail_open=False)

        async with AsyncClient(
            transport=ASGITransport(app=fast_app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/v1/sentinels/onboard")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_rate_limit_blocks_when_over_limit(self):
        """Requests over the limit return 429 with Retry-After."""
        from discovery.middleware.rate_limit import RateLimitMiddleware
        from fastapi import FastAPI

        fast_app = FastAPI()

        @fast_app.post("/api/v1/sentinels/onboard")
        async def onboard():
            return {"status": "ok"}

        # Mock Redis pipeline that returns count=10 (over the default limit of 5)
        mock_pipe = AsyncMock()
        mock_pipe.execute = AsyncMock(return_value=[None, 10, None, None])
        mock_pipe.zremrangebyscore = MagicMock()
        mock_pipe.zadd = MagicMock()
        mock_pipe.zcard = MagicMock()
        mock_pipe.expire = MagicMock()

        class _PipeCtx:
            async def __aenter__(self):
                return mock_pipe
            async def __aexit__(self, *a):
                return False

        mock_redis = AsyncMock()
        mock_redis.pipeline = MagicMock(return_value=_PipeCtx())
        mock_redis.zrange = AsyncMock(return_value=[("1000000000.0", 1000000000.0)])

        fast_app.state.redis = mock_redis
        fast_app.state.settings = None
        fast_app.add_middleware(RateLimitMiddleware, fail_open=False)

        async with AsyncClient(
            transport=ASGITransport(app=fast_app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/v1/sentinels/onboard")
        assert resp.status_code == 429
        assert "retry-after" in resp.headers
        body = resp.json()
        assert body["code"] == "RATE_LIMIT_EXCEEDED"


# ---------------------------------------------------------------------------
# IdempotencyMiddleware
# ---------------------------------------------------------------------------

class TestIdempotencyMiddleware:
    @pytest.mark.asyncio
    async def test_cached_response_returned_with_idempotency_used_header(self):
        from discovery.middleware.idempotency import IdempotencyMiddleware
        from fastapi import FastAPI

        fast_app = FastAPI()

        @fast_app.post("/api/v1/enrollments")
        async def enroll():
            return {"status": "created"}

        cached_payload = json.dumps({
            "body": '{"status":"cached"}',
            "status_code": 201,
            "headers": {"content-type": "application/json"},
            "media_type": "application/json",
        })
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=cached_payload)

        fast_app.state.redis = mock_redis
        fast_app.add_middleware(IdempotencyMiddleware)

        async with AsyncClient(
            transport=ASGITransport(app=fast_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/v1/enrollments",
                headers={"X-Idempotency-Key": "test-key-123"},
            )
        assert resp.headers.get("x-idempotency-used") == "true"

    @pytest.mark.asyncio
    async def test_no_idempotency_key_passes_through(self):
        from discovery.middleware.idempotency import IdempotencyMiddleware
        from fastapi import FastAPI

        fast_app = FastAPI()

        @fast_app.post("/api/v1/enrollments")
        async def enroll():
            return {"status": "created"}

        fast_app.state.redis = AsyncMock()
        fast_app.add_middleware(IdempotencyMiddleware)

        async with AsyncClient(
            transport=ASGITransport(app=fast_app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/v1/enrollments")
        # No X-Idempotency-Used header — fresh response
        assert resp.status_code == 200
        assert "x-idempotency-used" not in resp.headers

    @pytest.mark.asyncio
    async def test_get_requests_not_cached(self):
        from discovery.middleware.idempotency import IdempotencyMiddleware
        from fastapi import FastAPI

        fast_app = FastAPI()

        @fast_app.get("/api/v1/enrollments")
        async def list_enrollments():
            return {"items": []}

        mock_redis = AsyncMock()
        fast_app.state.redis = mock_redis
        fast_app.add_middleware(IdempotencyMiddleware)

        async with AsyncClient(
            transport=ASGITransport(app=fast_app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/api/v1/enrollments",
                headers={"X-Idempotency-Key": "get-key-456"},
            )
        # GET is not idempotency-cached — Redis should not have been called
        mock_redis.get.assert_not_called()
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# AbuseDetectionMiddleware
# ---------------------------------------------------------------------------

class TestAbuseDetectionMiddleware:
    @pytest.mark.asyncio
    async def test_flagged_ip_blocked_on_onboard(self):
        from discovery.middleware.abuse_detection import AbuseDetectionMiddleware
        from fastapi import FastAPI

        fast_app = FastAPI()

        @fast_app.post("/api/v1/sentinels/onboard")
        async def onboard():
            return {"status": "ok"}

        # Redis returns is_flagged=1 (IP is blacklisted)
        mock_redis = AsyncMock()
        mock_redis.exists = AsyncMock(return_value=1)

        fast_app.state.redis = mock_redis
        fast_app.add_middleware(AbuseDetectionMiddleware)

        async with AsyncClient(
            transport=ASGITransport(app=fast_app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/v1/sentinels/onboard")
        assert resp.status_code == 429
        assert resp.json()["code"] == "ABUSE_DETECTED"

    @pytest.mark.asyncio
    async def test_revocation_storm_returns_428(self):
        from discovery.middleware.abuse_detection import AbuseDetectionMiddleware
        from fastapi import FastAPI

        fast_app = FastAPI()

        @fast_app.post("/api/v1/credentials/{cred_id}/revoke")
        async def revoke(cred_id: str):
            return {"status": "ok"}

        # Not flagged for onboard; revoke count = 15 (over threshold 10)
        mock_pipe = AsyncMock()
        mock_pipe.execute = AsyncMock(return_value=[None, None, 15, None])
        mock_pipe.zremrangebyscore = MagicMock()
        mock_pipe.zadd = MagicMock()
        mock_pipe.zcard = MagicMock()
        mock_pipe.expire = MagicMock()

        class _PipeCtx:
            async def __aenter__(self):
                return mock_pipe
            async def __aexit__(self, *a):
                return False

        mock_redis = AsyncMock()
        mock_redis.exists = AsyncMock(return_value=0)
        mock_redis.pipeline = MagicMock(return_value=_PipeCtx())

        fast_app.state.redis = mock_redis
        fast_app.add_middleware(AbuseDetectionMiddleware)

        import base64, json as _json, time
        payload = {"sub": "admin-123", "exp": int(time.time()) + 3600}
        payload_b64 = base64.urlsafe_b64encode(_json.dumps(payload).encode()).rstrip(b"=").decode()
        fake_token = f"header.{payload_b64}.sig"

        async with AsyncClient(
            transport=ASGITransport(app=fast_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/v1/credentials/abc-123/revoke",
                headers={"Authorization": f"Bearer {fake_token}"},
            )
        assert resp.status_code == 428
        assert resp.headers.get("x-require-reauth") == "true"
        assert resp.json()["code"] == "REAUTH_REQUIRED"
