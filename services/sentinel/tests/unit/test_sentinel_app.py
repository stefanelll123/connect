"""Unit tests for TASK-037: Sentinel Core Runtime."""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_producer_settings(**kwargs):
    from sentinel.config import SentinelSettings
    return SentinelSettings(
        sentinel_role="producer",
        backend_url="http://backend:8080",
        discovery_url="http://discovery:8000",
        env="dev",
        **kwargs,
    )


def _make_consumer_settings(**kwargs):
    from sentinel.config import SentinelSettings
    return SentinelSettings(
        sentinel_role="consumer",
        discovery_url="http://discovery:8000",
        env="dev",
        **kwargs,
    )


# ---------------------------------------------------------------------------
# SentinelSettings
# ---------------------------------------------------------------------------

class TestSentinelSettings:
    def test_producer_requires_backend_url(self):
        from sentinel.config import SentinelSettings
        from pydantic import ValidationError
        with pytest.raises((ValidationError, ValueError)):
            SentinelSettings(
                sentinel_role="producer",
                discovery_url="http://discovery:8000",
                env="dev",
            )

    def test_consumer_does_not_require_backend_url(self):
        from sentinel.config import SentinelSettings
        settings = SentinelSettings(
            sentinel_role="consumer",
            discovery_url="http://discovery:8000",
            env="dev",
        )
        assert settings.sentinel_role == "consumer"

    def test_sentinel_id_is_auto_generated(self):
        settings = _make_producer_settings()
        assert len(settings.sentinel_id) == 36  # UUID format

    def test_default_env_is_dev(self):
        settings = _make_producer_settings()
        assert settings.env == "dev"


# ---------------------------------------------------------------------------
# App creation — producer mode
# ---------------------------------------------------------------------------

class TestCreateAppProducer:
    @pytest.mark.asyncio
    async def test_producer_health_live(self):
        from sentinel.app import create_app
        settings = _make_producer_settings()
        app = create_app(settings=settings)
        # Inject mock state to bypass lifespan
        app.state.settings = settings
        app.state.http_client = AsyncMock()
        app.state.credential_store = None
        app.state.status_cache = None

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/health/live")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["role"] == "producer"

    @pytest.mark.asyncio
    async def test_producer_has_metrics_endpoint(self):
        from sentinel.app import create_app
        settings = _make_producer_settings()
        app = create_app(settings=settings)
        app.state.settings = settings
        app.state.http_client = AsyncMock()
        app.state.credential_store = None
        app.state.status_cache = None

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/metrics")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# App creation — consumer mode
# ---------------------------------------------------------------------------

class TestCreateAppConsumer:
    @pytest.mark.asyncio
    async def test_consumer_health_live(self):
        from sentinel.app import create_app
        settings = _make_consumer_settings()
        app = create_app(settings=settings)
        app.state.settings = settings
        app.state.http_client = AsyncMock()
        app.state.credential_store = None
        app.state.status_cache = None

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/health/live")
        assert resp.status_code == 200
        data = resp.json()
        assert data["role"] == "consumer"


# ---------------------------------------------------------------------------
# Readiness probe
# ---------------------------------------------------------------------------

class TestSentinelReadiness:
    @pytest.mark.asyncio
    async def test_ready_ok_when_wallet_loaded_and_discovery_up(self):
        from sentinel.app import create_app
        settings = _make_producer_settings()
        app = create_app(settings=settings)
        app.state.settings = settings

        mock_credential_store = MagicMock()
        app.state.credential_store = mock_credential_store

        mock_http = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_http.get = AsyncMock(return_value=mock_resp)
        app.state.http_client = mock_http

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/health/ready")

        data = resp.json()
        assert resp.status_code == 200
        assert data["checks"]["wallet"] == "ok"
        assert data["checks"]["discovery"] == "ok"

    @pytest.mark.asyncio
    async def test_ready_503_when_discovery_unreachable(self):
        from sentinel.app import create_app
        settings = _make_producer_settings()
        app = create_app(settings=settings)
        app.state.settings = settings

        app.state.credential_store = MagicMock()

        import httpx
        mock_http = AsyncMock()
        mock_http.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        app.state.http_client = mock_http

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/health/ready")

        assert resp.status_code == 503
        assert resp.json()["checks"]["discovery"] == "error"


# ---------------------------------------------------------------------------
# SecurityPipeline
# ---------------------------------------------------------------------------

class TestVerificationPipeline:
    @pytest.mark.asyncio
    async def test_missing_bearer_token_fails(self):
        from sentinel.core.security_pipeline import VerificationPipeline
        from starlette.testclient import TestClient
        from starlette.requests import Request as StarletteRequest

        settings = _make_producer_settings()
        pipeline = VerificationPipeline(settings)

        # Construct a minimal mock request
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/test",
            "headers": [],
            "query_string": b"",
        }
        request = StarletteRequest(scope)
        result = await pipeline.verify(request)
        assert not result.passed
        assert "Bearer" in result.reason

    @pytest.mark.asyncio
    async def test_valid_bearer_token_passes(self):
        from sentinel.core.security_pipeline import VerificationPipeline
        from starlette.requests import Request as StarletteRequest

        settings = _make_producer_settings()
        pipeline = VerificationPipeline(settings)

        import base64, json, time
        payload = {"iss": "did:example:123", "exp": int(time.time()) + 3600}
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        token = f"header.{payload_b64}.sig"

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/test",
            "headers": [(b"authorization", f"Bearer {token}".encode())],
            "query_string": b"",
        }
        request = StarletteRequest(scope)
        result = await pipeline.verify(request)
        assert result.passed


class TestSigningPipeline:
    @pytest.mark.asyncio
    async def test_build_vp_returns_jwt_string(self):
        from sentinel.core.security_pipeline import SigningPipeline
        settings = _make_consumer_settings()
        pipeline = SigningPipeline(settings)

        vp = await pipeline.build_vp(descriptor={"service_did": "did:example:svc"})
        assert isinstance(vp, str)
        parts = vp.split(".")
        assert len(parts) == 3  # JWT structure


# ---------------------------------------------------------------------------
# Inbound proxy (producer mode)
# ---------------------------------------------------------------------------

class TestInboundProxy:
    @pytest.mark.asyncio
    async def test_inbound_returns_401_without_token(self):
        from sentinel.app import create_app
        settings = _make_producer_settings()
        app = create_app(settings=settings)
        app.state.settings = settings
        app.state.http_client = AsyncMock()
        app.state.credential_store = None
        app.state.status_cache = None

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/api/data", content=b"test")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_inbound_proxies_to_backend_with_valid_token(self):
        from sentinel.app import create_app
        import httpx

        settings = _make_producer_settings()
        app = create_app(settings=settings)
        app.state.settings = settings
        app.state.credential_store = None
        app.state.status_cache = None

        mock_upstream_resp = MagicMock()
        mock_upstream_resp.status_code = 200
        mock_upstream_resp.content = b'{"upstream":"ok"}'
        mock_upstream_resp.headers = MagicMock()
        mock_upstream_resp.headers.multi_items = MagicMock(return_value=[
            ("content-type", "application/json")
        ])

        mock_http = AsyncMock()
        mock_http.request = AsyncMock(return_value=mock_upstream_resp)
        app.state.http_client = mock_http

        import base64, json, time
        payload = {"iss": "did:example:123", "exp": int(time.time()) + 100}
        pb64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        token = f"h.{pb64}.s"

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/data",
                content=b"body",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Outbound (consumer mode)
# ---------------------------------------------------------------------------

class TestOutboundRoute:
    @pytest.mark.asyncio
    async def test_outbound_resolves_descriptor_and_forwards(self):
        from sentinel.app import create_app
        import httpx

        settings = _make_consumer_settings()
        app = create_app(settings=settings)
        app.state.settings = settings
        app.state.credential_store = None
        app.state.status_cache = None

        # Mock: first call resolves descriptor, second call is the forward
        descriptor_resp = MagicMock()
        descriptor_resp.status_code = 200
        descriptor_resp.json = MagicMock(return_value={
            "service_did": "did:example:svc",
            "inbound_url": "http://producer:8080/inbound",
        })

        upstream_resp = MagicMock()
        upstream_resp.status_code = 200
        upstream_resp.content = b'{"result":"ok"}'
        upstream_resp.headers = MagicMock()
        upstream_resp.headers.get = MagicMock(return_value="application/json")

        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=descriptor_resp)
        mock_http.post = AsyncMock(return_value=upstream_resp)
        app.state.http_client = mock_http

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/outbound/my-service", json={"key": "val"})

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_outbound_404_when_service_not_found(self):
        from sentinel.app import create_app

        settings = _make_consumer_settings()
        app = create_app(settings=settings)
        app.state.settings = settings
        app.state.credential_store = None
        app.state.status_cache = None

        not_found_resp = MagicMock()
        not_found_resp.status_code = 404

        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=not_found_resp)
        app.state.http_client = mock_http

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/outbound/nonexistent-service", json={})

        assert resp.status_code == 404
