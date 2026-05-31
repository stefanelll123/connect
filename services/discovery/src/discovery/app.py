"""FastAPI application factory for the Discovery Service."""
from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel
from starlette.responses import Response

from discovery.config import DiscoverySettings, get_settings
from discovery.middleware.abuse_detection import AbuseDetectionMiddleware
from discovery.middleware.idempotency import IdempotencyMiddleware
from discovery.middleware.logging import RequestLoggingMiddleware
from discovery.middleware.rate_limit import RateLimitMiddleware
from discovery.middleware.request_id import RequestIDMiddleware
from discovery.middleware.request_limits import RequestLimitsMiddleware
from discovery.middleware.secure_headers import SecureHeadersMiddleware

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# RFC 7807 Problem+JSON response model
# ---------------------------------------------------------------------------

class ProblemDetail(BaseModel):
    type: str
    title: str
    status: int
    detail: str
    instance: str
    request_id: str = ""
    code: str = ""


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app(settings: DiscoverySettings | None = None) -> FastAPI:
    """Create and configure a FastAPI application instance.

    Args:
        settings: Optional pre-built settings object.  When *None* the
                  settings are loaded from environment variables via
                  :func:`discovery.config.get_settings`.  Pass an explicit
                  instance during testing to avoid hitting env vars.
    """
    if settings is None:
        settings = get_settings()

    # In production the OpenAPI UI is disabled to reduce attack surface.
    docs_url = "/docs" if settings.env != "prod" else None
    openapi_url = "/openapi.json" if settings.env != "prod" else None

    # ------------------------------------------------------------------ #
    # Lifespan: startup / shutdown side-effects                           #
    # ------------------------------------------------------------------ #
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # ---- startup ----
        from discovery.db.session import get_engine

        try:
            engine = get_engine(settings.database_url.get_secret_value())
            app.state.db_engine = engine
            logger.info("Database engine initialised")
        except Exception as exc:
            logger.warning("Database engine init failed: %s", exc)
            app.state.db_engine = None

        try:
            import redis.asyncio as aioredis

            redis_client = aioredis.from_url(
                settings.redis_url.get_secret_value(),
                encoding="utf-8",
                decode_responses=True,
            )
            app.state.redis = redis_client
            logger.info("Redis client created")
        except Exception as exc:
            logger.warning("Redis client init failed: %s", exc)
            app.state.redis = None

        # ---- Chain integration startup ----
        try:
            from discovery.chain.client import (
                ChainClient,
                IssuerRegistryClient,
                ServiceRegistryClient,
                StatusRegistryClient,
            )
            from discovery.services.chain_policy_cache import ChainPolicyCache, set_chain_policy_cache
            from discovery.services.chain_indexer import ChainIndexer, set_chain_indexer

            chain_client: ChainClient | None = None
            issuer_client: IssuerRegistryClient | None = None
            status_client: StatusRegistryClient | None = None
            service_registry_client: ServiceRegistryClient | None = None

            if settings.blockchain_integration:
                chain_client = ChainClient(
                    settings.blockchain_rpc_url,
                    timeout_seconds=settings.chain_rpc_timeout_seconds,
                )
                if settings.contract_issuer_registry:
                    issuer_client = IssuerRegistryClient(
                        chain_client, settings.contract_issuer_registry
                    )
                if settings.contract_status_registry:
                    # In dev, no signing key — anchoring is best-effort only
                    anchor_key = os.environ.get("CHAIN_ANCHOR_PRIVATE_KEY", "")
                    if anchor_key:
                        status_client = StatusRegistryClient(
                            chain_client, settings.contract_status_registry, anchor_key
                        )
                if settings.contract_service_registry and settings.register_service_on_chain:
                    svc_key = os.environ.get("CHAIN_ANCHOR_PRIVATE_KEY", "")
                    if svc_key:
                        service_registry_client = ServiceRegistryClient(
                            chain_client, settings.contract_service_registry, svc_key
                        )

            cache = ChainPolicyCache(settings, issuer_client=issuer_client)
            await cache.load()
            set_chain_policy_cache(cache)

            indexer = ChainIndexer(settings, chain_client=chain_client)
            available = await indexer.check_availability()
            if available:
                from discovery.db.session import get_session_factory as _gsf
                if app.state.db_engine is not None:
                    async with _gsf(app.state.db_engine)() as _s:
                        await indexer.load_last_block(_s)
            set_chain_indexer(indexer)
            app.state.chain_client = chain_client
            app.state.issuer_registry_client = issuer_client
            app.state.status_registry_client = status_client
            app.state.service_registry_client = service_registry_client

            # Expose issuer client to credential_issuer module
            from discovery.services.credential_issuer import set_issuer_registry_client
            set_issuer_registry_client(issuer_client)

            if settings.chain_required_at_startup and not available:
                raise RuntimeError("Chain RPC unavailable but chain_required_at_startup=True")

            logger.info("Chain integration initialised (available=%s)", available)

            # NOTE: Discovery DID registration in IssuerRegistry is intentionally
            # NOT performed here. Use the Governance Admin app (http://localhost:8080)
            # to register the DID via Bootstrap + Issuers pages before starting Discovery.

            # Start background chain poll loop
            if available:
                import asyncio as _asyncio
                from discovery.db.session import get_session_factory

                async def _chain_poll_loop():
                    session_factory = get_session_factory(app.state.db_engine)
                    while True:
                        await _asyncio.sleep(30)
                        try:
                            async with session_factory() as session:
                                count = await indexer.poll_once(session)
                                if count:
                                    logger.info("Chain indexer: %d new events", count)
                        except Exception as exc:
                            logger.error("Chain poll loop error: %s", exc)

                _asyncio.create_task(_chain_poll_loop())
                logger.info("Chain poll loop started (interval=30s)")

            # Start service chain sync retry worker (independent of indexer availability)
            if settings.register_service_on_chain and service_registry_client is not None:
                import asyncio as _asyncio
                from discovery.db.session import get_session_factory
                from discovery.tasks.service_chain_sync_worker import sync_pending_service_registrations

                async def _service_chain_sync_loop():
                    session_factory = get_session_factory(app.state.db_engine)
                    while True:
                        await _asyncio.sleep(60)
                        logger.info("Starting service chain sync job")
                        try:
                            async with session_factory() as session:
                                count = await sync_pending_service_registrations(
                                    session, settings, app.state.service_registry_client
                                )
                                if count:
                                    logger.info("Service chain sync: %d registered", count)
                        except Exception as exc:
                            logger.error("Service chain sync loop error: %s", exc)

                _asyncio.create_task(_service_chain_sync_loop())
                logger.info("Service chain sync worker started (interval=60s)")

            # Start anchor retry worker (StatusAnchorPublished events)
            if settings.anchor_status_lists and status_client is not None:
                import asyncio as _asyncio
                from discovery.db.session import get_session_factory
                from discovery.tasks.anchor_retry_worker import anchor_pending_status_lists

                async def _anchor_retry_loop():
                    session_factory = get_session_factory(app.state.db_engine)
                    while True:
                        await _asyncio.sleep(60)
                        logger.debug("Starting anchor retry job")
                        try:
                            async with session_factory() as session:
                                count = await anchor_pending_status_lists(
                                    session, settings, app.state.status_registry_client
                                )
                                if count:
                                    logger.info("Anchor retry: %d status list(s) anchored", count)
                        except Exception as exc:
                            logger.error("Anchor retry loop error: %s", exc)

                _asyncio.create_task(_anchor_retry_loop())
                logger.info("Anchor retry worker started (interval=60s)")

        except Exception as exc:
            logger.warning("Chain integration init skipped: %s", exc)

        # ---- OTel tracing ----
        if settings.otlp_endpoint:
            try:
                from discovery.telemetry.tracing import init_tracing
                init_tracing(settings, app)
                logger.info("OpenTelemetry tracing initialised → %s", settings.otlp_endpoint)
            except Exception as exc:
                logger.warning("OTel init failed (non-fatal): %s", exc)

        # ---- Heartbeat status monitor ----
        import asyncio
        from discovery.tasks.heartbeat_monitor import run_status_sweep
        from discovery.db.session import get_session_factory

        async def _status_sweep_loop():
            while True:
                await asyncio.sleep(60)
                try:
                    engine = getattr(app.state, "db_engine", None)
                    if engine is None:
                        continue
                    factory = get_session_factory(engine)
                    async with factory() as session:
                        counts = await run_status_sweep(session)
                        await session.commit()
                    logger.debug("Status sweep: %s", counts)
                except Exception as exc:
                    logger.warning("Status sweep error: %s", exc)

        _sweep_task = asyncio.create_task(_status_sweep_loop())
        app.state.sweep_task = _sweep_task
        logger.info("Heartbeat status monitor started (interval=60s)")

        yield

        # ---- shutdown ----
        _sweep_task.cancel()
        if getattr(app.state, "db_engine", None):
            await app.state.db_engine.dispose()
            logger.info("Database engine disposed")
        if getattr(app.state, "redis", None):
            await app.state.redis.aclose()
            logger.info("Redis connection closed")

    # ------------------------------------------------------------------ #
    # FastAPI instance                                                    #
    # ------------------------------------------------------------------ #
    app = FastAPI(
        title="Discovery Service",
        version="0.1.0",
        docs_url=docs_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )

    # Store settings on app state — dependencies read from here.
    app.state.settings = settings

    # ------------------------------------------------------------------ #
    # Prometheus metrics endpoint (TASK-036)                             #
    # ------------------------------------------------------------------ #
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        @app.get("/metrics", include_in_schema=False)
        async def prometheus_metrics():
            return Response(
                content=generate_latest(),
                media_type=CONTENT_TYPE_LATEST,
            )
    except ImportError:
        pass

    # ------------------------------------------------------------------ #
    # Routers                                                             #
    # ------------------------------------------------------------------ #
    from discovery.api.v1.routers import (
        apps,
        audit,
        auth,
        chain,
        config_bundles,
        credentials,
        descriptors,
        endpoints,
        enrollments,
        health,
        registry,
        revocations,
        sentinel_credentials,
        sentinels,
        services,
        status_lists,
    )

    # Health probes are at /health/* (no versioned prefix — K8s requirement)
    app.include_router(health.router)

    # Public status list endpoint (no /api/v1 prefix — VPN-free access required)
    app.include_router(status_lists.router)

    # Admin status-lists endpoint (versioned, auth-protected)
    app.include_router(status_lists.admin_router, prefix="/api/v1")

    # Versioned API
    for router_mod in (
        auth, apps, services, sentinels, enrollments,
        credentials, revocations, config_bundles, sentinel_credentials,
        chain, audit, descriptors, registry, endpoints,
    ):
        app.include_router(router_mod.router, prefix="/api/v1")

    # ------------------------------------------------------------------ #
    # Exception handlers — RFC 7807 Problem+JSON                         #
    # ------------------------------------------------------------------ #

    def _make_problem(
        request: Request,
        status: int,
        title: str,
        detail: str,
        error_slug: str,
        code: str = "",
    ) -> Response:
        request_id = getattr(request.state, "request_id", "")
        body = ProblemDetail(
            type=f"https://discovery.sentinel.example/errors/{error_slug}",
            title=title,
            status=status,
            detail=detail,
            instance=str(request.url.path),
            request_id=request_id,
            code=code,
        )
        return Response(
            content=json.dumps(body.model_dump()),
            status_code=status,
            media_type="application/problem+json",
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError):
        return _make_problem(request, 422, "Validation Error", str(exc.errors()), "validation-error")

    @app.exception_handler(HTTPException)
    async def _http_handler(request: Request, exc: HTTPException):
        _TITLES = {
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
            404: "Not Found", 409: "Conflict", 422: "Unprocessable Entity",
            429: "Too Many Requests", 500: "Internal Server Error",
            503: "Service Unavailable",
        }
        title = _TITLES.get(exc.status_code, "Error")
        if isinstance(exc.detail, dict):
            # Structured error with {code, message} from our own raise sites
            error_code = exc.detail.get("code", "error")
            detail = exc.detail.get("message", title)
            slug = error_code.lower().replace("_", "-")
        else:
            detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
            slug = title.lower().replace(" ", "-")
            error_code = ""
        return _make_problem(request, exc.status_code, title, detail, slug, code=error_code)

    @app.exception_handler(Exception)
    async def _generic_handler(request: Request, exc: Exception):
        # Stack trace MUST NOT appear in the response — log it internally only.
        request_id = getattr(request.state, "request_id", "")
        logger.exception("Unhandled exception [request_id=%s]: %s", request_id, exc)
        return _make_problem(
            request, 500, "Internal Server Error",
            "An unexpected error occurred.", "internal-error",
        )

    # ------------------------------------------------------------------ #
    # Middleware stack                                                    #
    # Starlette applies middleware in LIFO order (last added = runs first #
    # in the request direction).  We add in reverse of our desired order. #
    #                                                                     #
    # Request  →  TrustedHost → RequestID → Logging → GZip               #
    #          → SecureHeaders → CORS → endpoint                         #
    # ------------------------------------------------------------------ #

    # CORS (outermost — first to see the request)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_cors_origins,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Request-ID",
            "X-Idempotency-Key",
        ],
        allow_credentials=True,
        expose_headers=["X-Request-ID", "X-Idempotency-Used", "Retry-After"],
    )

    # Abuse detection (before rate limiting so floods are caught early)
    app.add_middleware(AbuseDetectionMiddleware)
    # Idempotency (before rate limiting so cached replies don\'t count against limit)
    app.add_middleware(IdempotencyMiddleware)
    # Rate limiting
    app.add_middleware(RateLimitMiddleware, fail_open=settings.rate_limit_fail_open)
    # Request size limits (cheap — runs before body parsing)
    app.add_middleware(RequestLimitsMiddleware)
    # Security response headers
    app.add_middleware(SecureHeadersMiddleware)
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RequestIDMiddleware)

    # TrustedHostMiddleware only in non-dev to avoid localhost rejections
    if settings.env != "dev":
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

    return app
