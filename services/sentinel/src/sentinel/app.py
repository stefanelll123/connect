"""FastAPI application factory for the Sentinel Node (TASK-037).

Usage::

    from sentinel.app import create_app
    app = create_app()  # reads SENTINEL_ROLE from env
"""
from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles

from sentinel.clients.ds_client import DiscoveryClient
from sentinel.clients.sync_loop import DiscoverySyncLoop
from sentinel.config import SentinelSettings, get_settings

logger = logging.getLogger(__name__)


def _build_descriptor_jws(settings: SentinelSettings) -> str:
    """Build and sign a fresh service descriptor JWS for one publish cycle."""
    from datetime import datetime, timedelta, timezone

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from common.crypto.jws import sign_jws
    from sentinel.wallet.key_manager import Wallet

    passphrase = os.environ.get("SENTINEL_PASSPHRASE", "").encode()
    wallet = Wallet(Path(settings.sentinel_home) / "store")
    wallet.load(passphrase)

    now = datetime.now(timezone.utc)
    did = settings.sentinel_did
    payload = {
        "service_id": settings.service_id,
        "env": settings.env,
        "producer_sentinel_did": did,
        "valid_from": now.isoformat(),
        "valid_until": (now + timedelta(seconds=300)).isoformat(),
        "published_at": now.isoformat(),
        "endpoints": [
            {
                "url": settings.inbound_url.rstrip("/"),
                "protocol": "http",
                "weight": 1,
                "health_status": "active",
            }
        ],
    }
    private_key = Ed25519PrivateKey.from_private_bytes(wallet._private_key.reveal())  # type: ignore[union-attr]
    kid = f"{did}#{did.split(':', 2)[-1]}"
    return sign_jws(payload, private_key, kid=kid)


# Number of retries for the shared HTTPX client
_MAX_RETRIES = 3
_MAX_CONNECTIONS = 100


def _build_transport(max_retries: int) -> httpx.AsyncHTTPTransport:
    return httpx.AsyncHTTPTransport(retries=max_retries)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: SentinelSettings = app.state.settings
    app.state.start_time = time.time()

    # ------------------------------------------------------------------ #
    # Shared HTTPX client                                                 #
    # ------------------------------------------------------------------ #
    transport = _build_transport(settings.max_retries)
    client = httpx.AsyncClient(
        transport=transport,
        limits=httpx.Limits(max_connections=_MAX_CONNECTIONS),
        timeout=httpx.Timeout(settings.request_timeout_seconds),
        follow_redirects=False,
    )
    app.state.http_client = client
    logger.info("Shared HTTPX client created (max_connections=%d)", _MAX_CONNECTIONS)

    # ------------------------------------------------------------------ #
    # Wallet / credential store                                           #
    # ------------------------------------------------------------------ #
    try:
        from sentinel.wallet.credential_store import CredentialStore
        from sentinel.wallet.status_cache import StatusCache
        from sentinel.startup.permission_check import check_store_permissions

        store_root = Path(settings.sentinel_home) / "store"
        store_root.mkdir(parents=True, exist_ok=True)

        # Only enforce strict permissions outside dev
        if settings.env != "dev":
            check_store_permissions(store_root)

        app.state.credential_store = CredentialStore(store_root / "credentials")
        app.state.status_cache = StatusCache(store_root / "status_cache")
        logger.info("Wallet initialised at %s", store_root)
    except Exception as exc:
        logger.warning("Wallet init failed (non-fatal in dev): %s", exc)
        app.state.credential_store = None
        app.state.status_cache = None

    # ------------------------------------------------------------------ #
    # Load signing key bytes from wallet (both roles need it)            #
    # ------------------------------------------------------------------ #
    try:
        from sentinel.wallet.key_manager import Wallet
        passphrase = os.environ.get("SENTINEL_PASSPHRASE", "").encode()
        wallet = Wallet(Path(settings.sentinel_home) / "store")
        wallet.load(passphrase)
        app.state.consumer_key_bytes = wallet._private_key.reveal()  # type: ignore[union-attr]
        logger.info("Wallet signing key loaded for role=%s", settings.sentinel_role)
    except Exception as exc:
        logger.warning("Could not load wallet signing key: %s", exc)
        app.state.consumer_key_bytes = b"\x00" * 32

    # ------------------------------------------------------------------ #
    # OTel tracing                                                        #
    # ------------------------------------------------------------------ #
    if settings.otlp_endpoint:
        try:
            from sentinel.telemetry import init_tracing
            init_tracing(settings, app)
        except Exception as exc:
            logger.warning("OTel init failed: %s", exc)

    # ------------------------------------------------------------------ #
    # Trust layer client (chain-backed issuer/policy/anchor reads)       #
    # ------------------------------------------------------------------ #
    try:
        from common.trust_layer import OutagePolicy, TrustLayerClient

        trust_client = TrustLayerClient(
            chain_client=None,  # chain fetch stubs until chain wiring is complete
            outage_policy=OutagePolicy.FAIL_CLOSED,
        )
        app.state.trust_client = trust_client
        logger.info("TrustLayerClient initialised (chain_client=None, cache-only mode)")
    except Exception as exc:
        logger.warning("TrustLayerClient init failed (non-fatal): %s", exc)
        app.state.trust_client = None

    # ------------------------------------------------------------------ #
    # Revocation manager + background status-list refresher              #
    # ------------------------------------------------------------------ #
    try:
        import asyncio as _asyncio

        from common.revocation.checker import StatusListCache
        from common.revocation.manager import RevocationManager
        from common.revocation.models import StalenessMode, StalenessPolicy
        from common.revocation.refresher import StatusListRefresher

        _mode_map = {
            "fail_closed": StalenessMode.FAIL_CLOSED,
            "degrade": StalenessMode.FAIL_OPEN_DEGRADED,
            "use_cache": StalenessMode.ALLOW_WITH_WARNING,
        }
        staleness_mode = _mode_map.get(
            settings.revocation_outage_policy, StalenessMode.FAIL_CLOSED
        )
        staleness_policy = StalenessPolicy(
            delta_seconds=settings.status_list_delta_seconds,
            mode=staleness_mode,
        )

        revocation_manager = RevocationManager(
            status_list_cache=StatusListCache(),
            trust_client=app.state.trust_client,
            discovery_http_client=client,
            staleness_policy=staleness_policy,
            env=settings.env,
        )
        app.state.revocation_manager = revocation_manager

        refresher = StatusListRefresher(
            manager=revocation_manager,
            delta_seconds=float(settings.status_list_delta_seconds),
            trust_client=app.state.trust_client,
        )
        app.state.status_list_refresher = refresher
        app.state.status_list_refresher_task = _asyncio.create_task(refresher.run())
        logger.info(
            "RevocationManager initialised (policy=%s delta=%ds)",
            settings.revocation_outage_policy,
            settings.status_list_delta_seconds,
        )
    except Exception as exc:
        logger.warning("RevocationManager init failed (non-fatal): %s", exc)
        app.state.revocation_manager = None
        app.state.status_list_refresher = None
        app.state.status_list_refresher_task = None

    # ------------------------------------------------------------------ #
    # Discovery client + enrollment + sync loop                          #
    # ------------------------------------------------------------------ #
    from sentinel.clients.ds_client import _load_discovery_state

    sentinel_home = settings.sentinel_home
    persisted_id, persisted_token = _load_discovery_state(sentinel_home)

    ds_client = DiscoveryClient(
        base_url=settings.discovery_url,
        sentinel_id=persisted_id,
        sentinel_did=settings.sentinel_did,
        service_id=settings.service_id,
        env=settings.env,
        http_client=client,
    )
    # Pre-load persisted token so sync calls work immediately (before renewal)
    if persisted_token:
        ds_client._token_manager.set(persisted_token)
        logger.info("Loaded persisted discovery auth token (sentinel_id=%s)", ds_client.sentinel_id)

    app.state.ds_client = ds_client

    enrollment_token = os.environ.get("ENROLLMENT_TOKEN", "").strip()
    if enrollment_token:
        logger.info("ENROLLMENT_TOKEN found — starting onboarding handshake")
        try:
            bundle = await ds_client.onboard(enrollment_token)
            logger.info(
                "Onboarding complete: sentinel_id=%s", bundle.sentinel_id or "(unchanged)"
            )
            # Store initial credential if issued by Discovery during onboarding
            credential_store = getattr(app.state, "credential_store", None)
            master_key = getattr(app.state, "consumer_key_bytes", None)
            if (
                credential_store is not None
                and master_key is not None
                and bundle.initial_credentials
            ):
                for _vc_jwt in bundle.initial_credentials:
                    try:
                        credential_store.store(_vc_jwt, master_key=master_key)
                        logger.info("Stored credential from onboarding bundle")
                    except Exception as _store_exc:
                        logger.warning("Failed to store initial credential: %s", _store_exc)
        except Exception as exc:
            logger.error("Onboarding failed: %s — continuing without Discovery link", exc)
    else:
        logger.info(
            "No ENROLLMENT_TOKEN — skipping onboarding (sentinel_id=%s)",
            ds_client.sentinel_id,
        )

    # ------------------------------------------------------------------ #
    # Descriptor cache (consumer) / Descriptor publisher (producer)      #
    # ------------------------------------------------------------------ #
    descriptor_builder = None
    if settings.sentinel_role == "consumer":
        from sentinel.consumer.descriptor_cache import DescriptorCache
        from sentinel.consumer.endpoint_selector import EndpointSelector
        app.state.descriptor_cache = DescriptorCache(discovery_client=ds_client)
        app.state.endpoint_selector = EndpointSelector()
        logger.info("DescriptorCache initialised with DiscoveryClient")
    else:  # producer
        if settings.inbound_url and settings.service_id:
            def _builder(_s=settings):
                try:
                    return _build_descriptor_jws(_s)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Descriptor build failed: %s", exc)
                    return ""
            descriptor_builder = _builder
            logger.info(
                "Descriptor publisher configured for service_id=%s env=%s",
                settings.service_id, settings.env,
            )
        else:
            logger.warning("INBOUND_URL or SERVICE_ID not set — descriptor will not be published")

        # ------------------------------------------------------------------ #
        # Session exchange infrastructure (producer only)                    #
        # ------------------------------------------------------------------ #
        try:
            redis_client = None
            if settings.redis_url:
                import redis.asyncio as aioredis  # type: ignore[import]
                redis_client = aioredis.from_url(
                    settings.redis_url, encoding="utf-8", decode_responses=False
                )
            from sentinel.producer.nonce_store import NonceStore
            from sentinel.producer.session import SessionTokenIssuer

            nonce_store = NonceStore(
                redis_client=redis_client,
                ttl=settings.session_nonce_ttl,
            )
            session_issuer = SessionTokenIssuer(
                service_did=settings.sentinel_did or "",
                private_key_bytes=getattr(app.state, "consumer_key_bytes", b"\x00" * 32),
                service_id=settings.service_id,
                env=settings.env,
                token_ttl=settings.session_token_ttl,
            )
            from common.security_envelope.replay_cache import ReplayCache
            app.state.nonce_store = nonce_store
            app.state.session_issuer = session_issuer
            app.state.replay_cache = ReplayCache(redis_client=redis_client)
            logger.info(
                "Session exchange initialised: nonce_ttl=%ds token_ttl=%ds redis=%s",
                settings.session_nonce_ttl,
                settings.session_token_ttl,
                "yes" if redis_client else "no (in-memory fallback)",
            )
        except Exception as exc:
            logger.warning("Session exchange init failed (non-fatal): %s", exc)
            app.state.nonce_store = None
            app.state.session_issuer = None

    sync_loop = DiscoverySyncLoop(
        client=ds_client,
        instance_id=settings.sentinel_id,
        version="0.1.0",
        descriptor_builder=descriptor_builder,
        descriptor_refresh_interval=120.0,
        credential_store=getattr(app.state, "credential_store", None),
        master_key=getattr(app.state, "consumer_key_bytes", None),
    )
    app.state.sync_loop = sync_loop
    await sync_loop.start()

    yield  # ← application runs here

    # ------------------------------------------------------------------ #
    # Graceful shutdown                                                   #
    # ------------------------------------------------------------------ #
    logger.info("Sentinel shutting down — draining connections...")
    if getattr(app.state, "status_list_refresher", None):
        app.state.status_list_refresher.stop()
        task = getattr(app.state, "status_list_refresher_task", None)
        if task and not task.done():
            task.cancel()
            try:
                import asyncio as _asyncio
                await _asyncio.shield(task)
            except Exception:
                pass
        logger.info("StatusListRefresher stopped")
    if getattr(app.state, "sync_loop", None):
        await app.state.sync_loop.stop()
    if getattr(app.state, "http_client", None):
        await app.state.http_client.aclose()
        logger.info("HTTPX client closed")


def create_app(settings: SentinelSettings | None = None) -> FastAPI:
    """Create and configure the Sentinel FastAPI application."""
    if settings is None:
        settings = get_settings()

    docs_url = "/docs" if settings.env != "prod" else None
    openapi_url = "/openapi.json" if settings.env != "prod" else None

    app = FastAPI(
        title=f"Sentinel Node ({settings.sentinel_role.capitalize()})",
        version="0.1.0",
        docs_url=docs_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )
    app.state.settings = settings

    # ------------------------------------------------------------------ #
    # Routers — role-conditional                                          #
    # ------------------------------------------------------------------ #
    from sentinel.api.health import router as health_router
    app.include_router(health_router)

    from sentinel.api.enrollment import router as enrollment_router
    app.include_router(enrollment_router)

    # ------------------------------------------------------------------ #
    # UI (local web interface) — must be registered BEFORE catch-all     #
    # ------------------------------------------------------------------ #
    from sentinel.ui.router import ui_router
    app.include_router(ui_router)
    _static_dir = Path(__file__).parent / "ui" / "static"
    if _static_dir.is_dir():
        app.mount("/ui/static", StaticFiles(directory=str(_static_dir)), name="ui-static")
    logger.info("Registered UI router")

    # ------------------------------------------------------------------ #
    # Prometheus metrics endpoint (register BEFORE catch-all routes)     #
    # ------------------------------------------------------------------ #
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
        from starlette.responses import Response

        @app.get("/metrics", include_in_schema=False)
        async def prometheus_metrics():
            return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
    except ImportError:
        pass

    if settings.sentinel_role == "producer":
        from sentinel.api.inbound import router as inbound_router
        from sentinel.producer.routes.session import router as session_router
        # Session exchange routes must be registered BEFORE the inbound catch-all
        app.include_router(session_router)
        app.include_router(inbound_router)
        logger.info("Registered session-exchange and inbound (producer) routers")

    if settings.sentinel_role == "consumer":
        from sentinel.consumer.routes.outbound import router as outbound_router
        app.include_router(outbound_router)
        logger.info("Registered outbound (consumer) router")

    # ------------------------------------------------------------------ #
    # Middleware                                                          #
    # ------------------------------------------------------------------ #
    # Read UI auth config eagerly so middleware has correct values even
    # when env vars are changed after create_app() returns.
    import os as _os
    _ui_auth = _os.getenv("SENTINEL_UI_AUTH", "none")
    _ui_password = _os.getenv("SENTINEL_UI_PASSWORD", "")
    _ui_token = _os.getenv("SENTINEL_UI_TOKEN", "")

    # UI auth + CSRF + security headers (innermost — wraps /ui/* routes)
    from sentinel.ui.access_control import UIAuthMiddleware
    app.add_middleware(
        UIAuthMiddleware,
        auth_mode=_ui_auth,
        password=_ui_password,
        token=_ui_token,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=False,
    )
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # Non-loopback + auth=none startup warning
    import os as _os
    _ui_host = _os.getenv("SENTINEL_UI_HOST", "127.0.0.1")
    _ui_auth = _os.getenv("SENTINEL_UI_AUTH", "none").lower()
    if _ui_host != "127.0.0.1" and _ui_auth == "none":
        logger.critical(
            "event=ui_insecure_exposure host=%s auth=none. "
            "Set SENTINEL_UI_AUTH=token and SENTINEL_UI_TOKEN to protect the UI.",
            _ui_host,
        )

    return app
