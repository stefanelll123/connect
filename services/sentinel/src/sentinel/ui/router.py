"""FastAPI router for the Sentinel local UI (TASK-054 / TASK-055)."""
from __future__ import annotations

import asyncio
import hashlib
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sentinel.ui.live_logs import _MAX_SSE_CONNECTIONS, log_event_stream

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

ui_router = APIRouter(prefix="/ui", tags=["ui"])


@ui_router.get("", include_in_schema=False)
@ui_router.get("/", include_in_schema=False)
async def ui_root() -> RedirectResponse:
    return RedirectResponse(url="/ui/enrollment")

# Security response headers applied to every UI page
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline';"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
}


def _secure(response: HTMLResponse) -> HTMLResponse:
    for k, v in _SECURITY_HEADERS.items():
        response.headers[k] = v
    return response


def _sha256_trunc(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:length]


def _fmt_exp(ts) -> str:
    """Format a Unix timestamp as a UTC datetime string, or '\u2014' if absent."""
    import datetime
    if ts is None:
        return "\u2014"
    try:
        return datetime.datetime.utcfromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(ts)


# --------------------------------------------------------------------------- #
# DID identity page                                                            #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# Enrollment page                                                              #
# --------------------------------------------------------------------------- #

@ui_router.get("/enrollment", response_class=HTMLResponse)
async def ui_enrollment(request: Request) -> HTMLResponse:
    settings = request.app.state.settings
    ds_client = getattr(request.app.state, "ds_client", None)
    sentinel_id = ""
    enrolled = False
    if ds_client is not None:
        sentinel_id = getattr(ds_client, "sentinel_id", "") or ""
        enrolled = bool(sentinel_id)

    ctx: dict[str, Any] = {
        "enrolled": enrolled,
        "sentinel_id": sentinel_id,
        "discovery_url": settings.discovery_url,
        "service_id": settings.service_id,
        "role": settings.sentinel_role,
        "env": settings.env,
    }
    resp = templates.TemplateResponse(request, "enrollment.html", ctx)
    return _secure(resp)


# --------------------------------------------------------------------------- #
# DID identity page                                                            #
# --------------------------------------------------------------------------- #

@ui_router.get("/did", response_class=HTMLResponse)
async def ui_did(request: Request) -> HTMLResponse:
    settings = request.app.state.settings
    start_time = getattr(request.app.state, "start_time", None)
    uptime = int(time.time() - start_time) if start_time else 0

    did = settings.sentinel_did or "(not configured)"
    did_hash = _sha256_trunc(settings.sentinel_did) if settings.sentinel_did else ""

    ctx: dict[str, Any] = {
        "did": did,
        "did_hash": did_hash,
        "service_id": settings.service_id,
        "env": settings.env,
        "role": settings.sentinel_role,
        "instance_id": settings.sentinel_id,
        "uptime": uptime,
        "key_fingerprint": getattr(request.app.state, "key_fingerprint", ""),
    }
    resp = templates.TemplateResponse(request, "did.html", ctx)
    return _secure(resp)


# --------------------------------------------------------------------------- #
# Credentials page                                                             #
# --------------------------------------------------------------------------- #

@ui_router.get("/credentials", response_class=HTMLResponse)
async def ui_credentials(request: Request) -> HTMLResponse:
    settings = request.app.state.settings
    credential_store = getattr(request.app.state, "credential_store", None)
    master_key = getattr(request.app.state, "consumer_key_bytes", None)
    credentials: list[dict[str, Any]] = []
    raw_credentials: list[dict[str, Any]] = []

    if credential_store is not None:
        try:
            raw = credential_store.list_all(master_key=master_key)
            for vc in raw:
                payload = vc.get("payload", vc)
                exp = payload.get("exp")
                nbf = payload.get("nbf")
                vc_type = payload.get("type", ["VC"])
                audience = payload.get("aud", "")
                status_list_id = payload.get("status", {}).get("id", "")
                issuer = payload.get("iss", "")
                jti = payload.get("jti", "")
                is_expired = exp is not None and float(exp) < time.time()
                credentials.append(
                    {
                        "type": vc_type[-1] if isinstance(vc_type, list) else vc_type,
                        "exp": _fmt_exp(exp),
                        "aud": audience,
                        "env": payload.get("env", ""),
                        "status": "expired" if is_expired else "active",
                        "issuer_did_hash": _sha256_trunc(issuer) if issuer else "",
                        "jti_hash": _sha256_trunc(jti) if jti else "",
                        "status_list_id": status_list_id,
                        "nbf": nbf,
                    }
                )
        except Exception:
            pass

        if settings.env == "dev":
            try:
                for slug, jwt_string in credential_store.get_all_raw_with_type(master_key=master_key):
                    import base64 as _b64
                    parts = jwt_string.split(".")
                    if len(parts) == 3:
                        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                        import json as _json
                        payload = _json.loads(_b64.urlsafe_b64decode(padded))
                    else:
                        payload = {}
                    vc_type = payload.get("type", ["VC"])
                    raw_credentials.append(
                        {
                            "slug": slug,
                            "type": vc_type[-1] if isinstance(vc_type, list) else vc_type,
                            "jti": payload.get("jti", ""),
                            "iss": payload.get("iss", ""),
                            "sub": payload.get("sub", ""),
                            "aud": payload.get("aud", ""),
                            "env": payload.get("env", ""),
                            "exp": _fmt_exp(payload.get("exp")),
                            "nbf": payload.get("nbf"),
                            "raw_jwt": jwt_string,
                        }
                    )
            except Exception:
                pass

    ctx: dict[str, Any] = {
        "credentials": credentials,
        "is_dev": settings.env == "dev",
        "raw_credentials": raw_credentials,
    }
    resp = templates.TemplateResponse(request, "credentials.html", ctx)
    return _secure(resp)


# --------------------------------------------------------------------------- #
# Health page                                                                  #
# --------------------------------------------------------------------------- #

@ui_router.get("/health", response_class=HTMLResponse)
async def ui_health(request: Request) -> HTMLResponse:
    settings = request.app.state.settings
    start_time = getattr(request.app.state, "start_time", None)
    uptime = int(time.time() - start_time) if start_time else 0

    status_cache = getattr(request.app.state, "status_cache", None)

    revocation_staleness = 0
    last_sync = None
    cred_count = 0
    if status_cache is not None:
        try:
            revocation_staleness = int(getattr(status_cache, "staleness_seconds", 0))
            last_sync = getattr(status_cache, "last_sync_at", None)
            cred_count = len(status_cache)
        except Exception:
            pass

    sentinel_did = settings.sentinel_did or ""
    did_hash = _sha256_trunc(sentinel_did) if sentinel_did else ""

    ctx: dict[str, Any] = {
        "instance_id": settings.sentinel_id,
        "sentinel_did_hash": did_hash,
        "uptime_seconds": uptime,
        "credential_count": cred_count,
        "trust_layer_status": "ok",
        "config_bundle_version": getattr(request.app.state, "config_bundle_version", "—"),
        "config_bundle_age_seconds": getattr(request.app.state, "config_bundle_age_seconds", None),
        "last_credential_sync_at": last_sync,
        "chain_cache_age_seconds": getattr(request.app.state, "chain_cache_age_seconds", 0),
        "revocation_staleness_seconds": revocation_staleness,
        "revocation_delta_seconds": 3600,
        "policy_version": getattr(request.app.state, "policy_version", "—"),
        "policy_rule_count": getattr(request.app.state, "policy_rule_count", 0),
    }
    resp = templates.TemplateResponse(request, "health.html", ctx)
    return _secure(resp)


# --------------------------------------------------------------------------- #
# Logs page                                                                    #
# --------------------------------------------------------------------------- #

@ui_router.get("/logs", response_class=HTMLResponse)
async def ui_logs(
    request: Request,
    decision: str = Query(default="", alias="decision"),
    service_id: str = Query(default="", alias="service_id"),
) -> HTMLResponse:
    ring_buffer = getattr(request.app.state, "log_ring_buffer", None)
    events: list[Any] = []

    if ring_buffer is not None:
        filter_decision = decision.lower() if decision else None
        filter_service_id = service_id.strip() if service_id else None
        events = ring_buffer.get_recent(
            100,
            filter_decision=filter_decision,
            filter_service_id=filter_service_id,
        )

    ctx: dict[str, Any] = {
        "events": events,
        "filter_decision": decision,
        "filter_service_id": service_id,
    }
    resp = templates.TemplateResponse(request, "logs.html", ctx)
    return _secure(resp)


# --------------------------------------------------------------------------- #
# SSE log stream (TASK-055)                                                    #
# --------------------------------------------------------------------------- #

_sse_lock: asyncio.Lock | None = None


def _get_sse_lock() -> asyncio.Lock:
    global _sse_lock
    if _sse_lock is None:
        _sse_lock = asyncio.Lock()
    return _sse_lock


@ui_router.get("/logs/stream")
async def ui_logs_stream(
    request: Request,
    filter_decision: str | None = Query(
        default=None,
        pattern="^(permit|deny)$",
    ),
    filter_service_id: str | None = Query(default=None, max_length=64),
) -> Response:
    """SSE endpoint — streams live pre-redacted log events from the ring buffer.

    Returns HTTP 429 if the connection limit (10) has been reached.
    """
    ring_buffer = getattr(request.app.state, "log_ring_buffer", None)

    if ring_buffer is None:
        # No ring buffer configured — stream a single keepalive and close
        async def _empty() -> Any:
            yield ": no_ring_buffer\n\n"

        return StreamingResponse(
            _empty(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ── Connection limit ──────────────────────────────────────────────────────
    lock = _get_sse_lock()
    async with lock:
        current = getattr(request.app.state, "active_sse_connections", 0)
        if current >= _MAX_SSE_CONNECTIONS:
            return Response(
                content="Too Many Streaming Connections",
                status_code=429,
            )
        request.app.state.active_sse_connections = current + 1

    # ── Subscribe queue ───────────────────────────────────────────────────────
    try:
        queue = ring_buffer.subscribe()
    except RuntimeError:
        async with lock:
            request.app.state.active_sse_connections = max(
                0, getattr(request.app.state, "active_sse_connections", 1) - 1
            )
        return Response(content="Too Many Streaming Connections", status_code=429)

    async def _stream() -> Any:
        try:
            async for chunk in log_event_stream(
                queue, ring_buffer, filter_decision, filter_service_id
            ):
                yield chunk
        finally:
            ring_buffer.unsubscribe(queue)
            async with lock:
                request.app.state.active_sse_connections = max(
                    0,
                    getattr(request.app.state, "active_sse_connections", 1) - 1,
                )

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
