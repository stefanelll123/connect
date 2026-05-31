"""Health check endpoints for the Sentinel Node (TASK-037)."""
from __future__ import annotations

import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/health", tags=["Health"])
_START_TIME = time.monotonic()


@router.get("/live", summary="Liveness probe")
async def liveness(request: Request):
    """Confirm the process is alive."""
    settings = request.app.state.settings
    return {
        "status": "ok",
        "service": "sentinel",
        "role": settings.sentinel_role,
        "sentinel_id": settings.sentinel_id,
        "uptime_seconds": round(time.monotonic() - _START_TIME, 1),
    }


@router.get("/ready", summary="Readiness probe")
async def readiness(request: Request):
    """Check that critical dependencies are accessible."""
    settings = request.app.state.settings
    checks: dict[str, str] = {}

    # ── Wallet / credential store ───────────────────────────────────────
    credential_store = getattr(request.app.state, "credential_store", None)
    checks["wallet"] = "ok" if credential_store is not None else "unavailable"

    # ── Discovery Service reachability ─────────────────────────────────
    http_client = getattr(request.app.state, "http_client", None)
    if http_client is not None:
        try:
            resp = await http_client.get(
                f"{settings.discovery_url}/health/live",
                timeout=5.0,
            )
            checks["discovery"] = "ok" if resp.status_code == 200 else "error"
        except Exception:
            checks["discovery"] = "error"
    else:
        checks["discovery"] = "unavailable"

    all_ok = all(v in ("ok", "unavailable") for v in checks.values())
    # "unavailable" is tolerated (optional dependency); "error" is not.
    degraded = any(v == "error" for v in checks.values())
    status_code = 503 if degraded else 200

    return JSONResponse(
        content={
            "status": "ok" if not degraded else "degraded",
            "role": settings.sentinel_role,
            "checks": checks,
        },
        status_code=status_code,
    )
