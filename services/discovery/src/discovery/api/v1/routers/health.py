"""Health check endpoints — used as K8s liveness and readiness probes.

These endpoints are intentionally registered *without* the /api/v1 prefix
so that infrastructure (Kubernetes, load balancers) can reach them at
well-known paths.

TASK-036: Enhanced with version/uptime (live), chain check (ready), and
/health/detailed for operator diagnostics.
"""
from __future__ import annotations

import time
from importlib.metadata import PackageNotFoundError, version as pkg_version

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

router = APIRouter(prefix="/health", tags=["Health"])

# Record startup time for uptime calculation
_START_TIME = time.monotonic()

try:
    _SERVICE_VERSION = pkg_version("discovery")
except PackageNotFoundError:
    _SERVICE_VERSION = "0.0.0"


@router.get("/live", summary="Liveness probe")
async def liveness():
    """Returns 200 immediately — no external dependencies required.

    This endpoint confirms the process is alive and the event loop is
    responding.  Kubernetes will restart the pod if this fails.
    """
    return {
        "status": "ok",
        "service": "discovery",
        "version": _SERVICE_VERSION,
        "uptime_seconds": round(time.monotonic() - _START_TIME, 1),
    }


@router.get("/ready", summary="Readiness probe")
async def readiness(request: Request):
    """Returns 200 when all critical dependencies are reachable.

    Checks performed:
    - PostgreSQL: ``SELECT 1``
    - Redis: ``PING``
    - Chain RPC (if blockchain_integration enabled): ``eth_blockNumber``

    Returns 503 if any check fails so that Kubernetes stops routing
    traffic to the pod until dependencies recover.
    """
    checks: dict[str, str] = {}

    # --- Database ---
    try:
        engine = getattr(request.app.state, "db_engine", None)
        if engine is not None:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            checks["db"] = "ok"
        else:
            checks["db"] = "unavailable"
    except Exception:
        checks["db"] = "error"

    # --- Redis ---
    try:
        redis = getattr(request.app.state, "redis", None)
        if redis is not None:
            await redis.ping()
            checks["redis"] = "ok"
        else:
            checks["redis"] = "unavailable"
    except Exception:
        checks["redis"] = "error"

    # --- Chain RPC (optional) ---
    settings = getattr(request.app.state, "settings", None)
    if settings and getattr(settings, "blockchain_integration", False):
        try:
            from discovery.services.chain_indexer import get_chain_indexer
            indexer = get_chain_indexer()
            if indexer is not None:
                available = await indexer.check_availability()
                checks["chain"] = "ok" if available else "error"
            else:
                checks["chain"] = "unavailable"
        except Exception:
            checks["chain"] = "error"

    all_ok = all(v == "ok" for v in checks.values())
    status_code = 200 if all_ok else 503

    return JSONResponse(
        content={"status": "ok" if all_ok else "degraded", "checks": checks},
        status_code=status_code,
    )


@router.get("/detailed", summary="Detailed health — operator only")
async def detailed_health(
    request: Request,
    x_operator_token: str = Header(default=""),
):
    """Detailed operator health check including pool stats, Redis memory, chain.

    Requires ``X-Operator-Token`` header matching the configured operator secret.
    Returns 403 if the token is missing or invalid.
    """
    settings = getattr(request.app.state, "settings", None)
    operator_secret = getattr(settings, "operator_token", "")

    if not operator_secret or x_operator_token != operator_secret:
        raise HTTPException(status_code=403, detail="Forbidden")

    info: dict = {
        "service": "discovery",
        "version": _SERVICE_VERSION,
        "uptime_seconds": round(time.monotonic() - _START_TIME, 1),
        "db": {},
        "redis": {},
        "chain": {},
    }

    # --- DB pool stats ---
    engine = getattr(request.app.state, "db_engine", None)
    if engine is not None:
        try:
            pool = engine.pool
            info["db"] = {
                "pool_size": pool.size(),
                "checked_out": pool.checkedout(),
                "overflow": pool.overflow(),
                "checked_in": pool.checkedin(),
            }
        except Exception as exc:
            info["db"] = {"error": str(exc)}

    # --- Redis memory ---
    redis = getattr(request.app.state, "redis", None)
    if redis is not None:
        try:
            mem_info = await redis.info("memory")
            info["redis"] = {
                "used_memory_human": mem_info.get("used_memory_human"),
                "used_memory_peak_human": mem_info.get("used_memory_peak_human"),
                "maxmemory_human": mem_info.get("maxmemory_human"),
            }
        except Exception as exc:
            info["redis"] = {"error": str(exc)}

    # --- Chain ---
    if settings and getattr(settings, "blockchain_integration", False):
        try:
            from discovery.services.chain_indexer import get_chain_indexer
            indexer = get_chain_indexer()
            if indexer is not None:
                block_number = await indexer.get_latest_block_number()
                info["chain"] = {"latest_block": block_number}
            else:
                info["chain"] = {"status": "not_initialised"}
        except Exception as exc:
            info["chain"] = {"error": str(exc)}

    return JSONResponse(content=info, status_code=200)

