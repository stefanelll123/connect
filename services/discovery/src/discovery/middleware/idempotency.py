"""Idempotency key middleware (TASK-035).

Applies to mutating endpoints (POST) only.

Protocol:
1. Client sends `X-Idempotency-Key: <uuid4>` with a POST request.
2. On first call: execute normally, store serialised response in Redis with
   key `idempotency:{path}:{idempotency_key}`, TTL=600s (10 min).
3. On repeated calls with same key: return cached response and set
   `X-Idempotency-Used: true`.
4. Endpoints that should NOT be idempotent (e.g. create-token) are
   excluded via _EXCLUDED_PATHS.

If Redis is unavailable the middleware silently passes through (fail-open is
safe here since idempotency is a client-side safety net, not a security control).
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

_TTL_SECONDS = 600  # 10 minutes

# Paths where idempotency applies (POST only)
_IDEMPOTENCY_PATHS = frozenset({
    "/api/v1/sentinels/onboard",
    "/api/v1/enrollments",
    "/api/v1/services",
    "/api/v1/registry/register",
})

# Prefix-match: any /credentials/*/revoke  or  /services/*/descriptor
_IDEMPOTENCY_PREFIXES = (
    "/api/v1/credentials/",
    "/api/v1/services/",
)

# Paths where idempotency must never apply (token minting, auth)
_EXCLUDED_PATHS = frozenset({
    "/api/v1/auth/dev-token",
    "/api/v1/auth/token",
})


def _applies(method: str, path: str) -> bool:
    if method.upper() != "POST":
        return False
    if path in _EXCLUDED_PATHS:
        return False
    if path in _IDEMPOTENCY_PATHS:
        return True
    for prefix in _IDEMPOTENCY_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


class IdempotencyMiddleware(BaseHTTPMiddleware):
    """Cache POST responses by X-Idempotency-Key header (if present)."""

    async def dispatch(self, request: Request, call_next) -> Response:
        if not _applies(request.method, request.url.path):
            return await call_next(request)

        idem_key: Optional[str] = request.headers.get("x-idempotency-key")
        if not idem_key:
            # No key provided — pass through normally
            return await call_next(request)

        redis = getattr(request.app.state, "redis", None)
        if redis is None:
            return await call_next(request)

        cache_key = f"idempotency:{request.url.path}:{idem_key}"

        # ── Try to serve from cache ─────────────────────────────────────────
        try:
            cached = await redis.get(cache_key)
        except Exception as exc:
            logger.warning("Idempotency Redis read error: %s", exc)
            cached = None

        if cached:
            try:
                data = json.loads(cached)
                response = Response(
                    content=data["body"],
                    status_code=data["status_code"],
                    headers={k: v for k, v in data["headers"].items()},
                    media_type=data.get("media_type"),
                )
                response.headers["X-Idempotency-Used"] = "true"
                return response
            except Exception as exc:
                logger.warning("Idempotency cache deserialization error: %s", exc)

        # ── Execute and cache the response ──────────────────────────────────
        response: Response = await call_next(request)

        # Read entire body so we can cache it
        body_chunks = []
        async for chunk in response.body_iterator:  # type: ignore[attr-defined]
            if isinstance(chunk, str):
                chunk = chunk.encode()
            body_chunks.append(chunk)
        body_bytes = b"".join(body_chunks)

        payload = json.dumps({
            "body": body_bytes.decode("utf-8", errors="replace"),
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "media_type": response.media_type,
        })

        try:
            await redis.set(cache_key, payload, ex=_TTL_SECONDS)
        except Exception as exc:
            logger.warning("Idempotency Redis write error: %s", exc)

        # Re-create the response since body_iterator is exhausted
        return Response(
            content=body_bytes,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )
