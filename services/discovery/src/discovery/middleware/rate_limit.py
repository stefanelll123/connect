"""Redis sliding-window rate limiter middleware (TASK-035).

Key schema: ratelimit:{endpoint_slug}:{identifier}
Identifier: authenticated sub (from JWT) if available, else IP address.

On limit exceeded: 429 with Retry-After header.
Fail behaviour: configurable — fail_open=True allows all on Redis error.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default endpoint rate limits  (limit, window_seconds, key_type)
# key_type: "sub" | "ip" | "token_jti"
# ---------------------------------------------------------------------------
_DEFAULT_LIMITS: dict[str, tuple[int, int, str]] = {
    "POST /api/v1/sentinels/onboard": (5, 600, "token_jti"),
    "POST /api/v1/enrollments": (20, 60, "sub"),
    "POST /api/v1/credentials/revoke": (30, 60, "sub"),
    "POST /api/v1/auth/dev-token": (10, 60, "ip"),
    "GET /api/v1/registry/resolve": (100, 60, "sub"),
    "GET /status/": (1000, 60, "ip"),
    "GET /api/v1/": (200, 60, "sub"),
    # Admin mutations
    "POST /api/v1/": (60, 60, "sub"),
    "PATCH /api/v1/": (60, 60, "sub"),
    "DELETE /api/v1/": (60, 60, "sub"),
}


def _endpoint_slug(method: str, path: str) -> str:
    """Normalise method+path into a route slug for rate-limit key lookup."""
    # Strip trailing slashes and query strings
    clean_path = path.split("?")[0].rstrip("/")
    return f"{method} {clean_path}"


def _get_identifier(request: Request, key_type: str) -> str:
    """Extract the rate-limit identifier from the request."""
    if key_type == "ip":
        return request.client.host if request.client else "unknown"
    # Try to extract sub from Authorization header (best-effort, no verification here)
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and key_type in ("sub", "token_jti"):
        token = auth[7:]
        try:
            import base64
            # Decode payload without verification (already verified by auth middleware)
            parts = token.split(".")
            if len(parts) == 3:
                padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(padded))
                if key_type == "token_jti":
                    return payload.get("jti", payload.get("sub", "anonymous"))
                return payload.get("sub", "anonymous")
        except Exception:
            pass
    return request.client.host if request.client else "unknown"


async def _sliding_window_check(
    redis: Any,
    key: str,
    limit: int,
    window_seconds: int,
) -> tuple[bool, int]:
    """Sliding window rate check using Redis sorted sets.

    Returns (allowed, retry_after_seconds).
    """
    now = time.time()
    window_start = now - window_seconds

    async with redis.pipeline(transaction=False) as pipe:
        # Remove expired entries
        pipe.zremrangebyscore(key, "-inf", window_start)
        # Count current requests in window
        pipe.zcard(key)
        # Add current timestamp (score=ts, member=ts)
        pipe.zadd(key, {str(now): now})
        # Set expiry on the key
        pipe.expire(key, window_seconds + 1)
        results = await pipe.execute()

    count_after_remove = results[1]  # before the new entry

    if count_after_remove >= limit:
        # Calculate when the oldest entry will expire
        oldest_result = await redis.zrange(key, 0, 0, withscores=True)
        if oldest_result:
            oldest_ts = oldest_result[0][1]
            retry_after = int(oldest_ts + window_seconds - now) + 1
        else:
            retry_after = window_seconds
        return False, max(1, retry_after)

    return True, 0


def _build_429(limit: int, window_seconds: int, retry_after: int, slug: str) -> Response:
    body = json.dumps({
        "type": "about:blank",
        "title": "Too Many Requests",
        "status": 429,
        "detail": f"Rate limit of {limit}/{window_seconds}s exceeded. Retry after {retry_after}s.",
        "code": "RATE_LIMIT_EXCEEDED",
        "limit": limit,
        "window_seconds": window_seconds,
        "retry_after": retry_after,
    })
    return Response(
        content=body,
        status_code=429,
        headers={"Retry-After": str(retry_after), "Content-Type": "application/problem+json"},
    )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window Redis rate limiter.

    Skips rate-limiting for health/metrics endpoints.
    Fails safely — see fail_open setting.
    """

    _SKIP_PATHS = frozenset({"/health/live", "/health/ready", "/health/detailed", "/metrics"})

    def __init__(self, app, *, fail_open: bool = False) -> None:
        super().__init__(app)
        self._fail_open = fail_open

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in self._SKIP_PATHS:
            return await call_next(request)

        redis = getattr(request.app.state, "redis", None)
        if redis is None:
            if self._fail_open:
                return await call_next(request)
            # fail_closed: deny all rate-limited requests when Redis unavailable
            return Response(
                content='{"status":503,"detail":"Rate limiter unavailable"}',
                status_code=503,
                media_type="application/problem+json",
            )

        settings = getattr(request.app.state, "settings", None)
        rate_limits = getattr(settings, "rate_limits", {})

        method = request.method.upper()
        path = request.url.path
        slug = _endpoint_slug(method, path)

        # Find a matching config (exact match first, then prefix)
        limit_config: Optional[tuple[int, int, str]] = (
            rate_limits.get(slug)
            or _DEFAULT_LIMITS.get(slug)
        )
        if limit_config is None:
            # Prefix match
            for pattern, cfg in {**_DEFAULT_LIMITS, **rate_limits}.items():
                pat_method, pat_path = pattern.split(" ", 1)
                if pat_method == method and path.startswith(pat_path):
                    limit_config = cfg
                    break

        if limit_config is None:
            return await call_next(request)

        limit, window_seconds, key_type = limit_config
        identifier = _get_identifier(request, key_type)
        redis_key = f"ratelimit:{slug.replace(' ', ':').replace('/', '_')}:{identifier}"

        try:
            allowed, retry_after = await _sliding_window_check(
                redis, redis_key, limit, window_seconds
            )
        except Exception as exc:
            logger.warning("Rate limiter Redis error: %s", exc)
            if self._fail_open:
                return await call_next(request)
            return Response(
                content='{"status":503,"detail":"Rate limiter temporarily unavailable"}',
                status_code=503,
                media_type="application/problem+json",
            )

        if not allowed:
            return _build_429(limit, window_seconds, retry_after, slug)

        return await call_next(request)
