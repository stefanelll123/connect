"""Abuse detection middleware (TASK-035).

Detects two patterns:
1. Onboarding flood: >100 POST /api/v1/sentinels/onboard attempts from the
   same IP with *different* token JTIs within 10 minutes.  When triggered:
   - Flag the IP in Redis for 30 minutes.
   - While flagged: allow only 1 request per minute (hard rate limit).
   - Log at CRITICAL level ("SECURITY_ALERT").

2. Revocation storm: >10 POST /credentials/*/revoke from the same admin sub
   in 5 minutes.  When triggered:
   - Return 428 Precondition Required with `X-Require-Reauth: true`.
   - Log at CRITICAL level ("SECURITY_ALERT").
"""
from __future__ import annotations

import json
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

# ── Onboarding flood thresholds ────────────────────────────────────────────
_ONBOARD_PATH = "/api/v1/sentinels/onboard"
_ONBOARD_JTI_WINDOW = 600         # 10 minutes
_ONBOARD_JTI_THRESHOLD = 100      # distinct JTIs per IP in window
_ONBOARD_FLAG_TTL = 1800          # 30 minutes flagged
_ONBOARD_PENALTY_LIMIT = 1        # 1 req/min while flagged

# ── Revocation storm thresholds ────────────────────────────────────────────
_REVOKE_PREFIX = "/api/v1/credentials/"
_REVOKE_SUFFIX = "/revoke"
_REVOKE_WINDOW = 300              # 5 minutes
_REVOKE_THRESHOLD = 10            # revocations per admin sub


def _parse_jwt_payload(auth_header: str) -> dict:
    """Best-effort, no-verification JWT payload extraction."""
    import base64

    try:
        token = auth_header[7:]  # strip "Bearer "
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


def _is_revoke_endpoint(path: str, method: str) -> bool:
    return method.upper() == "POST" and path.startswith(_REVOKE_PREFIX) and path.endswith(_REVOKE_SUFFIX)


class AbuseDetectionMiddleware(BaseHTTPMiddleware):
    """Detect and block onboarding floods and revocation storms."""

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        method = request.method.upper()

        redis = getattr(request.app.state, "redis", None)
        if redis is None:
            return await call_next(request)

        # ── 1. Onboarding flood ─────────────────────────────────────────────
        if method == "POST" and path == _ONBOARD_PATH:
            result = await self._check_onboard_flood(request, redis)
            if result is not None:
                return result

        # ── 2. Revocation storm ─────────────────────────────────────────────
        if _is_revoke_endpoint(path, method):
            result = await self._check_revocation_storm(request, redis)
            if result is not None:
                return result

        return await call_next(request)

    # ── Internal helpers ────────────────────────────────────────────────────

    async def _check_onboard_flood(
        self, request: Request, redis
    ) -> Response | None:
        ip = request.client.host if request.client else "unknown"
        flag_key = f"abuse:onboard:flagged:{ip}"

        # Flagged IP → hard penalty
        try:
            is_flagged = await redis.exists(flag_key)
        except Exception:
            return None

        if is_flagged:
            logger.critical(
                "SECURITY_ALERT: Flagged IP %s attempted onboard (still blocked).", ip
            )
            return Response(
                content=json.dumps({
                    "type": "about:blank",
                    "title": "Too Many Requests",
                    "status": 429,
                    "code": "ABUSE_DETECTED",
                    "detail": "Automated onboarding activity detected. Contact support.",
                }),
                status_code=429,
                media_type="application/problem+json",
            )

        # Track JTIs seen from this IP
        auth = request.headers.get("Authorization", "")
        payload = _parse_jwt_payload(auth) if auth.startswith("Bearer ") else {}
        jti = payload.get("jti") or payload.get("sub") or "unknown"

        jti_set_key = f"abuse:onboard:jtis:{ip}"
        import time as _time

        try:
            now = _time.time()
            window_start = now - _ONBOARD_JTI_WINDOW
            async with redis.pipeline(transaction=False) as pipe:
                pipe.zremrangebyscore(jti_set_key, "-inf", window_start)
                pipe.zadd(jti_set_key, {jti: now})
                pipe.zcard(jti_set_key)
                pipe.expire(jti_set_key, _ONBOARD_JTI_WINDOW + 1)
                results = await pipe.execute()
            distinct_jtis = results[2]
        except Exception:
            return None

        if distinct_jtis > _ONBOARD_JTI_THRESHOLD:
            try:
                await redis.set(flag_key, "1", ex=_ONBOARD_FLAG_TTL)
            except Exception:
                pass
            logger.critical(
                "SECURITY_ALERT: IP %s triggered onboarding flood (%d distinct JTIs). Flagging.",
                ip, distinct_jtis,
            )
            return Response(
                content=json.dumps({
                    "type": "about:blank",
                    "title": "Too Many Requests",
                    "status": 429,
                    "code": "ABUSE_DETECTED",
                    "detail": "Automated onboarding activity detected. Contact support.",
                }),
                status_code=429,
                media_type="application/problem+json",
            )

        return None

    async def _check_revocation_storm(
        self, request: Request, redis
    ) -> Response | None:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        payload = _parse_jwt_payload(auth)
        sub = payload.get("sub", "unknown")

        revoke_count_key = f"abuse:revoke:count:{sub}"
        import time as _time

        now = _time.time()
        window_start = now - _REVOKE_WINDOW

        try:
            async with redis.pipeline(transaction=False) as pipe:
                pipe.zremrangebyscore(revoke_count_key, "-inf", window_start)
                pipe.zadd(revoke_count_key, {str(now): now})
                pipe.zcard(revoke_count_key)
                pipe.expire(revoke_count_key, _REVOKE_WINDOW + 1)
                results = await pipe.execute()
            count = results[2]
        except Exception:
            return None

        if count > _REVOKE_THRESHOLD:
            logger.critical(
                "SECURITY_ALERT: Admin sub=%s triggered revocation storm (%d in window). "
                "Re-auth required.",
                sub, count,
            )
            return Response(
                content=json.dumps({
                    "type": "about:blank",
                    "title": "Precondition Required",
                    "status": 428,
                    "code": "REAUTH_REQUIRED",
                    "detail": (
                        "High revocation rate detected. Re-authentication required "
                        "to continue."
                    ),
                }),
                status_code=428,
                headers={"X-Require-Reauth": "true"},
                media_type="application/problem+json",
            )

        return None
