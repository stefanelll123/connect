"""Secure response headers middleware (TASK-035).

Adds defensive HTTP response headers to every response:
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy: (restrict dangerous APIs)
- Cross-Origin-Opener-Policy: same-origin
- Content-Security-Policy: default-src 'none'  (API-only)
- Strict-Transport-Security: max-age=63072000; includeSubDomains; preload  (non-dev only)

Replaces the inline SecureHeadersMiddleware previously defined in app.py.
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_HSTS_VALUE = "max-age=63072000; includeSubDomains; preload"
_CSP_API = "default-src 'none'"
_PERMISSIONS_POLICY = (
    "geolocation=(), "
    "microphone=(), "
    "camera=(), "
    "payment=(), "
    "usb=(), "
    "magnetometer=(), "
    "gyroscope=(), "
    "accelerometer=()"
)


class SecureHeadersMiddleware(BaseHTTPMiddleware):
    """Injects security headers into every HTTP response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = _PERMISSIONS_POLICY
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = _CSP_API

        # HSTS only outside development
        settings = getattr(request.app.state, "settings", None)
        env = getattr(settings, "env", "dev")
        if env not in ("dev", "development", "local"):
            response.headers["Strict-Transport-Security"] = _HSTS_VALUE

        return response
