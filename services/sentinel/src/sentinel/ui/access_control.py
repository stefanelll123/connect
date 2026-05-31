"""UI local access control for the Sentinel UI (TASK-056).

Provides:
- ``UIAuthMiddleware``            — optional Basic Auth / Bearer token auth
- ``UISecurityHeadersMiddleware`` — CSP, X-Frame-Options, etc.
- CSRF double-submit cookie helpers

Configuration via environment variables:
    SENTINEL_UI_AUTH     = none | basic | token  (default: none)
    SENTINEL_UI_PASSWORD = password for basic auth (required if auth=basic)
    SENTINEL_UI_TOKEN    = bearer token for token auth (required if auth=token)
    SENTINEL_UI_HOST     = bind address (default: 127.0.0.1)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets

from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

# ── Security response headers ─────────────────────────────────────────────────

_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none';"
)

SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": _CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

# ── CSRF ──────────────────────────────────────────────────────────────────────

_CSRF_COOKIE = "csrf_token"
_CSRF_HEADER = "x-csrf-token"


def _generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def _csrf_cookie_value(request: Request) -> str | None:
    return request.cookies.get(_CSRF_COOKIE)


def validate_csrf(request: Request) -> bool:
    """Return True when the CSRF token in the header matches the cookie
    (constant-time comparison)."""
    cookie_token = _csrf_cookie_value(request)
    header_token = request.headers.get(_CSRF_HEADER)
    if not cookie_token or not header_token:
        return False
    return hmac.compare_digest(cookie_token, header_token)


# ── Security headers middleware ───────────────────────────────────────────────


class UISecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to every response under ``/ui``."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        response: Response = await call_next(request)
        if request.url.path.startswith("/ui"):
            for key, value in SECURITY_HEADERS.items():
                response.headers[key] = value
        return response


# ── Auth middleware ───────────────────────────────────────────────────────────


class ConfigurationError(RuntimeError):
    """Raised when the UI auth configuration is invalid at startup."""


class UIAuthMiddleware(BaseHTTPMiddleware):
    """Optional authentication for ``/ui/*`` routes.

    Auth mode is read once from the environment at construction time.
    """

    def __init__(
        self,
        app,  # type: ignore[override]
        auth_mode: str | None = None,
        password: str | None = None,
        token: str | None = None,
    ) -> None:
        super().__init__(app)
        self._mode = (auth_mode or os.getenv("SENTINEL_UI_AUTH", "none")).lower()
        self._password: str | None = None
        self._token: str | None = None

        if self._mode == "basic":
            pw = password or os.getenv("SENTINEL_UI_PASSWORD", "")
            if not pw:
                raise ConfigurationError(
                    "SENTINEL_UI_AUTH=basic requires SENTINEL_UI_PASSWORD to be set."
                )
            self._password = pw
            logger.info("UI authentication: basic (password configured)")
        elif self._mode == "token":
            tok = token or os.getenv("SENTINEL_UI_TOKEN", "")
            if not tok:
                raise ConfigurationError(
                    "SENTINEL_UI_AUTH=token requires SENTINEL_UI_TOKEN to be set."
                )
            self._token = tok
            logger.info("UI authentication: token")
        else:
            logger.info("UI authentication: none (localhost-only)")

    # ── CSRF cookie injection on GET /ui/* ────────────────────────────────────

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        if not request.url.path.startswith("/ui"):
            return await call_next(request)

        # ── Auth check ────────────────────────────────────────────────────────
        if self._mode == "basic":
            if not self._check_basic(request.headers):
                return self._unauthorized()
        elif self._mode == "token":
            if not self._check_token(request.headers):
                return self._unauthorized()

        # ── CSRF enforcement for mutations ────────────────────────────────────
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if not validate_csrf(request):
                return Response(content="CSRF validation failed", status_code=403)

        response: Response = await call_next(request)

        # ── Inject CSRF cookie on GET requests ────────────────────────────────
        if request.method == "GET" and not _csrf_cookie_value(request):
            token = _generate_csrf_token()
            response.set_cookie(
                _CSRF_COOKIE,
                token,
                httponly=True,
                samesite="strict",
                path="/ui",
            )

        # ── Security headers ──────────────────────────────────────────────────
        for key, value in SECURITY_HEADERS.items():
            response.headers[key] = value

        return response

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _check_basic(self, headers: Headers) -> bool:
        auth = headers.get("authorization", "")
        if not auth.lower().startswith("basic "):
            return False
        try:
            decoded = base64.b64decode(auth[6:]).decode()
            _, _, password = decoded.partition(":")
        except Exception:
            return False
        expected = self._password or ""
        return hmac.compare_digest(password, expected)

    def _check_token(self, headers: Headers) -> bool:
        auth = headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return False
        token = auth[7:]
        expected = self._token or ""
        return hmac.compare_digest(token, expected)

    @staticmethod
    def _unauthorized() -> Response:
        return Response(
            content="Unauthorized",
            status_code=401,
            headers={
                "WWW-Authenticate": 'Basic realm="Sentinel UI"',
                **SECURITY_HEADERS,
            },
        )
