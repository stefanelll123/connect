"""Request body and header size enforcement middleware (TASK-035).

Enforces:
- Content-Length > max_request_body_bytes → 413
- Total header size > max_header_size_bytes → 431

Sizes are read from app.state.settings (with sane defaults).
"""
from __future__ import annotations

import json

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_DEFAULT_MAX_BODY = 2 * 1024 * 1024   # 2 MB
_DEFAULT_MAX_HEADERS = 16 * 1024       # 16 KB


class RequestLimitsMiddleware(BaseHTTPMiddleware):
    """Enforce request body and total header size limits.

    Runs before body parsing so that oversized payloads are rejected without
    reading the full stream into memory.
    """

    _SKIP_PATHS = frozenset({"/health/live", "/health/ready", "/health/detailed", "/metrics"})

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in self._SKIP_PATHS:
            return await call_next(request)

        settings = getattr(request.app.state, "settings", None)
        max_body = getattr(settings, "max_request_body_bytes", _DEFAULT_MAX_BODY)
        max_headers = getattr(settings, "max_header_size_bytes", _DEFAULT_MAX_HEADERS)

        # ── Header size check ───────────────────────────────────────────────
        total_header_size = sum(
            len(k) + len(v) + 4  # ": " separator + "\r\n"
            for k, v in request.headers.items()
        )
        if total_header_size > max_headers:
            return Response(
                content=json.dumps({
                    "type": "about:blank",
                    "title": "Request Header Fields Too Large",
                    "status": 431,
                    "code": "HEADERS_TOO_LARGE",
                    "detail": (
                        f"Total header size {total_header_size}B exceeds limit of {max_headers}B."
                    ),
                }),
                status_code=431,
                media_type="application/problem+json",
            )

        # ── Content-Length body size check ──────────────────────────────────
        content_length_str = request.headers.get("content-length")
        if content_length_str is not None:
            try:
                content_length = int(content_length_str)
            except ValueError:
                return Response(
                    content=json.dumps({
                        "type": "about:blank",
                        "title": "Bad Request",
                        "status": 400,
                        "code": "INVALID_CONTENT_LENGTH",
                        "detail": "Content-Length header must be a non-negative integer.",
                    }),
                    status_code=400,
                    media_type="application/problem+json",
                )
            if content_length > max_body:
                return Response(
                    content=json.dumps({
                        "type": "about:blank",
                        "title": "Content Too Large",
                        "status": 413,
                        "code": "REQUEST_TOO_LARGE",
                        "detail": (
                            f"Request body {content_length}B exceeds limit of {max_body}B."
                        ),
                    }),
                    status_code=413,
                    media_type="application/problem+json",
                )

        return await call_next(request)
