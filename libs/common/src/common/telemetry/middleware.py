"""FastAPI RequestLoggingMiddleware — structured per-request logging with trace correlation.

Usage::

    from common.telemetry.middleware import RequestLoggingMiddleware
    app.add_middleware(RequestLoggingMiddleware)

Each request log entry includes: ``request_id``, ``method``, ``path``,
``status_code``, ``response_time_ms``.  The ``trace_id`` and ``span_id`` are
injected automatically by the structlog OTel processor when FastAPI
instrumentation is active.

Request bodies are NEVER logged by default to prevent leaking sensitive payloads.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

logger = structlog.get_logger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Starlette/FastAPI middleware that logs every HTTP request as a structured event.

    - Binds ``request_id`` (from ``X-Request-ID`` header or freshly generated UUID4)
      into the structlog context-var so all log lines within the request share it.
    - Logs a single *access* event after the response is sent, including latency.
    - Clears structlog context vars before and after each request to prevent leakage.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Any) -> Response:  # type: ignore[override]
        structlog.contextvars.clear_contextvars()

        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            http_method=request.method,
            http_path=request.url.path,
        )

        start = time.perf_counter()
        try:
            response: Response = await call_next(request)
        except Exception:
            elapsed_ms = (time.perf_counter() - start) * 1_000
            logger.exception(
                "unhandled_request_error",
                response_time_ms=round(elapsed_ms, 2),
            )
            raise
        finally:
            structlog.contextvars.clear_contextvars()

        elapsed_ms = (time.perf_counter() - start) * 1_000
        logger.info(
            "http_request",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            response_time_ms=round(elapsed_ms, 2),
        )

        # Echo the request ID back to the caller
        response.headers["X-Request-ID"] = request_id
        return response
