"""Structured request-logging middleware.

Logs method, path, HTTP status, and duration on every response.
The access log entry is emitted *after* the response is sent so latency
measurements include handler execution time.
"""
from __future__ import annotations

import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger("discovery.access")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Emit one structured log line per HTTP response."""

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000.0
        request_id = getattr(request.state, "request_id", "-")

        logger.info(
            "method=%s path=%s status=%d duration_ms=%.1f request_id=%s",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            request_id,
        )
        return response
