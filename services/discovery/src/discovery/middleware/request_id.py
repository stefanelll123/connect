"""Request-ID middleware.

Generates or validates X-Request-ID and X-Correlation-ID on every request:

* If the client provides a valid UUID4 in X-Request-ID it is echoed back.
* Any malformed / non-UUID4 value is silently replaced with a fresh UUID4.
* X-Correlation-ID defaults to the (final) X-Request-ID unless the client
  provides its own value.

Both IDs are stored on ``request.state`` so downstream handlers can reference
them for logging and error responses.
"""
from __future__ import annotations

import re
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

# UUID v4 validation pattern
_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Generate / propagate X-Request-ID and X-Correlation-ID."""

    async def dispatch(self, request: Request, call_next):
        # Accept client-provided request ID only when it is a valid UUID4.
        client_rid = request.headers.get("X-Request-ID", "")
        request_id = client_rid if (client_rid and _UUID4_RE.match(client_rid)) else str(uuid.uuid4())

        correlation_id = request.headers.get("X-Correlation-ID") or request_id

        request.state.request_id = request_id
        request.state.correlation_id = correlation_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Correlation-ID"] = correlation_id
        return response
