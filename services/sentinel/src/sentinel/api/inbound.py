"""Producer-mode inbound reverse-proxy route (TASK-037).

Catches ALL methods and paths, runs the security verification pipeline,
then streams the request to the configured ``backend_url``.

Security headers added:
- ``X-Sentinel-Verified: true``  — verification passed
- ``X-Sentinel-Consumer-DID``    — DID of the presenting consumer (if available)

Stripped headers:
- ``Authorization``              — never forwarded to the backend
- ``X-Forwarded-*``              — re-created from actual upstream
"""
from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import Response
from starlette.datastructures import Headers

from sentinel.core.security_pipeline import VerificationPipeline

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Inbound / Producer"])

_STRIP_REQUEST_HEADERS = frozenset({
    "authorization",
    "host",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
})
_STRIP_RESPONSE_HEADERS = frozenset({
    "content-encoding",
    "transfer-encoding",
    "connection",
})


@router.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    include_in_schema=False,
)
async def inbound_proxy(full_path: str, request: Request):
    """Verify the inbound request and forward it to the backend."""
    settings = request.app.state.settings
    http_client: httpx.AsyncClient = request.app.state.http_client

    # ── Security verification pipeline ─────────────────────────────────
    pipeline = VerificationPipeline(settings)
    verification = await pipeline.verify(request)

    if not verification.passed:
        logger.warning(
            "Inbound verification failed [path=/%s]: %s",
            full_path, verification.reason,
        )
        return Response(
            content=f'{{"status":401,"detail":"{verification.reason}"}}',
            status_code=401,
            media_type="application/problem+json",
        )

    # ── Build upstream request ──────────────────────────────────────────
    backend_url = settings.backend_url.rstrip("/")
    upstream_url = f"{backend_url}/{full_path}"
    if request.url.query:
        upstream_url += f"?{request.url.query}"

    # Filter headers
    upstream_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in _STRIP_REQUEST_HEADERS
    }
    upstream_headers["X-Sentinel-Verified"] = "true"
    if verification.consumer_did:
        upstream_headers["X-Sentinel-Consumer-DID"] = verification.consumer_did

    body = await request.body()

    # ── Forward and stream response ─────────────────────────────────────
    try:
        upstream_resp = await http_client.request(
            method=request.method,
            url=upstream_url,
            headers=upstream_headers,
            content=body,
        )
    except httpx.HTTPError as exc:
        logger.error("Upstream request failed: %s", exc)
        return Response(
            content='{"status":502,"detail":"Bad Gateway — upstream unreachable"}',
            status_code=502,
            media_type="application/problem+json",
        )

    # Strip hop-by-hop headers from response
    response_headers = {
        k: v
        for k, v in upstream_resp.headers.multi_items()
        if k.lower() not in _STRIP_RESPONSE_HEADERS
    }

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=response_headers,
        media_type=upstream_resp.headers.get("content-type"),
    )
