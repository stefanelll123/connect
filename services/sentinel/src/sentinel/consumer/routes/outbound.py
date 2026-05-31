"""Consumer outbound proxy route (TASK-044)."""
from __future__ import annotations

import logging
import uuid

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from sentinel.consumer.descriptor_cache import DescriptorCache, DescriptorInvalid, ServiceNotFound
from sentinel.consumer.endpoint_selector import EndpointSelector, NoEndpointsAvailable
from sentinel.consumer.pipeline import OutboundPipeline

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Outbound / Consumer"])

# Hop-by-hop headers to strip from upstream responses before returning to client
_STRIP_RESPONSE_HEADERS = frozenset({
    "authorization", "sentinelvp",
    "transfer-encoding", "connection",
    "x-sentinel-consumer-did",
})


@router.api_route(
    "/outbound/{service_id}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def proxy_outbound(service_id: str, path: str, request: Request):
    """Resolve the producer descriptor, build the security envelope, and forward."""
    settings = request.app.state.settings
    http_client: httpx.AsyncClient = request.app.state.http_client
    descriptor_cache: DescriptorCache = getattr(
        request.app.state, "descriptor_cache",
        DescriptorCache(),
    )
    endpoint_selector: EndpointSelector = getattr(
        request.app.state, "endpoint_selector",
        EndpointSelector(),
    )

    correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    body = await request.body()
    method = request.method
    env = settings.env

    # Collect headers to forward
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in {"host", "authorization", "sentinelvp"}
    }

    pipeline = OutboundPipeline(
        http_client=http_client,
        descriptor_cache=descriptor_cache,
        endpoint_selector=endpoint_selector,
        consumer_did=settings.sentinel_did,
        consumer_key_bytes=getattr(request.app.state, "consumer_key_bytes", b"\x00" * 32),
        credential_store=getattr(request.app.state, "credential_store", None),
    )

    try:
        upstream_resp = await pipeline.send(
            service_id=service_id,
            path=path,
            method=method,
            headers=forward_headers,
            body=body,
            query_params=dict(request.query_params),
            env=env,
            correlation_id=correlation_id,
        )

        # Filter response headers
        resp_headers = {
            k: v for k, v in upstream_resp.headers.items()
            if k.lower() not in _STRIP_RESPONSE_HEADERS
        }
        resp_headers["X-Correlation-ID"] = correlation_id

        # Check for upstream auth failure
        if upstream_resp.status_code in (401, 403):
            return JSONResponse(
                status_code=502,
                content={"error": "UPSTREAM_AUTH_FAILURE", "upstream_status": upstream_resp.status_code},
                headers={"X-Correlation-ID": correlation_id},
            )

        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type=upstream_resp.headers.get("content-type"),
        )

    except ServiceNotFound as exc:
        logger.warning("ServiceNotFound service_id=%s: %s", service_id, exc)
        return JSONResponse(
            status_code=503,
            content={"error": "SERVICE_NOT_FOUND", "request_id": correlation_id},
        )
    except DescriptorInvalid as exc:
        logger.error("DescriptorInvalid service_id=%s: %s", service_id, exc)
        return JSONResponse(
            status_code=502,
            content={"error": "DESCRIPTOR_INVALID", "request_id": correlation_id},
        )
    except NoEndpointsAvailable as exc:
        logger.warning("NoEndpointsAvailable service_id=%s: %s", service_id, exc)
        return JSONResponse(
            status_code=503,
            content={"error": "NO_ENDPOINTS_AVAILABLE", "request_id": correlation_id},
        )
    except (httpx.TimeoutException, httpx.NetworkError) as exc:
        logger.warning("Upstream timeout/unreachable service_id=%s: %s", service_id, exc)
        return JSONResponse(
            status_code=503,
            content={"error": "UPSTREAM_UNAVAILABLE", "request_id": correlation_id},
        )
