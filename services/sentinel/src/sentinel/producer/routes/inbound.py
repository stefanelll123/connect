"""Producer inbound catch-all route (TASK-045).

Replaces the stub ``api/inbound.py`` route with an 8-stage verification
pipeline.  Every request must pass ProofClaims + VP + trust + revocation
checks before being forwarded to the backend.
"""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Request

from sentinel.producer.pipeline import InboundPipeline

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Inbound / Producer"])


def _get_pipeline(request: Request) -> InboundPipeline:
    """Retrieve the InboundPipeline from app state (set up in lifespan)."""
    pipeline: InboundPipeline = getattr(request.app.state, "inbound_pipeline", None)
    if pipeline is None:
        # Lazy construction from app state on first request (dev convenience)
        settings = request.app.state.settings
        http_client = request.app.state.http_client
        trust_client = getattr(request.app.state, "trust_client", None)
        revocation_manager = getattr(request.app.state, "revocation_manager", None)
        replay_cache = getattr(request.app.state, "replay_cache", None)
        session_issuer = getattr(request.app.state, "session_issuer", None)

        from common.security_envelope.replay_cache import ReplayCache
        from common.vc_engine.resolver import DIDResolver

        if replay_cache is None:
            replay_cache = ReplayCache(redis_client=None)  # in-memory fallback

        pipeline = InboundPipeline(
            service_did=settings.sentinel_did or "",
            service_id=settings.service_id,
            env=settings.env,
            resolver=DIDResolver(),
            replay_cache=replay_cache,
            trust_client=trust_client,
            revocation_manager=revocation_manager,
            http_client=http_client,
            backend_url=settings.backend_url,
            max_clock_skew=300,
            session_issuer=session_issuer,
        )
        request.app.state.inbound_pipeline = pipeline

    return pipeline


@router.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    include_in_schema=False,
)
async def inbound_proxy(full_path: str, request: Request):
    """Verify the inbound request through the 8-stage pipeline and forward."""
    pipeline = _get_pipeline(request)
    return await pipeline.process(request, full_path)
