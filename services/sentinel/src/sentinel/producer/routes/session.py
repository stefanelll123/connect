"""Session exchange routes for producers (SD-JWT + KB-JWT fast-path).

Routes
------
``GET /auth/nonce``
    Issue a single-use nonce.  Consumer embeds it in its KB-JWT so the
    producer can verify freshness and prevent replay attacks.

``POST /auth/session``
    Receive an SD-JWT presentation (``<SD-JWT>~~<KB-JWT>``) and return a
    short-lived session JWT.  Future requests can use this token as a
    ``Bearer`` credential instead of re-presenting the full VP.

Rate limiting
-------------
Requests are counted per *consumer DID* (extracted from the unverified
SD-JWT payload).  If the counter exceeds ``settings.session_rate_limit_per_minute``
within a 60-second window the endpoint returns HTTP 429.  The counter
lives in process memory; at scale, replace with a Redis sliding window.

Security notes
--------------
* The nonce is **consumed** (deleted) at the start of verification — even
  if subsequent steps fail — to prevent partial-success replay.
* The SD-JWT issuer DID must be in the trusted-issuer set fetched from
  the TrustLayerClient (or Discovery HTTP fallback in dev).
* The response body never contains the consumer's DID or VC details.
"""
from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from typing import Any, Dict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from sentinel.producer.nonce_store import NonceStore
from sentinel.producer.session import SessionTokenIssuer

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Session Exchange"])

# ---------------------------------------------------------------------------
# In-process rate-limit state
# rate_counters: {consumer_did: [window_start, count]}
# ---------------------------------------------------------------------------
_rate_counters: Dict[str, list] = defaultdict(lambda: [0.0, 0])
_RATE_WINDOW_SECONDS = 60


def _check_rate_limit(consumer_did: str, limit: int) -> bool:
    """Return True if the request is within the allowed rate, False if throttled."""
    now = time.time()
    state = _rate_counters[consumer_did]
    window_start, count = state[0], state[1]

    if now - window_start >= _RATE_WINDOW_SECONDS:
        # New window
        state[0] = now
        state[1] = 1
        return True

    if count >= limit:
        return False

    state[1] = count + 1
    return True


def _peek_sd_jwt_payload(presentation: str) -> dict:
    """Decode the SD-JWT payload WITHOUT signature verification.

    Used only to extract consumer DID for rate-limiting before full
    verification.  Returns empty dict on any error.
    """
    import base64

    try:
        sd_jwt = presentation.split("~")[0]
        parts = sd_jwt.split(".")
        if len(parts) != 3:
            return {}
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


def _get_nonce_store(request: Request) -> NonceStore:
    store: NonceStore | None = getattr(request.app.state, "nonce_store", None)
    if store is None:
        settings = request.app.state.settings
        store = NonceStore(ttl=settings.session_nonce_ttl)
        request.app.state.nonce_store = store
    return store


def _get_session_issuer(request: Request) -> SessionTokenIssuer:
    issuer: SessionTokenIssuer | None = getattr(request.app.state, "session_issuer", None)
    if issuer is None:
        settings = request.app.state.settings
        key_bytes: bytes = getattr(request.app.state, "consumer_key_bytes", b"\x00" * 32)
        issuer = SessionTokenIssuer(
            service_did=settings.sentinel_did or "",
            private_key_bytes=key_bytes,
            service_id=settings.service_id,
            env=settings.env,
            token_ttl=settings.session_token_ttl,
        )
        request.app.state.session_issuer = issuer
    return issuer


def _get_trusted_issuer_dids(request: Request) -> set[str]:
    """Return the set of trusted issuer DIDs from app state (best-effort)."""
    trusted: set = set()
    trust_client = getattr(request.app.state, "trust_client", None)
    if trust_client is not None:
        # TrustLayerClient may expose a synchronous cache — use what's available
        try:
            cached: set = getattr(trust_client, "_cached_trusted_dids", set())
            trusted.update(cached)
        except Exception:
            pass
    return trusted


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/nonce", summary="Issue a single-use nonce for KB-JWT binding")
async def get_nonce(request: Request) -> JSONResponse:
    """Return a short-lived nonce.

    The consumer must embed this nonce in the ``nonce`` claim of the KB-JWT
    when calling ``POST /auth/session``.  Each nonce is valid for
    ``SESSION_NONCE_TTL`` seconds (default 60) and can only be used once.

    Response::

        { "nonce": "<uuid4>" }
    """
    nonce_store = _get_nonce_store(request)
    nonce = await nonce_store.issue()
    return JSONResponse(content={"nonce": nonce})


@router.post("/session", summary="Exchange an SD-JWT presentation for a session token")
async def post_session(request: Request) -> JSONResponse:
    """Verify an SD-JWT + KB-JWT presentation and return a session JWT.

    Request body (``Content-Type: application/x-www-form-urlencoded`` or
    ``application/json``)::

        { "presentation": "<SD-JWT>~~<KB-JWT>" }

    Success response (HTTP 200)::

        { "token": "<session-jwt>", "expires_in": <seconds> }

    Error responses never reveal internal claim details.
    """
    settings = request.app.state.settings
    nonce_store = _get_nonce_store(request)
    session_issuer = _get_session_issuer(request)

    # ── Parse request body ──────────────────────────────────────────────
    content_type = request.headers.get("content-type", "")
    try:
        if "application/json" in content_type:
            body = await request.json()
            presentation: str = body.get("presentation", "")
        else:
            form = await request.form()
            presentation = str(form.get("presentation", ""))
    except Exception:
        return JSONResponse(status_code=400, content={"error": "INVALID_REQUEST_BODY"})

    if not presentation:
        return JSONResponse(status_code=400, content={"error": "MISSING_PRESENTATION"})

    # ── Rate limit by consumer DID (pre-verification peek) ─────────────
    peeked = _peek_sd_jwt_payload(presentation)
    consumer_did_hint = peeked.get("sub", peeked.get("iss", "unknown"))
    if not _check_rate_limit(consumer_did_hint, settings.session_rate_limit_per_minute):
        logger.warning(
            "session_exchange rate_limit_exceeded consumer_did_hint=%s",
            consumer_did_hint[:32] if consumer_did_hint else "?",
        )
        return JSONResponse(status_code=429, content={"error": "RATE_LIMIT_EXCEEDED"})

    # ── Extract nonce from KB-JWT WITHOUT consuming it yet ──────────────
    from common.vc_engine.sd_jwt import parse_sd_presentation

    try:
        _, _, kb_jwt_str = parse_sd_presentation(presentation)
    except Exception:
        return JSONResponse(status_code=400, content={"error": "INVALID_PRESENTATION_FORMAT"})

    kb_nonce = _peek_kb_nonce(kb_jwt_str)
    if not kb_nonce:
        return JSONResponse(status_code=400, content={"error": "MISSING_NONCE_IN_KB_JWT"})

    # ── Consume nonce atomically BEFORE full verification ───────────────
    # By consuming first we guarantee single-use even if verification later
    # fails (e.g., second attempt with the same nonce is rejected).
    nonce_valid = await nonce_store.consume(kb_nonce)
    if not nonce_valid:
        logger.warning("session_exchange invalid_or_replayed_nonce")
        return JSONResponse(status_code=401, content={"error": "INVALID_OR_REPLAYED_NONCE"})

    # ── Full SD-JWT + KB-JWT verification ───────────────────────────────
    from common.vc_engine.resolver import DIDResolver
    from common.vc_engine.sd_jwt import verify_sd_jwt_with_kb

    trusted_dids = _get_trusted_issuer_dids(request)

    try:
        verified_vc = await verify_sd_jwt_with_kb(
            presentation=presentation,
            trusted_issuer_dids=trusted_dids,
            resolver=DIDResolver(),
            aud=settings.sentinel_did or "",
            nonce=kb_nonce,
        )
    except Exception as exc:
        logger.warning("session_exchange verification_failed: %s", exc)
        return JSONResponse(status_code=401, content={"error": "VERIFICATION_FAILED"})

    # ── Extract scope from VC payload ───────────────────────────────────
    scope = _extract_scope(verified_vc)

    # ── Issue session JWT ────────────────────────────────────────────────
    session_token = session_issuer.issue(
        consumer_did=verified_vc.subject_did or verified_vc.issuer_did,
        scope=scope,
    )

    logger.info(
        "session_exchange issued token consumer_did_hash=%.16s",
        _sha256_prefix(verified_vc.subject_did or verified_vc.issuer_did),
    )

    return JSONResponse(content={
        "token": session_token,
        "expires_in": settings.session_token_ttl,
    })


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _peek_kb_nonce(kb_jwt_str: str) -> str:
    """Decode the KB-JWT payload (no verification) and return the nonce claim."""
    import base64

    try:
        parts = kb_jwt_str.split(".")
        if len(parts) != 3:
            return ""
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        return str(payload.get("nonce", ""))
    except Exception:
        return ""


def _extract_scope(verified_vc) -> list:
    """Pull the scope list from a VerifiedCredential payload (best-effort)."""
    try:
        vc_payload = getattr(verified_vc, "payload", {}) or {}
        # SD-JWT carries claims flat; W3C VC wraps in "vc"
        vc_claims = vc_payload.get("vc", vc_payload)
        cs = vc_claims.get("credentialSubject", vc_claims)
        scope = cs.get("scope", [])
        if isinstance(scope, list):
            return scope
    except Exception:
        pass
    return []


def _sha256_prefix(value: str) -> str:
    import hashlib
    return hashlib.sha256(value.encode()).hexdigest()
