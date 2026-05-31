"""OutboundPipeline — consumer outbound request orchestrator (TASK-044).

Orchestrates the full flow:
  1. Resolve ServiceDescriptor (with signature verification)
  2. Select credentials from local store
  3. Select producer endpoint (weighted round-robin + circuit breaker)
  4. Build VP + ProofClaims (fresh jti per attempt)
  5. Send request with retry (up to 3 attempts, new jti per retry)
  6. Return producer response or structured error

See TASK-043 RETRY_SAFETY.md: jti + VP MUST be regenerated per retry.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
import uuid
from typing import Optional

import httpx

from sentinel.consumer.credential_selector import NoCredentialAvailable, select_credentials, select_sd_jwt_credential
from sentinel.consumer.descriptor_cache import DescriptorCache, DescriptorInvalid, ServiceNotFound
from sentinel.consumer.endpoint_selector import EndpointSelector, NoEndpointsAvailable

logger = logging.getLogger(__name__)

# Hop-by-hop headers that must never be forwarded
_HOP_BY_HOP = frozenset({
    "connection", "transfer-encoding", "upgrade", "keep-alive",
    "proxy-authenticate", "proxy-authorization", "te", "trailers",
})
# Retry backoff schedule (seconds) — one entry per inter-attempt pause
_BACKOFF = [0.5, 1.0]
# HTTP status codes that are NOT retried (definitive rejections)
_NO_RETRY_STATUSES = frozenset({400, 401, 403, 422})
_MAX_ATTEMPTS = 3

# Session cache entry: (token_str, exp_timestamp_unix)
_SessionEntry = tuple[str, float]


class OutboundPipeline:
    """Orchestrate consumer outbound requests to a producer sentinel.

    Args:
        http_client:        Shared ``httpx.AsyncClient``.
        descriptor_cache:   DescriptorCache for resolving ServiceDescriptors.
        endpoint_selector:  EndpointSelector (can be shared or per-pipeline).
        consumer_did:       Consumer sentinel's DID.
        consumer_key_bytes: Raw 32-byte Ed25519 private key.
        credential_store:   Local credential store for VC selection.
    """

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        descriptor_cache: DescriptorCache,
        endpoint_selector: EndpointSelector,
        consumer_did: str,
        consumer_key_bytes: bytes,
        credential_store=None,
    ) -> None:
        self._http_client = http_client
        self._descriptor_cache = descriptor_cache
        self._endpoint_selector = endpoint_selector
        self._consumer_did = consumer_did
        self._consumer_key = consumer_key_bytes
        self._credential_store = credential_store
        # Session token cache: {producer_did: (token, exp_unix)}
        self._session_cache: dict[str, _SessionEntry] = {}

    async def send(
        self,
        service_id: str,
        path: str,
        method: str,
        headers: dict,
        body: bytes,
        query_params: dict,
        env: str,
        correlation_id: Optional[str] = None,
    ) -> httpx.Response:
        """Execute the outbound pipeline.

        Returns the final httpx.Response (2xx) or raises after exhausting retries.

        Raises:
            ServiceNotFound:        Discovery unreachable + cache empty → 503.
            DescriptorInvalid:      Descriptor signature invalid → 502.
            NoCredentialAvailable:  No VC for service_id+env → 403.
            NoEndpointsAvailable:   All endpoints unhealthy → 503.
            httpx.HTTPError:        All retries failed → 503.
        """
        # ── Resolve descriptor ───────────────────────────────────────────
        descriptor = await self._descriptor_cache.get(service_id, env)

        # ── Try session token fast-path ──────────────────────────────────
        # If we have a cached session token that is still valid we can skip
        # building the full VP envelope (no SD-JWT or W3C VC presentation).
        producer_did = descriptor.service_did
        session_token = self._get_cached_session(producer_did)

        if session_token is None:
            # Attempt to acquire a session token via SD-JWT exchange
            try:
                session_token = await self._exchange_session(
                    descriptor=descriptor,
                    service_id=service_id,
                    env=env,
                )
            except Exception as _ex:
                logger.debug(
                    "session_exchange skipped (will use VP): %s", _ex
                )

        # ── Select credentials (needed for VP path) ──────────────────────
        vcs = self._get_credentials(service_id, env)

        # ── Build proxy (strip hop-by-hop, keep original headers) ────────
        forward_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in _HOP_BY_HOP and k.lower() != "authorization"
        }
        if correlation_id:
            forward_headers["X-Correlation-ID"] = correlation_id

        # ── Retry loop ───────────────────────────────────────────────────
        last_exc: Optional[Exception] = None
        for attempt in range(_MAX_ATTEMPTS):
            if attempt > 0:
                backoff = _BACKOFF[min(attempt - 1, len(_BACKOFF) - 1)]
                backoff += random.uniform(0, 0.1)
                await asyncio.sleep(backoff)
                logger.warning(
                    "outbound_retry attempt=%d service_id=%s reason=%s",
                    attempt + 1, service_id, str(last_exc),
                )

            # Re-select endpoint on each attempt (may pick different one)
            endpoint_url = self._endpoint_selector.select(descriptor.endpoints)
            target_url = f"{endpoint_url.rstrip('/')}/{path.lstrip('/')}"

            # Generate FRESH jti + VP + proof per attempt
            jti = str(uuid.uuid4())

            if session_token:
                # Fast path: use Bearer session token, no VP needed
                request_headers = {
                    **forward_headers,
                    "Authorization": f"Bearer {session_token}",
                    "X-Correlation-ID": correlation_id or "",
                }
                request_url = target_url
                if query_params:
                    from urllib.parse import urlencode
                    request_url = f"{target_url}?{urlencode(query_params)}"
            else:
                request_headers, request_url = await self._build_envelope(
                    method=method,
                    target_url=target_url,
                    query_params=query_params,
                    body=body,
                    aud=descriptor.service_did,
                    env=env,
                    jti=jti,
                    vcs=vcs,
                    forward_headers=forward_headers,
                )

            try:
                response = await self._http_client.request(
                    method=method,
                    url=target_url,
                    headers=request_headers,
                    content=body,
                    params=query_params,
                    timeout=httpx.Timeout(30.0, connect=5.0, write=10.0, pool=5.0),
                )
                self._endpoint_selector.record_success(endpoint_url)

                if response.status_code in _NO_RETRY_STATUSES:
                    # Definitive rejection — don't retry
                    return response

                if response.status_code < 500:
                    return response

                # 5xx — retry
                last_exc = httpx.HTTPStatusError(
                    f"Upstream {response.status_code}",
                    request=response.request,
                    response=response,
                )
                self._endpoint_selector.record_failure(endpoint_url)

            except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError) as exc:
                self._endpoint_selector.record_failure(endpoint_url)
                last_exc = exc

        raise last_exc or httpx.RequestError("All retries exhausted")

    def _get_credentials(self, service_id: str, env: str) -> list:
        if self._credential_store is None:
            return []  # no store configured — empty VC list (VP with no VCs)
        try:
            return select_credentials(service_id, env, self._credential_store, self._consumer_key)
        except NoCredentialAvailable:
            return []

    async def _build_envelope(
        self,
        method: str,
        target_url: str,
        query_params: dict,
        body: bytes,
        aud: str,
        env: str,
        jti: str,
        vcs: list,
        forward_headers: dict,
    ) -> tuple[dict, str]:
        """Build proof + VP headers for one attempt."""
        from common.security_envelope.builder import ProofClaimsBuilder, build_secure_headers
        from common.vc_engine.builder import create_vp

        # Build URL with query for hashing
        full_url = target_url
        if query_params:
            from urllib.parse import urlencode
            full_url = f"{target_url}?{urlencode(query_params)}"

        builder = ProofClaimsBuilder(self._consumer_did, self._consumer_key)
        proof_jwt, _ = builder.build(
            method=method,
            url=full_url,
            body=body if body else None,
            aud=aud,
            env=env,
            jti=jti,
        )
        vp_jwt = create_vp(
            vcs=vcs,
            holder_did=self._consumer_did,
            holder_key_bytes=self._consumer_key,
            aud=aud,
            nonce=jti,
            env=env,
            exp_seconds=60,
        )

        headers = {**forward_headers, **build_secure_headers(proof_jwt, vp_jwt)}
        return headers, full_url

    # ------------------------------------------------------------------
    # Session token helpers
    # ------------------------------------------------------------------

    def _get_cached_session(self, producer_did: str) -> Optional[str]:
        """Return a cached session token if still valid (>60s remaining), else None."""
        entry = self._session_cache.get(producer_did)
        if entry is None:
            return None
        token, exp = entry
        if time.time() + 60 >= exp:
            del self._session_cache[producer_did]
            return None
        return token

    async def _exchange_session(self, descriptor, service_id: str, env: str) -> Optional[str]:
        """Perform the session-exchange handshake with the producer sentinel.

        1. Picks the best endpoint URL from the descriptor.
        2. Selects an SD-JWT credential from the local store.
        3. GET /auth/nonce, builds KB-JWT, POST /auth/session.
        4. Returns the session token string (and caches it).

        Raises ``Exception`` on any failure so the caller can fall back to
        the full VP path.
        """
        if self._credential_store is None:
            raise RuntimeError("No credential store — cannot perform session exchange")

        sd_jwt_raw = select_sd_jwt_credential(service_id, env, self._credential_store, self._consumer_key)
        if not sd_jwt_raw:
            raise RuntimeError(f"No SD-JWT credential for service={service_id!r} env={env!r}")

        # Pick endpoint
        endpoint_url = self._endpoint_selector.select(descriptor.endpoints)
        base = endpoint_url.rstrip("/")

        producer_did = descriptor.service_did

        # Step 1: GET nonce
        nonce_resp = await self._http_client.get(
            f"{base}/auth/nonce",
            timeout=httpx.Timeout(10.0),
        )
        nonce_resp.raise_for_status()
        nonce = nonce_resp.json().get("nonce", "")
        if not nonce:
            raise ValueError("Producer returned empty nonce")

        # Step 2: Build KB-JWT and full presentation
        from common.vc_engine.sd_jwt import build_kb_jwt, build_sd_presentation

        # SD-JWT issuer part is everything before the first '~'
        sd_jwt_issuer = sd_jwt_raw.split("~")[0]
        disclosures: list[str] = []  # full-disclosure mode; no hidden claims

        presentation = build_sd_presentation(
            sd_jwt=sd_jwt_issuer,
            disclosures=disclosures,
            holder_private_key_bytes=self._consumer_key,
            aud=producer_did,
            nonce=nonce,
        )

        # Step 3: POST /auth/session
        session_resp = await self._http_client.post(
            f"{base}/auth/session",
            json={"presentation": presentation},
            timeout=httpx.Timeout(10.0),
        )
        session_resp.raise_for_status()
        data = session_resp.json()
        token: str = data.get("token", "")
        if not token:
            raise ValueError("Producer returned empty session token")
        expires_in: int = int(data.get("expires_in", 900))

        # Cache the token (expire it 60s early to avoid clock-skew issues)
        self._session_cache[producer_did] = (token, time.time() + expires_in - 60)

        logger.info(
            "session_exchange complete producer_did_prefix=%.16s expires_in=%d",
            producer_did,
            expires_in,
        )
        return token

