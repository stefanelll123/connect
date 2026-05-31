"""InboundPipeline — 8-stage producer-side request verification pipeline (TASK-045).

Stages:
  1. Request size and timeout enforcement (max 2MB, 10s total)
  2. Extract SentinelProof + SentinelVP security headers
  3. ProofClaims signature + binding + replay verification → VerificationContext
  4. VP / VC cryptographic verification (via ProofVerifier, stage 3 includes this)
  5. Per-VC issuer trust check via TrustLayerClient
  6. Per-VC revocation freshness check via RevocationManager (optional injection)
  7. Policy evaluation → permit / deny
  8. Forward to backend (scrub internal headers), stream response

On permit, the backend response is returned unchanged (minus internal headers).
On deny, a JSON error response {error, request_id} is returned — never leaking
internal claim details.

Structured audit log is emitted after every request.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional, Set

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse, Response

from sentinel.producer.pipeline_context import PipelineContext

logger = logging.getLogger(__name__)

# ── Pipeline constants ───────────────────────────────────────────────────────
_MAX_BODY_BYTES = 2 * 1024 * 1024          # 2MB
_PIPELINE_STAGE_TIMEOUT_SECONDS = 10.0    # excludes backend I/O
_BACKEND_TIMEOUT_SECONDS = 30.0

# Headers that must never be forwarded to the backend
_STRIP_TO_BACKEND = frozenset({
    "authorization", "sentinelvp",
    "host",
    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "x-internal-",   # prefix check done manually
})

# Headers to strip from backend response before returning to consumer
_STRIP_FROM_BACKEND = frozenset({
    "transfer-encoding", "connection",
})


def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(padded)


def _decode_jwt_payload(jwt_str: str) -> dict:
    """Decode JWT payload without signature verification."""
    parts = jwt_str.split(".")
    if len(parts) != 3:
        return {}
    try:
        return json.loads(_b64url_decode(parts[1]))
    except Exception:
        return {}


def _deny(error_code: str, request_id: str, status: int = 401) -> JSONResponse:
    """Return a minimal deny response — never leaks internal details."""
    return JSONResponse(
        status_code=status,
        content={"error": error_code, "request_id": request_id},
    )


class _StubPolicyEngine:
    """Stub ABAC policy engine (TASK-047 will replace this)."""

    async def evaluate(
        self,
        resource: str,
        method: str,
        env: str,
        consumer_did: str,
        vcs: list,
    ) -> bool:
        """Always permits. TASK-047 implements real ABAC."""
        return True


class InboundPipeline:
    """8-stage producer inbound verification pipeline.

    Args:
        service_did:      This producer sentinel's DID (audience of proof).
        service_id:       Service identifier (for audit logs).
        env:              Deployment environment.
        resolver:         DIDResolver instance.
        replay_cache:     ReplayCache instance.
        trust_client:     TrustLayerClient (optional; if None, trust checks are skipped).
        revocation_manager: RevocationManager (optional; if None, revocation skipped).
        http_client:      httpx.AsyncClient for forwarding to backend.
        backend_url:      Upstream backend base URL.
        max_clock_skew:   Max clock skew accepted in proof timestamps.
        policy_engine:    ABAC policy engine; defaults to permissive stub.
        session_issuer:   :class:`~sentinel.producer.session.SessionTokenIssuer` instance.
                          When supplied, a valid ``Bearer`` session token in the
                          ``Authorization`` header bypasses the full VP pipeline
                          (Stage 0 fast-path).
    """

    def __init__(
        self,
        *,
        service_did: str,
        service_id: str,
        env: str,
        resolver,
        replay_cache,
        trust_client=None,
        revocation_manager=None,
        http_client: httpx.AsyncClient,
        backend_url: str,
        max_clock_skew: int = 300,
        policy_engine=None,
        session_issuer=None,
    ) -> None:
        self._service_did = service_did
        self._service_id = service_id
        self._env = env
        self._resolver = resolver
        self._replay_cache = replay_cache
        self._trust_client = trust_client
        self._revocation_manager = revocation_manager
        self._http_client = http_client
        self._backend_url = backend_url.rstrip("/")
        self._max_clock_skew = max_clock_skew
        self._policy_engine = policy_engine or _StubPolicyEngine()
        self._session_issuer = session_issuer

        from common.security_envelope.verifier import ProofVerifier
        self._proof_verifier = ProofVerifier(max_clock_skew=max_clock_skew)

    async def process(self, request: Request, full_path: str) -> Response:
        """Run the 8-stage pipeline and return an appropriate HTTP response."""
        request_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        ctx = PipelineContext(
            request_id=request_id,
            method=request.method,
            path=full_path,
            service_id=self._service_id,
            env=self._env,
        )

        try:
            response = await asyncio.wait_for(
                self._run_pipeline(request, full_path, ctx),
                timeout=_PIPELINE_STAGE_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            ctx.error_code = "PIPELINE_TIMEOUT"
            ctx.denied_at_stage = "timeout"
            self._audit(ctx)
            return _deny("PIPELINE_TIMEOUT", request_id, status=504)

        return response

    async def _run_pipeline(
        self, request: Request, full_path: str, ctx: PipelineContext
    ) -> Response:
        """Inner pipeline; wrapped in wait_for for timeout enforcement."""
        request_id = ctx.request_id

        # ── Stage 0: Session token fast-path ────────────────────────────
        # If the consumer presents a valid Bearer session token previously
        # issued by this producer, skip the full VP pipeline and go straight
        # to the policy + backend stages.  This avoids re-verifying the
        # SD-JWT on every request after the initial session exchange.
        if self._session_issuer is not None:
            authorization = request.headers.get("Authorization", "")
            if authorization.startswith("Bearer "):
                token = authorization[len("Bearer "):].strip()
                try:
                    session_claims = self._session_issuer.verify(token)
                    ctx.consumer_did = session_claims.sub
                    ctx.record_stage("stage0_session_fast_path")

                    # Read body for forwarding (needed for stage 8)
                    body = await request.body()
                    if len(body) > _MAX_BODY_BYTES:
                        ctx.error_code = "REQUEST_TOO_LARGE"
                        ctx.denied_at_stage = "stage0_session_fast_path"
                        self._audit(ctx)
                        return _deny("REQUEST_TOO_LARGE", request_id, status=413)
                    ctx.body = body

                    # Stage 7: policy (session tokens carry scope)
                    try:
                        permitted = await self._policy_engine.evaluate(
                            resource=full_path,
                            method=request.method,
                            env=self._env,
                            consumer_did=ctx.consumer_did,
                            vcs=[],
                        )
                    except Exception as _policy_exc:
                        logger.error("Policy engine error (session path): %s", _policy_exc)
                        permitted = False

                    if not permitted:
                        ctx.error_code = "POLICY_DENY"
                        ctx.denied_at_stage = "stage0_policy"
                        self._audit(ctx)
                        return _deny("POLICY_DENY", request_id, status=403)

                    # Stage 8: forward
                    return await self._forward(request, full_path, ctx, body)

                except ValueError:
                    # Invalid / expired session token — fall through to full pipeline
                    pass

        # ── Stage 1: Request size ────────────────────────────────────────
        t0 = time.monotonic()
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > _MAX_BODY_BYTES:
            ctx.error_code = "REQUEST_TOO_LARGE"
            ctx.denied_at_stage = "stage1_size"
            self._audit(ctx)
            return _deny("REQUEST_TOO_LARGE", request_id, status=413)

        body = await request.body()
        if len(body) > _MAX_BODY_BYTES:
            ctx.error_code = "REQUEST_TOO_LARGE"
            ctx.denied_at_stage = "stage1_size"
            self._audit(ctx)
            return _deny("REQUEST_TOO_LARGE", request_id, status=413)

        ctx.body = body
        ctx.record_stage("stage1_size")

        # ── Stage 2: Extract security headers ────────────────────────────
        authorization = request.headers.get("Authorization", "")
        vp_header = request.headers.get("SentinelVP", "")

        if not authorization.startswith("SentinelProof "):
            ctx.error_code = "MISSING_PROOF"
            ctx.denied_at_stage = "stage2_headers"
            self._audit(ctx)
            return _deny("MISSING_PROOF", request_id)

        if not vp_header:
            ctx.error_code = "MISSING_VP"
            ctx.denied_at_stage = "stage2_headers"
            self._audit(ctx)
            return _deny("MISSING_VP", request_id)

        ctx.record_stage("stage2_headers")

        # ── Stage 3+4: Verify proof + VP/VC cryptography ─────────────────
        # Pre-extract VC issuers from (unverified) VP so we can build the
        # trusted_issuer_dids set needed by verify_vp's embedded VC checks.
        trusted_issuer_dids: Set[str] = await self._prefetch_trusted_issuers(vp_header)

        from common.security_envelope.errors import ProofError
        full_url = str(request.url)

        try:
            verification = await self._proof_verifier.verify(
                proof_header_value=authorization,
                vp_header_value=vp_header,
                body=body if body else None,
                url=full_url,
                method=request.method,
                expected_aud=self._service_did,
                expected_env=self._env,
                resolver=self._resolver,
                replay_cache=self._replay_cache,
                trusted_issuer_dids=trusted_issuer_dids if trusted_issuer_dids else None,
            )
        except ProofError as exc:
            ctx.error_code = exc.code.value
            ctx.denied_at_stage = "stage3_proof"
            self._audit(ctx)
            return _deny(exc.code.value, request_id, status=exc.http_status)

        ctx.consumer_did = verification.consumer_did
        ctx.jti = verification.jti
        ctx.proof_claims = verification.proof_claims
        ctx.verified_vcs = verification.verified_vcs
        ctx.record_stage("stage3_proof")

        # ── Stage 5: Per-VC issuer trust check ───────────────────────────
        if self._trust_client is not None and ctx.verified_vcs:
            try:
                for vc in ctx.verified_vcs:
                    schema_id = getattr(vc, "credential_type", None)
                    trusted = await self._trust_client.is_issuer_trusted(
                        vc.issuer_did,
                        schema_id=schema_id if isinstance(schema_id, str) else None,
                    )
                    if not trusted:
                        ctx.error_code = "ISSUER_NOT_TRUSTED"
                        ctx.denied_at_stage = "stage5_trust"
                        self._audit(ctx)
                        return _deny("ISSUER_NOT_TRUSTED", request_id)
            except Exception as exc:  # TrustLayerUnavailable or similar
                error_name = type(exc).__name__
                if "Unavailable" in error_name or "Unreachable" in error_name:
                    ctx.error_code = "TRUST_LAYER_UNAVAILABLE"
                    ctx.denied_at_stage = "stage5_trust"
                    self._audit(ctx)
                    return _deny("TRUST_LAYER_UNAVAILABLE", request_id, status=503)
                raise

        ctx.trust_checked = True
        ctx.record_stage("stage5_trust")

        # ── Stage 6: Revocation freshness check ──────────────────────────
        if self._revocation_manager is not None and ctx.verified_vcs:
            for vc in ctx.verified_vcs:
                vc_claims = _decode_jwt_payload(getattr(vc, "raw_jwt", ""))
                vc_claim = vc_claims.get("vc", vc_claims)
                cred_status = vc_claim.get("credentialStatus")
                if cred_status is None:
                    continue

                status_list_id = cred_status.get("statusListCredential", "")
                status_list_index = int(cred_status.get("statusListIndex", 0))
                vc_jti = getattr(vc, "jti", "") or vc_claims.get("jti", "")

                try:
                    result = await self._revocation_manager.check(
                        vc_jti, status_list_id, status_list_index
                    )
                    if getattr(result, "is_revoked", False):
                        ctx.error_code = "VC_REVOKED"
                        ctx.denied_at_stage = "stage6_revocation"
                        self._audit(ctx)
                        return _deny("VC_REVOKED", request_id)
                    if getattr(result, "stale", False):
                        ctx.stale_revocation = True  # audit log, don't deny
                except Exception as exc:
                    error_name = type(exc).__name__
                    if "Stale" in error_name:
                        # RevocationStatusStale → fail-closed
                        ctx.error_code = "REVOCATION_STATUS_STALE"
                        ctx.denied_at_stage = "stage6_revocation"
                        self._audit(ctx)
                        return _deny("REVOCATION_STATUS_STALE", request_id, status=503)
                    raise

        ctx.revocation_checked = True
        ctx.record_stage("stage6_revocation")

        # ── Stage 7: Policy evaluation ────────────────────────────────────
        try:
            permitted = await self._policy_engine.evaluate(
                resource=full_path,
                method=request.method,
                env=self._env,
                consumer_did=ctx.consumer_did,
                vcs=ctx.verified_vcs,
            )
        except Exception as exc:
            logger.error("Policy engine error: %s", exc)
            permitted = False

        if not permitted:
            ctx.error_code = "POLICY_DENY"
            ctx.denied_at_stage = "stage7_policy"
            self._audit(ctx)
            return _deny("POLICY_DENY", request_id, status=403)

        ctx.record_stage("stage7_policy")

        # ── Stage 8: Forward to backend ───────────────────────────────────
        return await self._forward(request, full_path, ctx, body)

    async def _forward(
        self,
        request: Request,
        full_path: str,
        ctx: "PipelineContext",
        body: bytes,
    ) -> Response:
        """Stage 8: forward the request to the upstream backend."""
        request_id = ctx.request_id
        upstream_url = f"{self._backend_url}/{full_path}"
        if request.url.query:
            upstream_url += f"?{request.url.query}"

        consumer_did_hash = hashlib.sha256(
            ctx.consumer_did.encode()
        ).hexdigest()[:16] if ctx.consumer_did else ""

        upstream_headers = {
            k: v for k, v in request.headers.items()
            if not self._should_strip_header(k)
        }
        upstream_headers["X-Sentinel-Consumer-DID-Hash"] = consumer_did_hash
        upstream_headers["X-Sentinel-Request-ID"] = request_id
        upstream_headers["X-Sentinel-Env"] = self._env

        try:
            upstream_resp = await self._http_client.request(
                method=request.method,
                url=upstream_url,
                headers=upstream_headers,
                content=body,
                timeout=_BACKEND_TIMEOUT_SECONDS,
                follow_redirects=False,
            )
        except httpx.TimeoutException:
            ctx.error_code = "BACKEND_TIMEOUT"
            ctx.denied_at_stage = "stage8_forward"
            self._audit(ctx)
            return _deny("BACKEND_TIMEOUT", request_id, status=504)
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            logger.error("Backend unreachable: %s", exc)
            ctx.error_code = "BACKEND_UNAVAILABLE"
            ctx.denied_at_stage = "stage8_forward"
            self._audit(ctx)
            return _deny("BACKEND_UNAVAILABLE", request_id, status=502)

        ctx.record_stage("stage8_forward")
        self._audit(ctx, decision="permit")

        resp_headers = {
            k: v for k, v in upstream_resp.headers.items()
            if k.lower() not in _STRIP_FROM_BACKEND
        }

        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type=upstream_resp.headers.get("content-type"),
        )

    def _should_strip_header(self, name: str) -> bool:
        lower = name.lower()
        if lower in _STRIP_TO_BACKEND:
            return True
        if lower.startswith("x-internal-"):
            return True
        return False

    async def _prefetch_trusted_issuers(self, vp_jwt: str) -> Set[str]:
        """Decode (without verification) VP and extract VC issuer DIDs.

        For each issuer, check with TrustLayerClient so the subsequent
        ProofVerifier.verify() call can pass a populated trusted_issuer_dids set.
        """
        if self._trust_client is None:
            return set()

        vp_payload = _decode_jwt_payload(vp_jwt)
        vp_claim = vp_payload.get("vp", {})
        vc_list: list = vp_claim.get("verifiableCredential", [])

        trusted: Set[str] = set()
        for vc_jwt in vc_list:
            vc_payload = _decode_jwt_payload(vc_jwt)
            issuer_did = vc_payload.get("iss", "")
            if issuer_did:
                try:
                    if await self._trust_client.is_issuer_trusted(issuer_did):
                        trusted.add(issuer_did)
                except Exception:
                    pass  # trust check failures handled in stage 5

        return trusted

    def _audit(self, ctx: PipelineContext, decision: str = "deny") -> None:
        """Emit structured audit log. Never logs full JTI, DID, or VC claims."""
        try:
            logger.info(
                "audit decision=%s error_code=%s request_id=%s "
                "jti_hash=%s consumer_did_hash=%s service_id=%s "
                "path=%s method=%s latency_ms=%.1f stage=%s stale_revocation=%s",
                decision,
                ctx.error_code or "null",
                ctx.request_id,
                ctx.jti_hash(),
                ctx.consumer_did_hash(),
                ctx.service_id,
                ctx.path,
                ctx.method,
                ctx.latency_ms(),
                ctx.denied_at_stage or "null",
                ctx.stale_revocation,
            )
        except Exception:
            pass  # audit log errors must never break the request path
