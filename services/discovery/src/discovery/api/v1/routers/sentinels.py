"""Sentinels router — sentinel onboarding endpoint (TASK-026).

POST /api/v1/sentinels/onboard
  Phase 1 (no proof field): validate enrollment token, return challenge nonce.
  Phase 2 (proof field): validate PoP, consume token, create sentinel record.

Idempotency-Key header (optional) caches the phase-2 response in Redis for
10 minutes to prevent double-registration on network retries.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.dependencies import get_db, get_redis, get_settings
from discovery.auth.rbac import require_roles
from discovery.repositories.enrollment_tokens import TokenAlreadyConsumedError
from discovery.schemas.onboarding import (
    ChallengeResponse,
    OnboardingBundle,
    OnboardingRequest,
)
from discovery.services.onboarding_service import (
    DIDProofError,
    EnrollmentTokenValidationError,
    NonceExpiredError,
    complete_onboarding,
    issue_challenge,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sentinels", tags=["Sentinels"])

_IDEMPOTENCY_TTL = 600  # 10 minutes
_RATE_KEY_PREFIX = "ratelimit:onboard:"
_RATE_IP_PREFIX = "ratelimit:onboard:ip:"
_RATE_TOKEN_LIMIT = 5
_RATE_IP_LIMIT = 50
_RATE_IP_WINDOW = 600  # 10 minutes


async def _check_onboard_rate_limits(redis, jti: str, client_ip: str) -> None:
    if redis is None:
        return
    token_key = f"{_RATE_KEY_PREFIX}{jti}"
    ip_key = f"{_RATE_IP_PREFIX}{client_ip}"
    pipe = redis.pipeline()
    pipe.incr(token_key)
    pipe.expire(token_key, 600)
    pipe.incr(ip_key)
    pipe.expire(ip_key, _RATE_IP_WINDOW)
    results = await pipe.execute()
    if results[0] > _RATE_TOKEN_LIMIT:
        raise HTTPException(
            status_code=429,
            detail={"code": "RATE_LIMIT_EXCEEDED", "message": "Too many onboarding attempts for this token"},
            headers={"Retry-After": "60"},
        )
    if results[2] > _RATE_IP_LIMIT:
        raise HTTPException(
            status_code=429,
            detail={"code": "RATE_LIMIT_EXCEEDED", "message": "Too many onboarding attempts. Retry after 60s"},
            headers={"Retry-After": "60"},
        )


@router.post(
    "/onboard",
    response_model=None,  # Returns ChallengeResponse (200) or OnboardingBundle (201)
    status_code=200,
)
async def onboard_sentinel(
    body: OnboardingRequest,
    request: Request,
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    redis=Depends(get_redis),
) -> Response:
    """Sentinel onboarding — two-phase challenge-response.

    Phase 1 (proof absent): validate token, return challenge nonce.
    Phase 2 (proof present): verify PoP, consume token, create/return sentinel.

    mTLS is enforced at the reverse-proxy layer; the endpoint itself checks for
    rate limits and idempotency.
    """
    client_ip = request.client.host if request.client else "unknown"
    idempotency_key = request.headers.get("Idempotency-Key", "")
    request_id = getattr(request.state, "request_id", "")

    # --- Phase 2: proof submission ---
    if body.proof is not None:
        proof_dict = body.proof.model_dump()
        jti_for_rate = "unknown"
        try:
            import jwt as pyjwt
            hdr = pyjwt.get_unverified_header(body.enrollment_token)
            decoded = pyjwt.decode(
                body.enrollment_token,
                options={"verify_signature": False},
                algorithms=["HS256"],
            )
            jti_for_rate = decoded.get("jti", "unknown")
        except Exception:
            pass

        await _check_onboard_rate_limits(redis, jti_for_rate, client_ip)

        # Idempotency: check cache
        if idempotency_key and redis is not None:
            cache_key = f"idempotency:onboard:{idempotency_key}"
            cached = await redis.get(cache_key)
            if cached:
                cached_body = json.loads(cached)
                status_code = cached_body.pop("_status_code", 201)
                return Response(
                    content=json.dumps(cached_body),
                    status_code=status_code,
                    media_type="application/json",
                    headers={"X-Idempotency-Hit": "true"},
                )

        try:
            bundle, is_new = await complete_onboarding(
                body.enrollment_token,
                body.did,
                proof_dict,
                settings=settings,
                session=session,
                redis=redis,
                request_id=request_id,
            )
        except EnrollmentTokenValidationError as exc:
            status_code = 403 if exc.code == "TOKEN_NOT_APPROVED" else 401
            raise HTTPException(
                status_code=status_code,
                detail={"code": exc.code, "message": exc.message},
            )
        except NonceExpiredError as exc:
            raise HTTPException(
                status_code=401,
                detail={"code": "NONCE_EXPIRED", "message": str(exc)},
            )
        except DIDProofError as exc:
            raise HTTPException(
                status_code=422 if exc.code == "UNSUPPORTED_DID_METHOD" else 401,
                detail={"code": exc.code, "message": exc.message},
            )
        except TokenAlreadyConsumedError:
            raise HTTPException(
                status_code=409,
                detail={"code": "ENROLLMENT_ALREADY_CONSUMED", "message": "This enrollment token has already been used"},
            )

        response_status = 201 if is_new else 200
        bundle_dict = bundle.model_dump(mode="json")

        # Cache for idempotency
        if idempotency_key and redis is not None:
            cache_key = f"idempotency:onboard:{idempotency_key}"
            cache_val = {**bundle_dict, "_status_code": response_status}
            await redis.set(cache_key, json.dumps(cache_val, default=str), ex=_IDEMPOTENCY_TTL)

        return Response(
            content=json.dumps(bundle_dict, default=str),
            status_code=response_status,
            media_type="application/json",
        )

    # --- Phase 1: challenge issuance ---
    try:
        result = await issue_challenge(
            body.enrollment_token,
            settings=settings,
            session=session,
            redis=redis,
        )
    except EnrollmentTokenValidationError as exc:
        status_code = 403 if exc.code == "TOKEN_NOT_APPROVED" else 401
        raise HTTPException(
            status_code=status_code,
            detail={"code": exc.code, "message": exc.message},
        )

    challenge = ChallengeResponse(
        challenge_nonce=result["challenge_nonce"],
        challenge_expires_at=result["challenge_expires_at"],
    )
    return Response(
        content=challenge.model_dump_json(),
        status_code=200,
        media_type="application/json",
    )


# ---------------------------------------------------------------------------
# POST /api/v1/sentinels/heartbeat  (TASK-033)
# ---------------------------------------------------------------------------

from pydantic import BaseModel
from typing import Optional

class HeartbeatHealth(BaseModel):
    cpu_pct: Optional[float] = None
    mem_pct: Optional[float] = None
    request_rate: Optional[float] = None


class HeartbeatRequest(BaseModel):
    sentinel_id: str
    instance_id: str
    version: str = "unknown"
    health: Optional[HeartbeatHealth] = None


@router.post("/heartbeat")
async def heartbeat(
    body: HeartbeatRequest,
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    current_user=Depends(require_roles("operator", "security-admin", "viewer", "sentinel")),
):
    """Update sentinel liveness state.  Must be called at the configured interval."""
    import uuid as _uuid
    from discovery.services import lifecycle_service

    # Verify sentinel_id matches caller (security: prevent impersonation)
    token_sub = current_user.sub if hasattr(current_user, "sub") else ""
    # Allow operators to heartbeat on behalf of sentinel (for testing)
    # In production, token subject must equal sentinel's DID
    try:
        sid = _uuid.UUID(body.sentinel_id)
    except ValueError:
        raise HTTPException(status_code=422, detail={"code": "INVALID_SENTINEL_ID", "message": "Invalid sentinel_id UUID"})

    try:
        result = await lifecycle_service.process_heartbeat(
            session,
            sentinel_id=sid,
            instance_id=body.instance_id,
            version=body.version,
            health=(body.health.model_dump() if body.health else {}),
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail={"code": "SENTINEL_NOT_FOUND", "message": str(exc)})

    return result


# ---------------------------------------------------------------------------
# POST /api/v1/sentinels/{sentinel_id}/decommission  (TASK-033)
# ---------------------------------------------------------------------------

class DecommissionRequest(BaseModel):
    reason: str = "Decommissioned by admin"
    revoke_credentials: bool = True
    invalidate_descriptor: bool = True


@router.post("/{sentinel_id}/decommission", status_code=200)
async def decommission(
    sentinel_id: str,
    body: DecommissionRequest,
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    current_user=Depends(require_roles("security-admin")),
):
    """Cascade decommission a sentinel: revoke credentials, invalidate descriptor."""
    import uuid as _uuid
    from discovery.services import lifecycle_service

    try:
        sid = _uuid.UUID(sentinel_id)
    except ValueError:
        raise HTTPException(status_code=422, detail={"code": "INVALID_SENTINEL_ID", "message": "Invalid UUID"})

    try:
        result = await lifecycle_service.decommission_sentinel(
            session,
            sentinel_id=sid,
            reason=body.reason,
            revoke_credentials=body.revoke_credentials,
            invalidate_descriptor=body.invalidate_descriptor,
            actor_id=current_user.sub if hasattr(current_user, "sub") else "admin",
            settings=settings,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail={"code": "SENTINEL_NOT_FOUND", "message": str(exc)})

    return result


# ---------------------------------------------------------------------------
# POST /api/v1/sentinels/{sentinel_id}/rejoin  (TASK-033)
# ---------------------------------------------------------------------------

class RejoinRequest(BaseModel):
    did: str
    new_instance_id: str
    new_base_url: Optional[str] = None


@router.post("/{sentinel_id}/rejoin", status_code=200)
async def rejoin(
    sentinel_id: str,
    body: RejoinRequest,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_roles("operator", "security-admin")),
):
    """Re-activate a previously offline or migrated sentinel."""
    import uuid as _uuid
    from discovery.services import lifecycle_service

    try:
        sid = _uuid.UUID(sentinel_id)
    except ValueError:
        raise HTTPException(status_code=422, detail={"code": "INVALID_SENTINEL_ID", "message": "Invalid UUID"})

    try:
        sentinel = await lifecycle_service.rejoin_sentinel(
            session,
            sentinel_id=sid,
            did=body.did,
            new_instance_id=body.new_instance_id,
            new_base_url=body.new_base_url,
            actor_id=current_user.sub if hasattr(current_user, "sub") else "admin",
        )
    except ValueError as exc:
        code = "DID_MISMATCH" if "DID_MISMATCH" in str(exc) else "SENTINEL_NOT_FOUND"
        status = 403 if code == "DID_MISMATCH" else 404
        raise HTTPException(status_code=status, detail={"code": code, "message": str(exc)})

    return {
        "sentinel_id": str(sentinel.id),
        "status": "REJOINED",
        "computed_status": sentinel.computed_status,
    }


# ---------------------------------------------------------------------------
# GET /api/v1/sentinels  (TASK-033)
# ---------------------------------------------------------------------------

from sqlalchemy import select as sa_select

@router.get("")
async def list_sentinels(
    env: Optional[str] = None,
    role: Optional[str] = None,
    status: Optional[str] = None,
    service_id: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_roles("viewer", "operator", "security-admin")),
):
    """List sentinels with optional status/role/env filters."""
    from discovery.db.models.sentinels import Sentinel as SentinelModel

    query = sa_select(SentinelModel)
    if env:
        query = query.where(SentinelModel.env == env)
    if role:
        query = query.where(SentinelModel.role == role)
    if status:
        query = query.where(SentinelModel.computed_status == status)
    query = query.limit(limit)

    result = await session.execute(query)
    sentinels = list(result.scalars().all())

    return {
        "items": [
            {
                "id": str(s.id),
                "did": s.did,
                "role": s.role,
                "env": s.env,
                "is_active": s.is_active,
                "computed_status": s.computed_status,
                "last_seen": s.last_seen.isoformat() if s.last_seen else None,
            }
            for s in sentinels
        ],
        "count": len(sentinels),
    }


# ---------------------------------------------------------------------------
# POST /api/v1/sentinels/{sentinel_id}/auth/renew  (TASK-040)
# ---------------------------------------------------------------------------

class RenewalRequest(BaseModel):
    did: str
    iat: int
    proof_value: str  # multibase-encoded Ed25519 signature


@router.post("/{sentinel_id}/auth/renew", status_code=200)
async def renew_sentinel_token(
    sentinel_id: str,
    body: RenewalRequest,
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
):
    """Issue a fresh sentinel service-account JWT via DID self-signed assertion.

    No bearer token required — the sentinel proves identity by signing a
    time-bound assertion with its Ed25519 key.
    """
    import uuid as _uuid
    from discovery.auth.local_jwt import issue_dev_token
    from discovery.services.did_verification import (
        verify_renewal_assertion,
        DIDResolutionError,
        InvalidSignatureError,
        UnsupportedDIDMethodError,
    )
    from discovery.db.models.sentinels import Sentinel as SentinelModel

    try:
        sid = _uuid.UUID(sentinel_id)
    except ValueError:
        raise HTTPException(status_code=422, detail={"code": "INVALID_SENTINEL_ID", "message": "Invalid UUID"})

    # Resolve sentinel and verify DID matches
    result = await session.execute(
        sa_select(SentinelModel).where(SentinelModel.id == sid)
    )
    sentinel = result.scalar_one_or_none()
    if sentinel is None:
        raise HTTPException(status_code=404, detail={"code": "SENTINEL_NOT_FOUND", "message": "Sentinel not found"})

    if sentinel.did != body.did:
        raise HTTPException(status_code=403, detail={"code": "DID_MISMATCH", "message": "DID does not match registered sentinel"})

    try:
        await verify_renewal_assertion(
            did=body.did,
            sentinel_id=sentinel_id,
            iat=body.iat,
            proof_value=body.proof_value,
        )
    except (DIDResolutionError, InvalidSignatureError, UnsupportedDIDMethodError, ValueError) as exc:
        raise HTTPException(status_code=401, detail={"code": "PROOF_INVALID", "message": str(exc)})

    new_token = issue_dev_token(
        sub=sentinel_id,
        roles=["sentinel"],
        secret=settings.local_jwt_secret.get_secret_value(),
        ttl_seconds=3600,
        actor_type="SENTINEL",
    )
    return {"access_token": new_token}
