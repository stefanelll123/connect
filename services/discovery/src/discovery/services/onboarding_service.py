"""Sentinel onboarding business logic.

Implements the two-phase challenge-response handshake:

  Phase 1: validate enrollment token → issue nonce
  Phase 2: validate enrollment token + PoP proof → consume token + create sentinel

SECURITY:
  - Enrollment token JWT is verified before any state change.
  - Nonce is one-time-use (stored in Redis, deleted on first retrieval).
  - Token consumption uses SELECT FOR UPDATE SKIP LOCKED.
  - Idempotency-Key header returns cached response to prevent double-registration.
  - Raw token is never stored or logged; only jti is referenced in audit events.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import jwt  # PyJWT

from discovery.config import DiscoverySettings
from discovery.db.models.sentinels import Sentinel
from discovery.repositories.audit import audit_log
from discovery.repositories.enrollment_tokens import (
    EnrollmentTokenRepository,
    TokenAlreadyConsumedError,
    TokenExpiredError,
    TokenNotFoundError,
)
from discovery.repositories.nonce_store import NonceStore
from discovery.repositories.sentinels import SentinelRepository
from discovery.repositories.services import ServiceRepository
from discovery.schemas.onboarding import (
    ChainInfo,
    ContractAddresses,
    CredentialBundle,
    DiscoveryUrls,
    OnboardingBundle,
    RevocationInfo,
)
from discovery.services.credential_issuer import (
    IssuerNotActiveError,
    issue_sentinel_identity,
)
from discovery.services.did_verification import (
    DIDResolutionError,
    InvalidSignatureError,
    UnsupportedDIDMethodError,
    verify_pop,
)
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class EnrollmentTokenValidationError(Exception):
    """Raised when the enrollment token JWT is invalid."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class NonceExpiredError(Exception):
    pass


class DIDProofError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Token validation helper
# ---------------------------------------------------------------------------


async def _validate_enrollment_token(
    raw_token: str,
    settings: DiscoverySettings,
    session: AsyncSession,
) -> dict:
    """Verify enrollment JWT and check DB record.  Returns decoded payload.

    Raises:
        EnrollmentTokenValidationError on any failure.
    """
    # 1. Verify JWT signature and exp
    try:
        payload = jwt.decode(
            raw_token,
            settings.local_jwt_secret.get_secret_value(),
            algorithms=["HS256"],
            options={"require": ["jti", "exp"]},
        )
    except jwt.ExpiredSignatureError:
        raise EnrollmentTokenValidationError("TOKEN_EXPIRED", "Enrollment token has expired")
    except jwt.InvalidTokenError as exc:
        raise EnrollmentTokenValidationError(
            "INVALID_TOKEN_SIGNATURE", f"Enrollment token signature verification failed: {exc}"
        )

    jti = payload["jti"]

    # 2. Compute SHA-256 of the submitted raw token and look up in DB
    submitted_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    token_record = await EnrollmentTokenRepository.get_by_jti(session, jti)
    if token_record is None:
        raise EnrollmentTokenValidationError(
            "INVALID_TOKEN_SIGNATURE", "Enrollment token not found"
        )
    if token_record.token_hash != submitted_hash:
        raise EnrollmentTokenValidationError(
            "INVALID_TOKEN_SIGNATURE", "Token hash mismatch"
        )

    # 3. Check status
    if token_record.status == "CONSUMED":
        raise EnrollmentTokenValidationError(
            "ENROLLMENT_ALREADY_CONSUMED", "Token already used"
        )
    if token_record.status == "EXPIRED":
        raise EnrollmentTokenValidationError("TOKEN_EXPIRED", "Token has expired")
    if token_record.status == "PENDING":
        raise EnrollmentTokenValidationError(
            "TOKEN_NOT_APPROVED",
            "Enrollment token has not been approved",
        )

    return payload


# ---------------------------------------------------------------------------
# Phase 1: Issue challenge
# ---------------------------------------------------------------------------


async def issue_challenge(
    raw_token: str,
    *,
    settings: DiscoverySettings,
    session: AsyncSession,
    redis,
) -> dict:
    """Validate the enrollment token and issue a one-time nonce.

    Returns:
        {"challenge_nonce": str, "challenge_expires_at": datetime}
    """
    payload = await _validate_enrollment_token(raw_token, settings, session)
    jti = payload["jti"]

    nonce_store = NonceStore(redis)
    nonce = await nonce_store.issue_nonce(jti, ttl_seconds=120)

    expires_at = datetime.now(timezone.utc) + timedelta(seconds=120)
    return {"challenge_nonce": nonce, "challenge_expires_at": expires_at}


# ---------------------------------------------------------------------------
# Phase 2: Full onboarding with PoP proof
# ---------------------------------------------------------------------------


async def complete_onboarding(
    raw_token: str,
    did: str,
    proof: dict,
    *,
    settings: DiscoverySettings,
    session: AsyncSession,
    redis,
    request_id: str = "",
) -> tuple[OnboardingBundle, bool]:
    """Execute the full onboarding flow.

    Returns:
        (OnboardingBundle, is_new_registration)
        is_new_registration=True → 201, False → 200 (idempotent re-registration)

    Raises:
        EnrollmentTokenValidationError
        NonceExpiredError
        DIDProofError
        TokenAlreadyConsumedError (concurrent attempt)
    """
    # --- Validate enrollment token ---
    payload = await _validate_enrollment_token(raw_token, settings, session)
    jti = payload["jti"]

    # --- Verify nonce ---
    nonce_store = NonceStore(redis)
    provided_nonce = proof.get("challenge_nonce", "")
    nonce_ok = await nonce_store.consume_nonce(jti, provided_nonce)
    if not nonce_ok:
        raise NonceExpiredError(
            "Challenge nonce expired or already used. Request a new challenge."
        )

    # --- Verify DID Proof-of-Possession ---
    iat_val = int(time.time())
    if isinstance(proof.get("created"), str):
        # Parse iat from 'created' field if provided; fall back to now
        try:
            from datetime import datetime as dt
            ts = dt.fromisoformat(proof["created"].replace("Z", "+00:00"))
            iat_val = int(ts.timestamp())
        except (ValueError, KeyError):
            pass

    pop_payload = {
        "jti": jti,
        "did": did,
        "challenge_nonce": provided_nonce,
        "iat": iat_val,
    }

    try:
        await verify_pop(did, pop_payload, proof.get("proof_value", ""))
    except (DIDResolutionError, InvalidSignatureError, UnsupportedDIDMethodError, ValueError) as exc:
        if isinstance(exc, UnsupportedDIDMethodError):
            raise DIDProofError("UNSUPPORTED_DID_METHOD", str(exc))
        raise DIDProofError("INVALID_DID_PROOF", f"DID proof-of-possession failed: {exc}")

    # --- Atomic token consumption ---
    try:
        token_record = await EnrollmentTokenRepository.consume_atomic(session, jti)
    except TokenAlreadyConsumedError:
        raise  # → 409 ENROLLMENT_ALREADY_CONSUMED

    service_id = token_record.service_id
    role = token_record.role
    env = token_record.env

    # --- Idempotent sentinel creation ---
    existing = await SentinelRepository.get_by_did(session, did, env)
    # Filter by role if multiple records for same DID
    existing_for_role = [s for s in existing if s.role == role]

    # Resolve service UUID once — used for both new and existing sentinel paths
    resolved_service_uuid = None
    if service_id:
        svc = await ServiceRepository.get_by_service_id_env(session, service_id, env)
        if svc is not None:
            resolved_service_uuid = svc.id
        else:
            logger.warning(
                "Service '%s' (env=%s) not found in services table — "
                "sentinel.service_id will be NULL",
                service_id, env,
            )

    is_new = False
    if existing_for_role:
        sentinel = existing_for_role[0]
        if sentinel.service_id is None and resolved_service_uuid is not None:
            sentinel.service_id = resolved_service_uuid
        if not sentinel.is_active:
            # Re-activate decommissioned sentinel
            sentinel.is_active = True
            sentinel.last_seen = datetime.now(timezone.utc)
            sentinel.config_version += 1
            await session.flush()
            await session.refresh(sentinel)
        else:
            # Idempotent: update last_seen
            sentinel.last_seen = datetime.now(timezone.utc)
            await session.flush()
    else:
        is_new = True
        sentinel = await SentinelRepository.create(
            session,
            Sentinel(
                id=uuid.uuid4(),
                service_id=resolved_service_uuid,
                did=did,
                role=role,
                env=env,
                is_active=True,
                config_version=1,
                last_seen=datetime.now(timezone.utc),
            ),
        )

    # --- Audit events ---
    await audit_log(
        session,
        actor_type="SENTINEL_ONBOARDING",
        actor_id=did,
        action="sentinel_onboarded",
        target_type="sentinel",
        target_id=str(sentinel.id),
        summary={"service_id": service_id, "role": role, "env": env, "token_jti": jti},
        request_id=request_id,
    )
    await audit_log(
        session,
        actor_type="SENTINEL_ONBOARDING",
        actor_id=did,
        action="enrollment_token_consumed",
        target_type="enrollment_token",
        target_id=str(token_record.id),
        summary={"jti": jti},
        request_id=request_id,
    )

    # --- Issue initial credential ---
    vc_jwt: Optional[str] = None
    try:
        _, vc_jwt = await issue_sentinel_identity(sentinel, session, settings)
    except IssuerNotActiveError:
        logger.info(
            "Discovery DID not yet active on-chain — deferring SentinelIdentityCredential "
            "(sentinel_id=%s)",
            sentinel.id,
        )
    except Exception as exc:
        logger.warning(
            "Credential issuance during onboarding failed (non-fatal, sentinel_id=%s): %s",
            sentinel.id,
            exc,
        )

    # --- Build bootstrap bundle ---
    bundle = _build_bundle(sentinel, settings, vc_jwt=vc_jwt)
    return bundle, is_new


def _build_bundle(
    sentinel: Sentinel,
    settings: DiscoverySettings,
    vc_jwt: Optional[str] = None,
) -> OnboardingBundle:
    from discovery.auth.local_jwt import issue_dev_token

    base = settings.jwt_issuer_did or "https://discovery.example.gov"
    # Normalize to a URL base for endpoint construction
    if base.startswith("did:"):
        base = "https://discovery.example.gov"

    access_token = issue_dev_token(
        sub=str(sentinel.id),
        roles=["sentinel"],
        secret=settings.local_jwt_secret.get_secret_value(),
        ttl_seconds=3600,
        actor_type="SENTINEL",
    )

    return OnboardingBundle(
        sentinel_id=sentinel.id,
        did=sentinel.did,
        role=sentinel.role,
        env=sentinel.env,
        config_version=sentinel.config_version,
        discovery=DiscoveryUrls(
            sync_url=f"{base}/api/v1/sentinels/{sentinel.id}",
            credentials_url=f"{base}/api/v1/sentinels/{sentinel.id}/credentials",
        ),
        chain=ChainInfo(
            network=f"chain-{settings.chain_id}",
            rpc_urls=[settings.blockchain_rpc_url],
            contract_addresses=ContractAddresses(
                issuer_registry=settings.contract_issuer_registry,
                trust_policy_registry=settings.contract_trust_policy_registry,
                status_registry=settings.contract_status_registry,
                service_registry=settings.contract_service_registry,
            ),
        ),
        revocation=RevocationInfo(delta_seconds=300),
        credentials=CredentialBundle(
            sentinel_identity=vc_jwt,
            credentials_pending=(vc_jwt is None),
        ),
        access_token=access_token,
    )
