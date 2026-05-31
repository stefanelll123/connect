"""CredentialIssuerService — JWT-VC issuance for sentinels (TASK-028).

Implements VC DM 2.0 + VC-JOSE-COSE profile using compact JWT serialization.
Signing uses HS256 in dev mode (local_jwt_secret); production must use EdDSA
with a key from SecretStorage.

Credential types issued:
  - SentinelIdentityCredential: issued on sentinel onboarding (90-day TTL)
  - ServiceBindingCredential: issued when sentinel proxies a service (1-year TTL)
  - AccessGrantCredential: issued by admin to grant consumer→producer access
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from discovery.config import DiscoverySettings
from discovery.db.models.credentials import Credential
from discovery.db.models.sentinels import Sentinel
from discovery.repositories.credentials import CredentialRepository
from discovery.repositories.sentinels import SentinelRepository
from discovery.repositories.status_lists import allocate_index as _repo_allocate_index
from common.crypto.did_key import did_key_to_raw_public_bytes

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level issuer registry client reference (set by app.py at startup)
# ---------------------------------------------------------------------------

_issuer_registry_client = None


def set_issuer_registry_client(client) -> None:  # type: ignore[type-arg]
    global _issuer_registry_client
    _issuer_registry_client = client


def get_issuer_registry_client():  # type: ignore[return]
    return _issuer_registry_client

# Maximum TTL per credential type (days)
_MAX_TTL = {
    "SentinelIdentityCredential": 90,
    "ServiceBindingCredential": 365,
    "AccessGrantCredential": 365,
}

_VC_CONTEXT = ["https://www.w3.org/ns/credentials/v2"]


class IssuerKeyUnavailableError(Exception):
    pass


class CredentialIssuanceError(Exception):
    pass


def _clamp_days(requested_days: int, credential_type: str) -> int:
    max_days = _MAX_TTL.get(credential_type, 365)
    if requested_days > max_days:
        logger.warning(
            "Clamping %s TTL from %d to %d days", credential_type, requested_days, max_days
        )
        return max_days
    return requested_days


def _sign_vc(payload: dict, settings: DiscoverySettings) -> str:
    """Sign a VC payload as compact JWT.

    Uses EdDSA (Ed25519) when *discovery_private_key_hex* is configured;
    otherwise falls back to HS256 with *local_jwt_secret* (dev mode only).
    """
    import jwt as pyjwt

    kid = settings.jwt_issuer_key_id or "local-key"
    if settings.discovery_private_key_hex:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private_key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(settings.discovery_private_key_hex)
        )
        return pyjwt.encode(
            payload,
            key=private_key,
            algorithm="EdDSA",
            headers={"kid": kid, "typ": "vc+jwt"},
        )
    return pyjwt.encode(
        payload,
        key=settings.local_jwt_secret.get_secret_value(),
        algorithm="HS256",
        headers={"kid": kid, "typ": "vc+jwt"},
    )


def _verify_vc(token: str, settings: DiscoverySettings) -> dict:
    """Self-check: verify the just-signed VC."""
    import jwt as pyjwt

    if settings.discovery_private_key_hex:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from common.crypto.did_key import did_key_to_public_key
        if settings.jwt_issuer_did:
            public_key = did_key_to_public_key(settings.jwt_issuer_did)
        else:
            private_key = Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(settings.discovery_private_key_hex)
            )
            public_key = private_key.public_key()
        return pyjwt.decode(
            token,
            key=public_key,
            algorithms=["EdDSA"],
            options={"verify_aud": False},
        )
    return pyjwt.decode(
        token,
        key=settings.local_jwt_secret.get_secret_value(),
        algorithms=["HS256"],
        options={"verify_aud": False},
    )


def _build_jwt_vc(
    *,
    credential_type: str,
    issuer_did: str,
    subject_did: str,
    audience: Optional[str],
    jti: str,
    now: datetime,
    expires_at: datetime,
    credential_subject: dict,
    status_list_url: str,
    status_list_index: int,
) -> dict:
    vc_obj = {
        "@context": _VC_CONTEXT,
        "type": ["VerifiableCredential", credential_type],
        "issuer": {"id": issuer_did},
        "validFrom": now.isoformat(),
        "validUntil": expires_at.isoformat(),
        "credentialSubject": {"id": subject_did, **credential_subject},
        "credentialStatus": {
            "id": f"{status_list_url}#{status_list_index}",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": status_list_index,
            "statusListCredential": status_list_url,
        },
    }
    payload: dict = {
        "iss": issuer_did,
        "sub": subject_did,
        "jti": jti,
        "nbf": int(now.timestamp()),
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "vc": vc_obj,
    }
    if audience:
        payload["aud"] = audience
    return payload


def _build_cnf_jwk(subject_did: str) -> dict | None:
    """Build a ``cnf.jwk`` dict from a ``did:key`` DID.

    Returns ``None`` (and logs a warning) if the DID cannot be decoded, so
    credential issuance can continue without key binding rather than failing.
    """
    import base64
    try:
        raw = did_key_to_raw_public_bytes(subject_did)
        x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        return {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": x}}
    except Exception as exc:
        logger.warning(
            "Could not derive cnf.jwk from DID %r — SD-JWT key binding unavailable: %s",
            subject_did, exc,
        )
        return None


async def _persist_credential(
    session: AsyncSession,
    *,
    credential_type: str,
    issuer_did: str,
    subject_did: str,
    audience: Optional[str],
    env: str,
    jti: str,
    now: datetime,
    expires_at: datetime,
    status_list_id: Optional[str],
    status_list_index: Optional[int],
) -> Credential:
    cred = Credential(
        credential_type=credential_type,
        issuer_did=issuer_did,
        subject_did=subject_did,
        audience=audience,
        env=env,
        jti=jti,
        issued_at=now,
        expires_at=expires_at,
        status="active",
        status_list_id=status_list_id,
        status_list_index=status_list_index,
        is_latest=True,
    )
    return await CredentialRepository.create(session, cred)


class IssuerNotActiveError(Exception):
    """Raised when the Discovery node's own DID is not active on-chain."""


async def _check_issuer_active(settings: DiscoverySettings) -> None:
    """If VERIFY_ISSUER_ON_CHAIN is enabled, confirm the Discovery DID is active.

    Raises IssuerNotActiveError if the check fails so callers block issuance.
    Non-fatal if the chain client is unavailable (logs a warning only).
    """
    if not settings.verify_issuer_on_chain:
        return
    client = get_issuer_registry_client()
    if client is None:
        logger.warning(
            "verify_issuer_on_chain=True but IssuerRegistryClient not available — skipping check"
        )
        return
    issuer_did = settings.jwt_issuer_did
    if not issuer_did:
        return
    try:
        active = await client.is_issuer_active(issuer_did)
    except Exception as exc:
        logger.warning("on-chain issuer check failed (non-fatal): %s", exc)
        return
    if not active:
        raise IssuerNotActiveError(
            f"Discovery DID '{issuer_did}' is not active in IssuerRegistry — "
            "credential issuance blocked"
        )


async def issue_sentinel_identity(
    sentinel: Sentinel,
    session: AsyncSession,
    settings: DiscoverySettings,
    expires_in_days: int = 90,
) -> tuple[Credential, str]:
    """Issue a SentinelIdentityCredential.  Returns (record, jwt_vc_string)."""
    await _check_issuer_active(settings)
    credential_type = "SentinelIdentityCredential"
    clamped_days = _clamp_days(expires_in_days, credential_type)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=clamped_days)
    jti = f"urn:uuid:{uuid.uuid4()}"
    issuer_did = settings.jwt_issuer_did or "did:key:discovery"

    service_id = str(sentinel.service_id) if sentinel.service_id else ""
    credential_subject = {
        "role": sentinel.role,
        "service_id": service_id,
        "env": sentinel.env,
        "registered_at": (sentinel.created_at or now).isoformat(),
    }

    status_list_id, status_list_index = await _repo_allocate_index(
        session, issuer_did, sentinel.env, credential_type
    )
    status_list_url = f"https://discovery.example.gov/status/{status_list_id}"

    payload = _build_jwt_vc(
        credential_type=credential_type,
        issuer_did=issuer_did,
        subject_did=sentinel.did,
        audience=None,
        jti=jti,
        now=now,
        expires_at=expires_at,
        credential_subject=credential_subject,
        status_list_url=status_list_url,
        status_list_index=status_list_index,
    )
    cnf = _build_cnf_jwk(sentinel.did)
    if cnf:
        payload["cnf"] = cnf
    jwt_vc = _sign_vc(payload, settings)

    # Internal self-check
    try:
        _verify_vc(jwt_vc, settings)
    except Exception as exc:
        raise CredentialIssuanceError(f"Self-check after signing failed: {exc}") from exc

    record = await _persist_credential(
        session,
        credential_type=credential_type,
        issuer_did=issuer_did,
        subject_did=sentinel.did,
        audience=None,
        env=sentinel.env,
        jti=jti,
        now=now,
        expires_at=expires_at,
        status_list_id=status_list_id,
        status_list_index=status_list_index,
    )
    return record, jwt_vc


async def issue_access_grant(
    consumer_sentinel: Sentinel,
    producer_service_id: str,
    env: str,
    scope: list[str],
    expires_in_days: int,
    session: AsyncSession,
    settings: DiscoverySettings,
    granted_by: str = "admin",
) -> tuple[Credential, str]:
    """Issue an AccessGrantCredential.  Returns (record, jwt_vc_string)."""
    await _check_issuer_active(settings)
    credential_type = "AccessGrantCredential"
    clamped_days = _clamp_days(expires_in_days, credential_type)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=clamped_days)
    jti = f"urn:uuid:{uuid.uuid4()}"
    issuer_did = settings.jwt_issuer_did or "did:key:discovery"

    audience = f"did:service:{producer_service_id}"
    credential_subject = {
        "target_service_id": producer_service_id,
        "env": env,
        "scope": scope,
        "granted_by": granted_by,
        "granted_at": now.isoformat(),
    }

    status_list_id = f"{env}-{credential_type.lower()}-001"
    status_list_index = 0
    status_list_url = f"https://discovery.example.gov/status/{status_list_id}"

    payload = _build_jwt_vc(
        credential_type=credential_type,
        issuer_did=issuer_did,
        subject_did=consumer_sentinel.did,
        audience=audience,
        jti=jti,
        now=now,
        expires_at=expires_at,
        credential_subject=credential_subject,
        status_list_url=status_list_url,
        status_list_index=status_list_index,
    )
    cnf = _build_cnf_jwk(consumer_sentinel.did)
    if cnf:
        payload["cnf"] = cnf
    jwt_vc = _sign_vc(payload, settings)

    try:
        _verify_vc(jwt_vc, settings)
    except Exception as exc:
        raise CredentialIssuanceError(f"Self-check after signing failed: {exc}") from exc

    record = await _persist_credential(
        session,
        credential_type=credential_type,
        issuer_did=issuer_did,
        subject_did=consumer_sentinel.did,
        audience=audience,
        env=env,
        jti=jti,
        now=now,
        expires_at=expires_at,
        status_list_id=status_list_id,
        status_list_index=status_list_index,
    )
    return record, jwt_vc


async def issue_service_binding(
    sentinel: Sentinel,
    service_id: str,
    session: AsyncSession,
    settings: DiscoverySettings,
    expires_in_days: int = 365,
) -> tuple[Credential, str]:
    """Issue a ServiceBindingCredential.  Returns (record, jwt_vc_string)."""
    await _check_issuer_active(settings)
    credential_type = "ServiceBindingCredential"
    clamped_days = _clamp_days(expires_in_days, credential_type)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=clamped_days)
    jti = f"urn:uuid:{uuid.uuid4()}"
    issuer_did = settings.jwt_issuer_did or "did:key:discovery"

    audience = f"did:service:{service_id}"
    credential_subject = {
        "authorized_service_id": service_id,
        "authorized_service_did": audience,
        "env": sentinel.env,
        "binding_type": "producer-proxy",
    }

    status_list_id = f"{sentinel.env}-{credential_type.lower()}-001"
    status_list_index = 0
    status_list_url = f"https://discovery.example.gov/status/{status_list_id}"

    payload = _build_jwt_vc(
        credential_type=credential_type,
        issuer_did=issuer_did,
        subject_did=sentinel.did,
        audience=audience,
        jti=jti,
        now=now,
        expires_at=expires_at,
        credential_subject=credential_subject,
        status_list_url=status_list_url,
        status_list_index=status_list_index,
    )
    jwt_vc = _sign_vc(payload, settings)

    try:
        _verify_vc(jwt_vc, settings)
    except Exception as exc:
        raise CredentialIssuanceError(f"Self-check after signing failed: {exc}") from exc

    record = await _persist_credential(
        session,
        credential_type=credential_type,
        issuer_did=issuer_did,
        subject_did=sentinel.did,
        audience=audience,
        env=sentinel.env,
        jti=jti,
        now=now,
        expires_at=expires_at,
        status_list_id=status_list_id,
        status_list_index=status_list_index,
    )
    return record, jwt_vc


async def reissue_on_rotation(
    credential_id: uuid.UUID,
    session: AsyncSession,
    settings: DiscoverySettings,
    new_expires_in_days: Optional[int] = None,
) -> tuple[Credential, str]:
    """Re-issue an existing credential with a new jti and fresh signature.

    The old credential is marked is_latest=False. The caller is responsible
    for setting deprecated_until on the old record (TASK-029).
    """
    from sqlalchemy import select

    result = await session.execute(
        select(Credential).where(Credential.id == credential_id)
    )
    old_cred = result.scalar_one_or_none()
    if old_cred is None:
        raise ValueError(f"Credential {credential_id} not found")

    # Load sentinel for subject info
    sentinel = None
    result2 = await session.execute(
        select(Sentinel).where(Sentinel.did == old_cred.subject_did)
    )
    sentinel = result2.scalar_one_or_none()

    issuer_did = settings.jwt_issuer_did or "did:key:discovery"
    now = datetime.now(timezone.utc)

    if new_expires_in_days is not None:
        clamped = _clamp_days(new_expires_in_days, old_cred.credential_type)
    else:
        # preserve original TTL
        if old_cred.expires_at and old_cred.issued_at:
            original_days = (old_cred.expires_at - old_cred.issued_at).days
            clamped = _clamp_days(original_days, old_cred.credential_type)
        else:
            clamped = 30
    expires_at = now + timedelta(days=clamped)
    new_jti = f"urn:uuid:{uuid.uuid4()}"

    credential_subject: dict = {}
    if sentinel:
        credential_subject = {
            "role": sentinel.role,
            "service_id": str(sentinel.service_id) if sentinel.service_id else "",
            "env": sentinel.env,
        }

    # Re-derive cnf.jwk using sentinel's current DID (updated before reissue request)
    reissue_cnf = _build_cnf_jwk(old_cred.subject_did) if sentinel is None else _build_cnf_jwk(sentinel.did)

    status_list_url = (
        f"https://discovery.example.gov/status/{old_cred.status_list_id}"
        if old_cred.status_list_id
        else "https://discovery.example.gov/status/default-001"
    )
    status_list_index = old_cred.status_list_index or 0

    payload = _build_jwt_vc(
        credential_type=old_cred.credential_type,
        issuer_did=issuer_did,
        subject_did=old_cred.subject_did,
        audience=old_cred.audience,
        jti=new_jti,
        now=now,
        expires_at=expires_at,
        credential_subject=credential_subject,
        status_list_url=status_list_url,
        status_list_index=status_list_index,
    )
    if reissue_cnf:
        payload["cnf"] = reissue_cnf
    jwt_vc = _sign_vc(payload, settings)

    try:
        _verify_vc(jwt_vc, settings)
    except Exception as exc:
        raise CredentialIssuanceError(f"Self-check after signing failed: {exc}") from exc

    # Mark old as not latest
    old_cred.is_latest = False
    await session.flush()

    new_cred = await _persist_credential(
        session,
        credential_type=old_cred.credential_type,
        issuer_did=issuer_did,
        subject_did=old_cred.subject_did,
        audience=old_cred.audience,
        env=old_cred.env or "",
        jti=new_jti,
        now=now,
        expires_at=expires_at,
        status_list_id=old_cred.status_list_id,
        status_list_index=old_cred.status_list_index,
    )
    return new_cred, jwt_vc
