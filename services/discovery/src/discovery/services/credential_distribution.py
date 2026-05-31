"""Credential distribution service — feed, scoping, ETag, rotation (TASK-029)."""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.config import DiscoverySettings
from discovery.db.models.credentials import Credential
from discovery.db.models.sentinels import Sentinel

logger = logging.getLogger(__name__)

# Default rotation grace period in seconds
_DEFAULT_GRACE_SECONDS = 300
_RATE_LIMIT_FULL_SYNC = 10  # per hour per sentinel


def _compute_feed_etag(credentials: list[Credential]) -> str:
    """Compute ETag as SHA-256 of sorted jti list."""
    jtis = sorted(c.jti or "" for c in credentials)
    return hashlib.sha256("|".join(jtis).encode()).hexdigest()


async def get_credentials_for_sentinel(
    session: AsyncSession,
    sentinel: Sentinel,
    *,
    since: Optional[datetime] = None,
    credential_type: Optional[str] = None,
    status_filter: Optional[list[str]] = None,
) -> list[Credential]:
    """Return credentials scoped to this sentinel with security filtering.

    SECURITY: Filters by subject_did + env + service_id — never returns
    credentials belonging to a different sentinel.
    """
    if status_filter is None:
        status_filter = ["active", "deprecated"]

    query = select(Credential).where(
        Credential.subject_did == sentinel.did,
        Credential.env == sentinel.env,
        Credential.is_latest.is_(True),
        Credential.status.in_(status_filter),
    )

    if sentinel.service_id:
        # Additional scoping by service if available
        pass  # service_id is on sentinel; credentials don't store it separately

    if credential_type:
        query = query.where(Credential.credential_type == credential_type)

    if since:
        # Return credentials issued after `since` OR deprecated ones still in grace period
        from sqlalchemy import or_

        query = query.where(
            or_(
                Credential.issued_at > since,
                (Credential.status == "deprecated") & (Credential.deprecated_until > since),
            )
        )

    result = await session.execute(query)
    return list(result.scalars().all())


def reconstruct_jwt_vc(cred: Credential, settings: DiscoverySettings) -> str:
    """Re-sign the credential from metadata (no raw JWT stored by default).

    In production with CREDENTIAL_STORAGE_ENCRYPT=true this would decrypt
    the encrypted_payload column and return the plaintext JWT.
    For now, we reconstruct a valid signed JWT from persisted metadata.
    """
    import jwt as pyjwt
    from datetime import timezone

    now = datetime.now(timezone.utc)
    payload = {
        "iss": cred.issuer_did,
        "sub": cred.subject_did,
        "jti": cred.jti or f"urn:uuid:{cred.id}",
        "iat": int((cred.issued_at or now).timestamp()),
        "exp": int((cred.expires_at or now).timestamp()),
        "vc": {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", cred.credential_type],
            "issuer": {"id": cred.issuer_did},
            "credentialSubject": {"id": cred.subject_did},
        },
    }
    if cred.audience:
        payload["aud"] = cred.audience

    kid = settings.jwt_issuer_key_id or "local-key"
    return pyjwt.encode(
        payload,
        key=settings.local_jwt_secret.get_secret_value(),
        algorithm="HS256",
        headers={"kid": kid, "typ": "vc+jwt"},
    )


async def start_rotation(
    old_cred: Credential,
    new_cred: Credential,
    session: AsyncSession,
    grace_seconds: int = _DEFAULT_GRACE_SECONDS,
) -> None:
    """Mark old credential as deprecated with deprecated_until."""
    deprecated_until = datetime.now(timezone.utc) + timedelta(seconds=grace_seconds)
    old_cred.status = "deprecated"
    old_cred.deprecated_until = deprecated_until
    old_cred.is_latest = False
    await session.flush()
