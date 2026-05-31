"""StatusListService — bitstring status list management (TASK-030).

Implements W3C Bitstring Status List v1.0 for credential revocation.
Each status list is identified by a (issuer_did, env, credential_type) bucket.
The JWT credential is signed and cached; the dirty flag triggers republish.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from discovery.config import DiscoverySettings
from discovery.db.models.status_lists import StatusList
from discovery.repositories.status_lists import StatusListRepository

logger = logging.getLogger(__name__)


def _encode_bitstring(raw_bytes: bytes) -> str:
    """Return base64url(gzip(bitstring_bytes)) per W3C spec."""
    compressed = gzip.compress(raw_bytes, compresslevel=9)
    return base64.urlsafe_b64encode(compressed).decode("ascii")


def _generate_status_list_jwt(
    sl: StatusList,
    settings: DiscoverySettings,
    base_url: str = "https://discovery.example.gov",
) -> str:
    """Produce a signed StatusListCredential JWT."""
    import jwt as pyjwt

    now = datetime.now(timezone.utc)
    exp = now + timedelta(hours=24)
    status_list_url = f"{base_url}/status/{sl.status_list_id}"

    encoded_list = _encode_bitstring(sl.bitstring or bytes(sl.max_size // 8))

    payload = {
        "iss": settings.jwt_issuer_did or "did:key:discovery",
        "sub": status_list_url,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "vc": {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/status/v1",
            ],
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "credentialSubject": {
                "id": status_list_url,
                "type": "BitstringStatusList",
                "statusPurpose": "revocation",
                "encodedList": encoded_list,
            },
        },
    }

    kid = settings.jwt_issuer_key_id or "local-key"
    return pyjwt.encode(
        payload,
        key=settings.local_jwt_secret.get_secret_value(),
        algorithm="HS256",
        headers={"kid": kid, "typ": "statuslist+jwt"},
    )


async def get_status_list_jwt(
    session: AsyncSession,
    status_list_id: str,
    settings: DiscoverySettings,
) -> Optional[str]:
    """Return the current signed StatusListCredential JWT, or None if not found."""
    sl = await StatusListRepository.get_by_slug(session, status_list_id)
    if sl is None:
        return None
    return _generate_status_list_jwt(sl, settings)


async def publish(
    session: AsyncSession,
    status_list_id: str,
    settings: DiscoverySettings,
) -> StatusList:
    """Re-sign the status list, update hash, clear dirty flag."""
    sl = await StatusListRepository.get_by_slug(session, status_list_id)
    if sl is None:
        raise ValueError(f"Status list '{status_list_id}' not found")

    encoded = _encode_bitstring(sl.bitstring or bytes(sl.max_size // 8))
    # Hash the raw bitstring bytes (pre-gzip, pre-base64) so the anchor is
    # stable across routine JWT re-signs (new iat/exp) and only changes when
    # a credential bit is actually flipped.
    sl.current_hash = hashlib.sha256(sl.bitstring or bytes(sl.max_size // 8)).hexdigest()
    sl.dirty = False
    sl.published_at = datetime.now(timezone.utc)
    if settings.anchor_status_lists:
        sl.anchor_pending = True
        sl.anchor_attempts = 0
        sl.anchor_next_retry_at = None
    await StatusListRepository.save(session, sl)
    return sl


async def publish_dirty(
    session: AsyncSession,
    settings: DiscoverySettings,
) -> int:
    """Publish all status lists with dirty=true.  Returns count published."""
    all_lists = await StatusListRepository.list_all(session)
    count = 0
    for sl in all_lists:
        if sl.dirty:
            await publish(session, sl.status_list_id, settings)
            count += 1
    return count
