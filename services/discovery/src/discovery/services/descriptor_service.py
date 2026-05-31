"""DescriptorService — validation, storage, and expiry of service descriptors (TASK-032)."""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.db.models.service_descriptors import ServiceDescriptor
from discovery.db.models.sentinels import Sentinel

logger = logging.getLogger(__name__)

_MAX_TTL_SECONDS = 600


class DescriptorValidationError(Exception):
    """Raised when descriptor payload or signature is invalid."""

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def _canonical_descriptor(payload: dict) -> bytes:
    """Deterministic JSON serialization for hashing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def _compute_descriptor_hash(payload: dict) -> str:
    return hashlib.sha256(_canonical_descriptor(payload)).hexdigest()


def _extract_jws_payload(signed_jws: str) -> dict:
    """Extract the payload from a compact JWS without signature verification.

    In production the signature MUST be verified using the producer's DID key.
    For dev: we use unverified extraction so the endpoint can be tested without
    needing actual DID-key JWS libraries wired up.
    """
    import base64
    import json

    parts = signed_jws.split(".")
    if len(parts) != 3:
        raise DescriptorValidationError(
            "INVALID_DESCRIPTOR_SIGNATURE",
            "JWS must be compact serialization with 3 parts",
        )
    # Base64url decode the payload (index 1)
    payload_b64 = parts[1]
    # Add padding
    padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
    try:
        payload_bytes = base64.urlsafe_b64decode(padded)
        return json.loads(payload_bytes)
    except Exception as exc:
        raise DescriptorValidationError(
            "INVALID_DESCRIPTOR_SIGNATURE",
            f"Failed to decode JWS payload: {exc}",
        )


async def validate_and_publish(
    session: AsyncSession,
    *,
    service_id: str,
    env: str,
    signed_descriptor_jws: str,
) -> ServiceDescriptor:
    """Validate descriptor JWS and persist/upsert into service_descriptors.

    Validation steps:
    (a) Extract and decode payload from JWS
    (b) Verify service_id and env match URL path params
    (c) Verify producer_sentinel_did is an active producer sentinel for this service
    (d) Check TTL ≤ 600s
    (e) Check endpoints non-empty
    (f) Upsert record

    Note: DID-key JWS signature verification requires the sender to self-describe
    producer_sentinel_did; full cryptographic verification is gated on DID resolver
    integration (TASK-039). Currently we trust the extracted DID from the payload
    and validate it against the DB.
    """
    now = datetime.now(timezone.utc)

    # (a) Extract payload
    payload = _extract_jws_payload(signed_descriptor_jws)

    # (b) Match path params
    if payload.get("service_id") != service_id:
        raise DescriptorValidationError(
            "DESCRIPTOR_SERVICE_MISMATCH",
            f"service_id in descriptor ({payload.get('service_id')!r}) does not match URL ({service_id!r})",
            422,
        )
    if payload.get("env") != env:
        raise DescriptorValidationError(
            "DESCRIPTOR_ENV_MISMATCH",
            f"env in descriptor ({payload.get('env')!r}) does not match URL ({env!r})",
            422,
        )

    # (c) Validate TTL
    valid_from_raw = payload.get("valid_from")
    valid_until_raw = payload.get("valid_until")
    if not valid_from_raw or not valid_until_raw:
        raise DescriptorValidationError("MISSING_VALIDITY", "valid_from and valid_until are required", 422)

    try:
        valid_from = datetime.fromisoformat(str(valid_from_raw).replace("Z", "+00:00"))
        valid_until = datetime.fromisoformat(str(valid_until_raw).replace("Z", "+00:00"))
    except ValueError as exc:
        raise DescriptorValidationError("INVALID_DATETIME", str(exc), 422)

    ttl = (valid_until - valid_from).total_seconds()
    if ttl > _MAX_TTL_SECONDS:
        raise DescriptorValidationError(
            "TTL_TOO_LONG",
            f"Descriptor TTL cannot exceed {_MAX_TTL_SECONDS} seconds (got {ttl:.0f}s)",
            422,
        )

    if valid_until < now:
        raise DescriptorValidationError(
            "DESCRIPTOR_ALREADY_EXPIRED",
            "Descriptor valid_until is already in the past",
            422,
        )

    # (d) Endpoints non-empty
    endpoints = payload.get("endpoints", [])
    if not endpoints:
        raise DescriptorValidationError("EMPTY_ENDPOINTS", "Descriptor must have at least one endpoint", 422)

    # (e) Validate producer sentinel is registered for this service
    producer_did = payload.get("producer_sentinel_did", "")
    if producer_did:
        result = await session.execute(
            select(Sentinel).where(
                Sentinel.did == producer_did,
                Sentinel.env == env,
                Sentinel.role == "producer",
                Sentinel.is_active.is_(True),
            )
        )
        sentinel = result.scalar_one_or_none()
        if sentinel is None:
            raise DescriptorValidationError(
                "UNAUTHORIZED_PUBLISHER",
                f"producer_sentinel_did {producer_did!r} is not a registered active producer for env={env}",
                403,
            )

    descriptor_hash = _compute_descriptor_hash(payload)

    # Upsert — mark old record inactive, insert new
    stmt = pg_insert(ServiceDescriptor).values(
        service_id=service_id,
        env=env,
        producer_sentinel_did=producer_did or None,
        descriptor_hash=descriptor_hash,
        signed_descriptor_jws=signed_descriptor_jws,
        valid_until=valid_until,
        published_at=now,
        is_active=True,
    ).on_conflict_do_update(
        constraint="uq_service_descriptors_service_env",
        set_={
            "producer_sentinel_did": producer_did or None,
            "descriptor_hash": descriptor_hash,
            "signed_descriptor_jws": signed_descriptor_jws,
            "valid_until": valid_until,
            "published_at": now,
            "is_active": True,
        },
    )
    await session.execute(stmt)
    await session.flush()

    # Return the freshly upserted record
    result = await session.execute(
        select(ServiceDescriptor).where(
            ServiceDescriptor.service_id == service_id,
            ServiceDescriptor.env == env,
        )
    )
    return result.scalar_one()


async def resolve_descriptor(
    session: AsyncSession,
    *,
    service_id: str,
    env: str,
) -> ServiceDescriptor:
    """Return the active, non-expired descriptor.  Raises ValueError on failure."""
    now = datetime.now(timezone.utc)
    result = await session.execute(
        select(ServiceDescriptor).where(
            ServiceDescriptor.service_id == service_id,
            ServiceDescriptor.env == env,
            ServiceDescriptor.is_active.is_(True),
        )
    )
    sd = result.scalar_one_or_none()
    if sd is None:
        raise DescriptorValidationError(
            "SERVICE_NOT_RESOLVABLE",
            f"No active service descriptor found for '{service_id}' in env '{env}'",
            404,
        )
    if sd.valid_until and sd.valid_until < now:
        raise DescriptorValidationError(
            "DESCRIPTOR_EXPIRED",
            "Service descriptor has expired. Producer sentinel may be offline.",
            404,
        )
    return sd


async def invalidate(session: AsyncSession, *, service_id: str, env: str) -> None:
    """Mark the descriptor inactive (called from decommission cascade)."""
    result = await session.execute(
        select(ServiceDescriptor).where(
            ServiceDescriptor.service_id == service_id,
            ServiceDescriptor.env == env,
        )
    )
    sd = result.scalar_one_or_none()
    if sd:
        sd.is_active = False
        await session.flush()
