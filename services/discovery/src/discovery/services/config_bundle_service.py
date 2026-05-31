"""Config bundle service — generation, signing, and invalidation (TASK-027)."""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from discovery.config import DiscoverySettings
from discovery.db.models.config_bundles import ConfigBundle
from discovery.db.models.sentinels import Sentinel
from discovery.repositories.config_bundles import ConfigBundleRepository
from discovery.repositories.sentinels import SentinelRepository
from discovery.schemas.config_bundle import (
    BundleChainConfig,
    BundleDiscoveryConfig,
    BundleObservabilityConfig,
    BundlePolicyDefaults,
    BundleRevocationConfig,
    ConfigBundlePayload,
)

logger = logging.getLogger(__name__)

_DECOMMISSION_POLICY = {
    "max_token_age_seconds": 0,
    "allow_unknown_issuers": False,
    "fail_closed_on_chain_error": True,
    "all_requests_denied": True,
}


def _canonical_json(payload: dict) -> bytes:
    """Produce deterministic UTF-8 JSON (sorted keys, no extra whitespace)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sign_bundle(canonical_bytes: bytes, settings: DiscoverySettings) -> str:
    """Sign a bundle using HS256 (dev) — returns a compact JWS string.

    In production this would use EdDSA with a key from SecretStorage.
    The kid is set to settings.jwt_issuer_key_id.
    """
    import jwt as pyjwt

    payload_str = canonical_bytes.decode("utf-8")
    # We embed the raw payload as the JWT subject claim for compact serialization.
    # The full payload is included in the `bundle` claim so verifiers can inspect it.
    token = pyjwt.encode(
        {
            "typ": "config-bundle+jwt",
            "bundle": json.loads(payload_str),
        },
        key=settings.local_jwt_secret.get_secret_value(),
        algorithm="HS256",
        headers={"kid": settings.jwt_issuer_key_id or "local-key", "typ": "config-bundle+jwt"},
    )
    return token


def _build_payload(
    sentinel: Sentinel,
    settings: DiscoverySettings,
    version: int,
    service_id: str,
    issued_at: datetime,
) -> dict:
    base_url = "https://discovery.example.gov"
    sid = str(sentinel.id)
    discovery = BundleDiscoveryConfig(
        sync_url=f"{base_url}/api/v1/sentinels/{sid}/config",
        credentials_url=f"{base_url}/api/v1/sentinels/{sid}/credentials",
        heartbeat_url=f"{base_url}/api/v1/sentinels/{sid}/heartbeat",
        status_list_base_url=f"{base_url}/status/",
    )
    chain = BundleChainConfig(
        network="localhost",
        chain_id=settings.chain_id,
        rpc_urls=[settings.blockchain_rpc_url],
        contract_addresses={
            "issuer_registry": "",
            "trust_policy_registry": "",
            "status_registry": "",
            "service_registry": "",
        },
    )
    payload = ConfigBundlePayload(
        bundle_version=version,
        issued_at=issued_at.isoformat(),
        sentinel_did=sentinel.did,
        sentinel_id=sid,
        role=sentinel.role,
        env=sentinel.env,
        service_id=service_id,
        discovery=discovery,
        chain=chain,
        policy_defaults=BundlePolicyDefaults(),
        revocation=BundleRevocationConfig(),
        observability=BundleObservabilityConfig(),
        issued_by=settings.jwt_issuer_did or "did:key:discovery",
        signature_kid=settings.jwt_issuer_key_id or "local-key",
    )
    return payload.model_dump()


async def generate_and_sign(
    sentinel_id: uuid.UUID,
    session: AsyncSession,
    settings: DiscoverySettings,
) -> ConfigBundle:
    """Generate, sign, and persist a new config bundle for the sentinel."""
    sentinel = await SentinelRepository.get_by_id(session, sentinel_id)
    if sentinel is None:
        raise ValueError(f"Sentinel {sentinel_id} not found")

    # Resolve service_id string
    service_id = str(sentinel.service_id) if sentinel.service_id else ""

    max_ver = await ConfigBundleRepository.get_max_version(session, sentinel_id)
    new_version = max_ver + 1
    issued_at = datetime.now(timezone.utc)

    payload_dict = _build_payload(sentinel, settings, new_version, service_id, issued_at)
    canonical_bytes = _canonical_json(payload_dict)
    bundle_hash = hashlib.sha256(canonical_bytes).hexdigest()
    signed_jws = _sign_bundle(canonical_bytes, settings)

    bundle = ConfigBundle(
        sentinel_id=sentinel_id,
        version=new_version,
        bundle_hash=bundle_hash,
        signed_bundle_jws=signed_jws,
        issued_at=issued_at,
        is_current=True,
    )
    return await ConfigBundleRepository.create(session, bundle)


async def rollback(
    sentinel_id: uuid.UUID,
    to_version: int,
    session: AsyncSession,
    settings: DiscoverySettings,
) -> ConfigBundle:
    """Re-sign config from historical version X as a new version N+1."""
    target = await ConfigBundleRepository.get_by_version(session, sentinel_id, to_version)
    if target is None:
        raise ValueError(f"Version {to_version} not found")

    current = await ConfigBundleRepository.get_current(session, sentinel_id)
    if current is not None and current.version == to_version:
        raise ValueError(f"Version {to_version} is already current")

    # Extract original payload from the signed JWS and re-sign with new version
    import jwt as pyjwt

    try:
        decoded = pyjwt.decode(
            target.signed_bundle_jws,
            key=settings.local_jwt_secret.get_secret_value(),
            algorithms=["HS256"],
        )
        old_bundle_content = decoded.get("bundle", {})
    except Exception:
        old_bundle_content = {}

    max_ver = await ConfigBundleRepository.get_max_version(session, sentinel_id)
    new_version = max_ver + 1
    issued_at = datetime.now(timezone.utc)

    if old_bundle_content:
        old_bundle_content["bundle_version"] = new_version
        old_bundle_content["issued_at"] = issued_at.isoformat()
    
    canonical_bytes = _canonical_json(old_bundle_content)
    bundle_hash = hashlib.sha256(canonical_bytes).hexdigest()
    signed_jws = _sign_bundle(canonical_bytes, settings)

    bundle = ConfigBundle(
        sentinel_id=sentinel_id,
        version=new_version,
        bundle_hash=bundle_hash,
        signed_bundle_jws=signed_jws,
        issued_at=issued_at,
        is_current=True,
    )
    return await ConfigBundleRepository.create(session, bundle)


async def invalidate(
    sentinel_id: uuid.UUID,
    session: AsyncSession,
    settings: DiscoverySettings,
) -> ConfigBundle:
    """Mark sentinel decommissioned — issue terminal bundle with all_requests_denied."""
    max_ver = await ConfigBundleRepository.get_max_version(session, sentinel_id)
    new_version = max_ver + 1
    issued_at = datetime.now(timezone.utc)

    terminal_payload = {
        "bundle_version": new_version,
        "issued_at": issued_at.isoformat(),
        "sentinel_id": str(sentinel_id),
        "policy_defaults": _DECOMMISSION_POLICY,
        "decommissioned": True,
    }
    canonical_bytes = _canonical_json(terminal_payload)
    bundle_hash = hashlib.sha256(canonical_bytes).hexdigest()
    signed_jws = _sign_bundle(canonical_bytes, settings)

    bundle = ConfigBundle(
        sentinel_id=sentinel_id,
        version=new_version,
        bundle_hash=bundle_hash,
        signed_bundle_jws=signed_jws,
        issued_at=issued_at,
        is_current=True,
    )
    return await ConfigBundleRepository.create(session, bundle)
