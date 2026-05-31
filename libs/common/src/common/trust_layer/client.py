"""TrustLayerClient — main entry point (TASK-042)."""
from __future__ import annotations

import asyncio
import logging
import time
from enum import Enum
from typing import Optional

from common.trust_layer.cache_models import (
    IssuerRecord,
    PolicyParams,
    ServiceBinding,
    StatusAnchor,
)
from common.trust_layer.memory_cache import MemoryCache
from common.trust_layer.metrics import (
    chain_rpc_errors_total,
    trust_cache_hits_total,
    trust_cache_misses_total,
    trust_cache_staleness_seconds,
    trust_layer_unavailable_total,
)
from common.trust_layer.persistent_cache import PersistentCache

logger = logging.getLogger(__name__)

# Cache TTLs (seconds) — can be overridden via env vars or constructor
_DEFAULT_ISSUER_TTL = 60.0
_DEFAULT_POLICY_TTL = 60.0
_DEFAULT_STATUS_ANCHOR_TTL = 30.0
_DEFAULT_SERVICE_BINDING_TTL = 60.0
_DEFAULT_MAX_OUTAGE_AGE = 300.0

# Namespace keys
_NS_ISSUER = "issuer"
_NS_POLICY = "policy"
_NS_STATUS_ANCHOR = "status_anchor"
_NS_SERVICE_BINDING = "service_binding"
_POLICY_KEY = "__global__"


class OutagePolicy(str, Enum):
    FAIL_CLOSED = "fail_closed"
    DEGRADE_READ_ONLY = "degrade_read_only"
    USE_CACHE = "use_cache"


class TrustLayerUnavailable(Exception):
    """Raised when the chain is unreachable and FAIL_CLOSED policy is active."""


class TrustLayerClient:
    """Read-only blockchain trust layer client with two-tier caching.

    Args:
        chain_client:    Async chain client providing read methods.
        persistent_cache: Optional persistent cache for cross-restart survival.
        issuer_ttl:      Cache TTL for issuer records (seconds).
        policy_ttl:      Cache TTL for policy params (seconds).
        status_anchor_ttl: Cache TTL for status anchors (seconds).
        service_binding_ttl: Cache TTL for service bindings (seconds).
        max_cache_age:   Max age (seconds) to serve stale data during outage.
        outage_policy:   Behaviour when chain unreachable and cache is stale.
    """

    def __init__(
        self,
        chain_client=None,
        persistent_cache: Optional[PersistentCache] = None,
        issuer_ttl: float = _DEFAULT_ISSUER_TTL,
        policy_ttl: float = _DEFAULT_POLICY_TTL,
        status_anchor_ttl: float = _DEFAULT_STATUS_ANCHOR_TTL,
        service_binding_ttl: float = _DEFAULT_SERVICE_BINDING_TTL,
        max_cache_age: float = _DEFAULT_MAX_OUTAGE_AGE,
        outage_policy: OutagePolicy = OutagePolicy.FAIL_CLOSED,
    ) -> None:
        self._chain = chain_client
        self._mem = MemoryCache()
        self._persistent = persistent_cache
        self._issuer_ttl = issuer_ttl
        self._policy_ttl = policy_ttl
        self._status_anchor_ttl = status_anchor_ttl
        self._service_binding_ttl = service_binding_ttl
        self._max_cache_age = max_cache_age
        self._outage_policy = outage_policy
        # Staleness tracking: last successful chain fetch per type
        self._last_refresh: dict[str, float] = {}

    # ── Startup ─────────────────────────────────────────────────────────

    async def load_persistent(self) -> None:
        """Load persisted cache on startup."""
        if self._persistent is None:
            return
        loaded = self._persistent.load(self._deserialise_entry)
        if loaded:
            self._mem.load_dict(loaded)
            logger.info("Trust layer persistent cache loaded")

    # ── Public API ───────────────────────────────────────────────────────

    async def get_issuer(self, did: str) -> Optional[IssuerRecord]:
        return await self._cached_fetch(
            ns=_NS_ISSUER,
            key=did,
            ttl=self._issuer_ttl,
            fetcher=lambda: self._fetch_issuer(did),
            type_label="issuer",
        )

    async def get_policy_params(self) -> PolicyParams:
        result = await self._cached_fetch(
            ns=_NS_POLICY,
            key=_POLICY_KEY,
            ttl=self._policy_ttl,
            fetcher=lambda: self._fetch_policy_params(),
            type_label="policy",
        )
        if result is None:
            # Return safe defaults if cache empty and chain unavailable
            return PolicyParams(
                max_clock_skew_seconds=300,
                revocation_delta_seconds=300,
                require_vpq=False,
                cached_at=0.0,
            )
        return result

    async def get_status_anchor(self, status_list_id: str) -> Optional[StatusAnchor]:
        return await self._cached_fetch(
            ns=_NS_STATUS_ANCHOR,
            key=status_list_id,
            ttl=self._status_anchor_ttl,
            fetcher=lambda: self._fetch_status_anchor(status_list_id),
            type_label="status_anchor",
        )

    async def get_service_binding(self, service_id: str, env: str) -> Optional[ServiceBinding]:
        cache_key = f"{service_id}:{env}"
        return await self._cached_fetch(
            ns=_NS_SERVICE_BINDING,
            key=cache_key,
            ttl=self._service_binding_ttl,
            fetcher=lambda: self._fetch_service_binding(service_id, env),
            type_label="service_binding",
        )

    async def is_issuer_trusted(self, issuer_did: str, schema_id: Optional[str] = None) -> bool:
        """Return True if issuer_did is active and optionally has schema_id."""
        try:
            record = await self.get_issuer(issuer_did)
            if record is None:
                return False
            if not record.is_active:
                return False
            if schema_id is not None and not record.has_schema(schema_id):
                return False
            return True
        except Exception:
            return False

    async def invalidate_issuer(self, did: str) -> None:
        """Immediately evict an issuer from cache (e.g. on revocation event)."""
        await self._mem.invalidate(_NS_ISSUER, did)

    # ── Internal cache-aside logic ───────────────────────────────────────

    async def _cached_fetch(
        self,
        ns: str,
        key: str,
        ttl: float,
        fetcher,
        type_label: str,
    ):
        # 1. Memory cache hit
        cached = await self._mem.get(ns, key, ttl)
        if cached is not None:
            trust_cache_hits_total.labels(type=type_label).inc()
            return cached

        trust_cache_misses_total.labels(type=type_label).inc()

        # 2. Try chain
        try:
            result = await fetcher()
            if result is not None:
                await self._mem.put(ns, key, result)
                self._last_refresh[type_label] = time.time()
                trust_cache_staleness_seconds.labels(type=type_label).set(0)
            return result
        except Exception as exc:
            chain_rpc_errors_total.labels(method=type_label).inc()
            logger.warning("Chain fetch failed for %s(%s): %s", type_label, key, exc)

        # 3. Outage fallback: check persistent cache staleness
        return await self._outage_fallback(ns, key, ttl, type_label)

    async def _outage_fallback(self, ns: str, key: str, ttl: float, type_label: str):
        now = time.time()
        stale_age = now - self._last_refresh.get(type_label, 0.0)
        trust_cache_staleness_seconds.labels(type=type_label).set(stale_age)

        # Peek at any cached value without deleting it (TTL already expired)
        stale = await self._mem.peek(ns, key)

        if stale is None:
            # Try persistent fallback
            stale = await self._load_from_persistent(ns, key, type_label)

        if stale is not None:
            if stale_age <= self._max_cache_age or self._outage_policy == OutagePolicy.USE_CACHE:
                logger.warning(
                    "Serving stale %s (age=%.0fs, policy=%s)",
                    type_label, stale_age, self._outage_policy,
                )
                return stale
            # Stale beyond max age
            if self._outage_policy == OutagePolicy.FAIL_CLOSED:
                trust_layer_unavailable_total.inc()
                raise TrustLayerUnavailable(
                    f"Chain unavailable and cache too stale for {type_label} ({stale_age:.0f}s)"
                )
            if self._outage_policy == OutagePolicy.DEGRADE_READ_ONLY:
                trust_layer_unavailable_total.inc()
                logger.warning("DEGRADE_READ_ONLY: serving very stale %s (age=%.0fs)", type_label, stale_age)
                return stale

        return None

    async def _load_from_persistent(self, ns: str, key: str, type_label: str):
        """Try to load a specific key from the persistent cache."""
        if self._persistent is None:
            return None
        loaded = self._persistent.load(self._deserialise_entry)
        if loaded and ns in loaded and key in loaded[ns]:
            value, ts = loaded[ns][key]
            await self._mem.put(ns, key, value)
            return value
        return None

    # ── Chain fetch methods ──────────────────────────────────────────────

    async def _fetch_issuer(self, did: str) -> Optional[IssuerRecord]:
        # Subclassed or injected; base returns None
        return None

    async def _fetch_policy_params(self) -> Optional[PolicyParams]:
        return None

    async def _fetch_status_anchor(self, status_list_id: str) -> Optional[StatusAnchor]:
        return None

    async def _fetch_service_binding(self, service_id: str, env: str) -> Optional[ServiceBinding]:
        return None

    # ── Serialisation helpers ────────────────────────────────────────────

    def _deserialise_entry(self, ns: str, key: str, value_dict: dict, ts: float):
        """Reconstruct a dataclass from a JSON-decoded dict."""
        try:
            if ns == _NS_ISSUER:
                return IssuerRecord(
                    did=value_dict["did"],
                    is_active=value_dict["is_active"],
                    schemas=tuple(value_dict.get("schemas", [])),
                    cached_at=value_dict.get("cached_at", ts),
                )
            if ns == _NS_POLICY:
                return PolicyParams(
                    max_clock_skew_seconds=value_dict["max_clock_skew_seconds"],
                    revocation_delta_seconds=value_dict["revocation_delta_seconds"],
                    require_vpq=value_dict["require_vpq"],
                    cached_at=value_dict.get("cached_at", ts),
                )
            if ns == _NS_STATUS_ANCHOR:
                return StatusAnchor(
                    status_list_id=value_dict["status_list_id"],
                    root_hash=value_dict["root_hash"],
                    updated_at=value_dict["updated_at"],
                    cached_at=value_dict.get("cached_at", ts),
                )
            if ns == _NS_SERVICE_BINDING:
                return ServiceBinding(
                    service_id=value_dict["service_id"],
                    producer_did=value_dict["producer_did"],
                    env=value_dict["env"],
                    endpoint=value_dict["endpoint"],
                    cached_at=value_dict.get("cached_at", ts),
                )
        except Exception as exc:
            logger.warning("Could not deserialise %s/%s: %s", ns, key, exc)
        return None
