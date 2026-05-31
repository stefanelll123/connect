"""ChainPolicyCache — in-process TTL cache for on-chain issuer/policy state (TASK-031).

Reads from IssuerRegistry and TrustPolicyRegistry contracts (via ChainClient).
Provides fast synchronous access to is_issuer_active() and get_policy().
Falls back to stale cache when RPC is unavailable.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from discovery.chain.client import IssuerRegistryClient

logger = logging.getLogger(__name__)

_DEFAULT_TTL_SECONDS = 300  # 5 minutes


@dataclass
class PolicyParams:
    env: str
    max_token_ttl_seconds: int = 3600
    require_chain_of_trust: bool = False
    raw: dict = field(default_factory=dict)


@dataclass
class IssuerEntry:
    did: str
    is_active: bool
    schema_hashes: list[str] = field(default_factory=list)


class ChainPolicyCache:
    """Thread-safe in-process cache for chain issuer/policy data.

    Usage::

        cache = ChainPolicyCache(settings)
        await cache.load()
        if cache.is_issuer_active("did:key:..."):
            ...
    """

    def __init__(self, settings: Any, issuer_client: Optional[IssuerRegistryClient] = None) -> None:
        self._settings = settings
        self._issuer_client = issuer_client
        self._issuers: dict[str, IssuerEntry] = {}
        self._policies: dict[str, PolicyParams] = {}
        self._last_loaded_at: Optional[datetime] = None
        self._stale: bool = False
        self._lock = asyncio.Lock()
        self._ttl = timedelta(seconds=_DEFAULT_TTL_SECONDS)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_issuer_active(self, did: str) -> bool:
        """Return True if the DID is a known active issuer.  Fails-safe: returns True
        if cache is empty (chain unavailable) to avoid blocking enrollments."""
        if not self._issuers:
            return True  # fail-open when chain unavailable
        entry = self._issuers.get(did)
        return entry.is_active if entry else False

    def get_policy(self, env: str) -> PolicyParams:
        """Return policy params for environment.  Returns defaults if unknown."""
        return self._policies.get(env, PolicyParams(env=env))

    @property
    def is_stale(self) -> bool:
        return self._stale

    @property
    def last_loaded_at(self) -> Optional[datetime]:
        return self._last_loaded_at

    @property
    def cache_age_seconds(self) -> float:
        if self._last_loaded_at is None:
            return float("inf")
        return (datetime.now(timezone.utc) - self._last_loaded_at).total_seconds()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    async def load(self) -> None:
        """Load fresh data from chain.  Catches all RPC errors gracefully."""
        async with self._lock:
            await self._do_load()

    async def load_if_stale(self) -> None:
        """Trigger reload only when TTL has expired."""
        if self.cache_age_seconds > self._ttl.total_seconds():
            await self.load()

    async def _do_load(self) -> None:
        if not self._settings.blockchain_integration:
            logger.debug("Blockchain integration disabled — using empty policy cache")
            self._last_loaded_at = datetime.now(timezone.utc)
            self._stale = False
            return

        try:
            await self._fetch_issuers()
            await self._fetch_policies()
            self._stale = False
            self._last_loaded_at = datetime.now(timezone.utc)
            logger.info(
                "ChainPolicyCache refreshed: %d issuers, %d policies",
                len(self._issuers),
                len(self._policies),
            )
        except Exception as exc:
            self._stale = True
            logger.warning(
                "ChainPolicyCache reload failed (using stale data): %s", exc
            )

    async def _fetch_issuers(self) -> None:
        """Load all issuers from IssuerRegistry contract."""
        if self._issuer_client is None:
            self._issuers = {}
            return
        records = await self._issuer_client.get_all_issuers()
        self._issuers = {
            r["did"]: IssuerEntry(did=r["did"], is_active=r["active"])
            for r in records
        }

    async def _fetch_policies(self) -> None:
        """Policy loading not yet wired — uses empty defaults."""
        self._policies = {}


# ---------------------------------------------------------------------------
# Module-level singleton access (set by app lifespan)
# ---------------------------------------------------------------------------

_global_cache: Optional[ChainPolicyCache] = None


def get_chain_policy_cache() -> Optional[ChainPolicyCache]:
    return _global_cache


def set_chain_policy_cache(cache: ChainPolicyCache) -> None:
    global _global_cache
    _global_cache = cache
