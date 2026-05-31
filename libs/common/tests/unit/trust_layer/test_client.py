"""Unit tests for TrustLayerClient (TASK-042)."""
from __future__ import annotations

import asyncio
import dataclasses
import time
from pathlib import Path
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from common.trust_layer.cache_models import IssuerRecord, PolicyParams, StatusAnchor
from common.trust_layer.client import (
    OutagePolicy,
    TrustLayerClient,
    TrustLayerUnavailable,
    _NS_ISSUER,
    _NS_POLICY,
    _NS_STATUS_ANCHOR,
    _POLICY_KEY,
)
from common.trust_layer.memory_cache import MemoryCache
from common.trust_layer.persistent_cache import PersistentCache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_issuer(did: str = "did:key:zTest", is_active: bool = True) -> IssuerRecord:
    return IssuerRecord(did=did, is_active=is_active, schemas=("schema:1",), cached_at=time.time())


def _make_policy() -> PolicyParams:
    return PolicyParams(
        max_clock_skew_seconds=30,
        revocation_delta_seconds=60,
        require_vpq=False,
        cached_at=time.time(),
    )


def _make_anchor(sid: str = "sl:1") -> StatusAnchor:
    return StatusAnchor(
        status_list_id=sid,
        root_hash="0xabc",
        updated_at=time.time(),
        cached_at=time.time(),
    )


class _Client(TrustLayerClient):
    """TrustLayerClient subclass with injectable fetch functions for testing."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fetch_issuer_fn = None
        self.fetch_policy_fn = None
        self.fetch_anchor_fn = None

    async def _fetch_issuer(self, did: str) -> Optional[IssuerRecord]:
        if self.fetch_issuer_fn:
            return await self.fetch_issuer_fn(did)
        return None

    async def _fetch_policy_params(self) -> Optional[PolicyParams]:
        if self.fetch_policy_fn:
            return await self.fetch_policy_fn()
        return None

    async def _fetch_status_anchor(self, status_list_id: str) -> Optional[StatusAnchor]:
        if self.fetch_anchor_fn:
            return await self.fetch_anchor_fn(status_list_id)
        return None


# ---------------------------------------------------------------------------
# 1. Cache hit – chain NOT called
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cache_hit_skips_chain():
    """Second get_issuer call must return from cache without calling the chain."""
    call_count = 0

    async def fetch(did):
        nonlocal call_count
        call_count += 1
        return _make_issuer(did)

    client = _Client(issuer_ttl=60.0)
    client.fetch_issuer_fn = fetch

    did = "did:key:zABC"
    first = await client.get_issuer(did)
    second = await client.get_issuer(did)

    assert first is not None
    assert second is not None
    assert call_count == 1  # chain called once only


# ---------------------------------------------------------------------------
# 2. Cache miss – chain called, cache populated
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cache_miss_fetches_from_chain():
    """First get_issuer call must hit the chain and store result in memory cache."""
    fetched_dids = []

    async def fetch(did):
        fetched_dids.append(did)
        return _make_issuer(did)

    client = _Client(issuer_ttl=60.0)
    client.fetch_issuer_fn = fetch

    did = "did:key:zDEF"
    result = await client.get_issuer(did)

    assert result is not None
    assert result.did == did
    assert did in fetched_dids

    # Verify it's now in memory cache
    cached = await client._mem.get(_NS_ISSUER, did, ttl=60.0)
    assert cached is not None


# ---------------------------------------------------------------------------
# 3. Chain error + stale within max_outage_age + DEGRADE_READ_ONLY → stale
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_chain_error_within_max_age_degrade_read_only():
    """With DEGRADE_READ_ONLY and stale data within max_cache_age, return stale."""
    issuer = _make_issuer()
    call_count = 0

    async def fetch(did):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return issuer  # first call succeeds
        raise RuntimeError("chain down")

    client = _Client(
        issuer_ttl=60.0,
        max_cache_age=300.0,
        outage_policy=OutagePolicy.DEGRADE_READ_ONLY,
    )
    client.fetch_issuer_fn = fetch

    did = issuer.did

    # Populate cache
    await client.get_issuer(did)

    # Expire the memory cache TTL artificially
    store = client._mem._stores.get(_NS_ISSUER)
    assert store is not None
    old_value, _ = store[did]
    store[did] = (old_value, time.time() - 120.0)  # make it 2 min old

    # fetch_call will fail now
    result = await client.get_issuer(did)

    # We set last_refresh to ~now during first call, so stale_age is small
    assert result is not None  # stale served
    assert call_count == 2


# ---------------------------------------------------------------------------
# 4. Chain error + stale beyond max_outage_age + FAIL_CLOSED → raises
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_chain_error_beyond_max_age_fail_closed_raises():
    """With FAIL_CLOSED and stale data beyond max_cache_age, raise TrustLayerUnavailable."""
    issuer = _make_issuer()
    call_count = 0

    async def fetch(did):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return issuer
        raise RuntimeError("chain completely down")

    client = _Client(
        issuer_ttl=60.0,
        max_cache_age=10.0,  # very short max outage age
        outage_policy=OutagePolicy.FAIL_CLOSED,
    )
    client.fetch_issuer_fn = fetch

    did = issuer.did

    # Populate cache and set last_refresh to a long time ago
    await client.get_issuer(did)
    client._last_refresh["issuer"] = time.time() - 400.0  # 400s ago > max_cache_age=10s

    # Expire the memory cache entry
    store = client._mem._stores.get(_NS_ISSUER)
    old_value, _ = store[did]
    store[did] = (old_value, time.time() - 120.0)

    with pytest.raises(TrustLayerUnavailable):
        await client.get_issuer(did)


# ---------------------------------------------------------------------------
# 5. is_issuer_trusted returns False for inactive issuer
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_is_issuer_trusted_inactive_returns_false():
    """Inactive issuer must not be trusted."""
    inactive = _make_issuer(is_active=False)

    async def fetch(did):
        return inactive

    client = _Client(issuer_ttl=60.0)
    client.fetch_issuer_fn = fetch

    result = await client.is_issuer_trusted(inactive.did)
    assert result is False


@pytest.mark.asyncio
async def test_is_issuer_trusted_active_returns_true():
    """Active issuer without schema filter must be trusted."""
    active = _make_issuer(is_active=True)

    async def fetch(did):
        return active

    client = _Client(issuer_ttl=60.0)
    client.fetch_issuer_fn = fetch

    result = await client.is_issuer_trusted(active.did)
    assert result is True


@pytest.mark.asyncio
async def test_is_issuer_trusted_wrong_schema_returns_false():
    """Active issuer without matching schema must not be trusted."""
    active = IssuerRecord(
        did="did:key:zAAA", is_active=True, schemas=("schema:1",), cached_at=time.time()
    )

    async def fetch(did):
        return active

    client = _Client(issuer_ttl=60.0)
    client.fetch_issuer_fn = fetch

    assert await client.is_issuer_trusted(active.did, schema_id="schema:99") is False


@pytest.mark.asyncio
async def test_is_issuer_trusted_never_raises_on_exception():
    """is_issuer_trusted must return False, not propagate, when chain throws."""

    async def fetch(did):
        raise RuntimeError("unexpected")

    client = _Client(issuer_ttl=60.0, outage_policy=OutagePolicy.FAIL_CLOSED)
    client.fetch_issuer_fn = fetch

    result = await client.is_issuer_trusted("did:key:zBRK")
    assert result is False


# ---------------------------------------------------------------------------
# 6. Persistent cache survives restart
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_persistent_cache_survives_restart(tmp_path):
    """Flushing cache to disk and loading it in a new client returns the data."""
    cache_file = tmp_path / "trust_cache.enc"
    master_key = b"\x01" * 32

    # First "process": populate and flush
    def serialiser(value):
        return dataclasses.asdict(value)

    pc = PersistentCache(cache_file, master_key)
    mem1 = MemoryCache()
    issuer = _make_issuer("did:key:zPersist")
    await mem1.put(_NS_ISSUER, issuer.did, issuer)
    pc.flush(mem1, serialiser)
    assert cache_file.exists()

    # Second "process": create new client and load persistent cache
    def deserialiser(ns, key, value_dict, ts):
        if ns == _NS_ISSUER:
            return IssuerRecord(
                did=value_dict["did"],
                is_active=value_dict["is_active"],
                schemas=tuple(value_dict.get("schemas", [])),
                cached_at=value_dict.get("cached_at", ts),
            )
        return None

    pc2 = PersistentCache(cache_file, master_key)
    client2 = _Client(persistent_cache=pc2, issuer_ttl=60.0)
    await client2.load_persistent()

    # Should now find the issuer in memory cache
    cached = await client2._mem.get(_NS_ISSUER, issuer.did, ttl=300.0)
    assert cached is not None
    assert cached.did == issuer.did


# ---------------------------------------------------------------------------
# 7. invalidate_issuer removes from cache
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_invalidate_issuer_clears_cache():
    """After invalidation, the issuer must be re-fetched from the chain."""
    call_count = 0

    async def fetch(did):
        nonlocal call_count
        call_count += 1
        return _make_issuer(did)

    client = _Client(issuer_ttl=60.0)
    client.fetch_issuer_fn = fetch

    did = "did:key:zINVAL"
    await client.get_issuer(did)       # populate cache
    await client.invalidate_issuer(did)
    await client.get_issuer(did)       # must re-fetch

    assert call_count == 2


# ---------------------------------------------------------------------------
# 8. get_policy_params returns safe defaults when no chain and no cache
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_policy_params_returns_defaults_on_no_chain():
    """With no chain client, get_policy_params must return safe default values."""
    client = _Client()  # no fetch_policy_fn

    params = await client.get_policy_params()
    assert isinstance(params, PolicyParams)
    assert params.max_clock_skew_seconds > 0


# ---------------------------------------------------------------------------
# 9. Chain error + USE_CACHE policy always returns stale
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_use_cache_policy_returns_very_stale_data():
    """With USE_CACHE policy, serve stale data indefinitely regardless of age."""
    issuer = _make_issuer()
    call_count = 0

    async def fetch(did):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return issuer
        raise RuntimeError("chain down indefinitely")

    client = _Client(
        issuer_ttl=60.0,
        max_cache_age=10.0,
        outage_policy=OutagePolicy.USE_CACHE,
    )
    client.fetch_issuer_fn = fetch

    did = issuer.did
    await client.get_issuer(did)

    # Simulate very old stale data (600s) and very old last_refresh
    store = client._mem._stores[_NS_ISSUER]
    old_value, _ = store[did]
    store[did] = (old_value, time.time() - 600.0)
    client._last_refresh["issuer"] = time.time() - 600.0

    result = await client.get_issuer(did)
    assert result is not None  # USE_CACHE always serves stale
