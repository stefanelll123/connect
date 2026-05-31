"""Unit tests for the anti-replay subsystem (TASK-050).

Test cases:
  1.  First insert returns True (JTI is new)
  2.  Duplicate insert returns False (replay detected — Redis)
  3.  Expired entry returns True (treated as new, re-insert allowed)
  4.  MemoryLRU fallback behaves identically (same assertions as #1-3)
  5.  Redis failure triggers in-memory fallback, no exception propagated
  6.  NonceStore generate + consume round-trip succeeds
  7.  NonceStore replay of same nonce returns False (nonce consumed)
  8.  Clock skew exactly at limit accepted (no exception)
  9.  Clock skew one second over limit rejected (ClockSkewError raised)
  10. Expired proof rejected with PROOF_EXPIRED (not CLOCK_SKEW_EXCEEDED)
"""
from __future__ import annotations

import time

import pytest
import fakeredis.aioredis as fakeredis_async

from common.anti_replay.clock_skew import ClockSkewError, validate_temporal_claims
from common.anti_replay.memory_lru import MemoryLRUCache
from common.anti_replay.nonce_store import NonceStore
from common.anti_replay.replay_cache import ReplayCache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _make_redis():
    """Create a fresh fakeredis async client."""
    return fakeredis_async.FakeRedis()


async def _make_cache(redis=None) -> ReplayCache:
    r = redis or await _make_redis()
    return ReplayCache(redis_client=r, service_id="svc-a", env="prod")


# ---------------------------------------------------------------------------
# Test 1: First insert returns True
# ---------------------------------------------------------------------------


class TestFirstInsert:
    async def test_first_insert_returns_true(self):
        cache = await _make_cache()
        result = await cache.check_and_insert("jti-1", "iss-a", "aud-a", ttl_seconds=60)
        assert result is True


# ---------------------------------------------------------------------------
# Test 2: Duplicate insert returns False (Redis path)
# ---------------------------------------------------------------------------


class TestDuplicateInsert:
    async def test_duplicate_returns_false(self):
        cache = await _make_cache()
        first = await cache.check_and_insert("jti-dup", "iss-a", "aud-a", ttl_seconds=60)
        second = await cache.check_and_insert("jti-dup", "iss-a", "aud-a", ttl_seconds=60)
        assert first is True
        assert second is False


# ---------------------------------------------------------------------------
# Test 3: Expired entry is treated as new after TTL elapses
# ---------------------------------------------------------------------------


class TestExpiredEntry:
    async def test_expired_entry_treated_as_new(self):
        cache = await _make_cache()
        # Insert with TTL of 1 second
        first = await cache.check_and_insert("jti-exp", "iss-a", "aud-a", ttl_seconds=1)
        assert first is True

        # Wait for TTL to elapse
        await _async_sleep(1.1)

        # Should be treated as new
        again = await cache.check_and_insert("jti-exp", "iss-a", "aud-a", ttl_seconds=60)
        assert again is True

    async def test_not_expired_still_rejected(self):
        cache = await _make_cache()
        await cache.check_and_insert("jti-live", "iss-a", "aud-a", ttl_seconds=60)
        result = await cache.check_and_insert("jti-live", "iss-a", "aud-a", ttl_seconds=60)
        assert result is False


# ---------------------------------------------------------------------------
# Test 4: MemoryLRUCache fallback behaves identically
# ---------------------------------------------------------------------------


class TestMemoryLRUFallback:
    def _mem_cache(self) -> ReplayCache:
        # Redis_client=None → uses in-memory fallback exclusively
        return ReplayCache(redis_client=None, service_id="svc-a", env="prod")

    async def test_first_insert_true(self):
        cache = self._mem_cache()
        assert await cache.check_and_insert("jti-m1", "iss", "aud", 60) is True

    async def test_duplicate_false(self):
        cache = self._mem_cache()
        await cache.check_and_insert("jti-m2", "iss", "aud", 60)
        assert await cache.check_and_insert("jti-m2", "iss", "aud", 60) is False

    def test_expired_entry_allowed(self):
        lru = MemoryLRUCache(max_entries=10)
        assert lru.set_nx_ex("key-ttl", ttl_seconds=1) is True
        # Simulate TTL expiry by manipulating inserted_at
        key = list(lru._store.keys())[0]
        inserted_at, ttl = lru._store[key]
        lru._store[key] = (inserted_at - 2, ttl)  # make it appear 2s old with 1s TTL
        assert lru.set_nx_ex("key-ttl", ttl_seconds=60) is True  # treated as new

    def test_lru_eviction_at_capacity(self):
        lru = MemoryLRUCache(max_entries=3)
        lru.set_nx_ex("k1", 60)
        lru.set_nx_ex("k2", 60)
        lru.set_nx_ex("k3", 60)
        # k1 should be evicted when k4 is inserted
        lru.set_nx_ex("k4", 60)
        assert len(lru) == 3
        assert "k1" not in lru._store  # oldest evicted


# ---------------------------------------------------------------------------
# Test 5: Redis failure triggers fallback, no exception propagated
# ---------------------------------------------------------------------------


class TestRedisFallback:
    async def test_redis_error_uses_memory_fallback(self):
        class _BrokenRedis:
            async def set(self, *_, **__):
                raise ConnectionError("Redis unavailable")

        cache = ReplayCache(
            redis_client=_BrokenRedis(),
            service_id="svc-a",
            env="prod",
        )
        # Must not raise; fallback to in-memory
        result = await cache.check_and_insert("jti-rb", "iss", "aud", 60)
        assert result is True  # in-memory fallback accepted the new jti

        # Duplicate still rejected by in-memory fallback
        result2 = await cache.check_and_insert("jti-rb", "iss", "aud", 60)
        assert result2 is False


# ---------------------------------------------------------------------------
# Test 6: NonceStore generate + consume round-trip
# ---------------------------------------------------------------------------


class TestNonceStoreRoundTrip:
    async def test_generate_and_consume_succeeds(self):
        r = await _make_redis()
        store = NonceStore(redis_client=r, service_id="svc-a")
        nonce = await store.generate("ctx-1", ttl_seconds=120)
        assert isinstance(nonce, str) and len(nonce) > 0
        result = await store.consume("ctx-1", nonce)
        assert result is True


# ---------------------------------------------------------------------------
# Test 7: Nonce replay rejected
# ---------------------------------------------------------------------------


class TestNonceReplay:
    async def test_second_consume_returns_false(self):
        r = await _make_redis()
        store = NonceStore(redis_client=r, service_id="svc-a")
        nonce = await store.generate("ctx-2", ttl_seconds=120)
        first = await store.consume("ctx-2", nonce)
        second = await store.consume("ctx-2", nonce)
        assert first is True
        assert second is False  # already consumed


# ---------------------------------------------------------------------------
# Test 8: Clock skew exactly at limit accepted
# ---------------------------------------------------------------------------


class TestClockSkewAtLimit:
    def test_iat_exactly_at_limit_accepted(self):
        now = time.time()
        skew = 30
        # iat exactly at the boundary (now + skew)
        validate_temporal_claims(
            iat=now + skew,
            exp=now + 60,
            max_clock_skew_seconds=skew,
            now=now,
        )  # must not raise

    def test_exp_exactly_at_limit_accepted(self):
        now = time.time()
        skew = 30
        # exp == now - skew: exactly at the boundary → accepted (< not <=)
        validate_temporal_claims(
            iat=now - 10,
            exp=now - skew,
            max_clock_skew_seconds=skew,
            now=now,
        )  # must not raise


# ---------------------------------------------------------------------------
# Test 9: Clock skew one second over limit rejected
# ---------------------------------------------------------------------------


class TestClockSkewOverLimit:
    def test_iat_one_second_over_limit_rejected(self):
        now = time.time()
        skew = 30
        with pytest.raises(ClockSkewError) as exc_info:
            validate_temporal_claims(
                iat=now + skew + 1,
                exp=now + 60,
                max_clock_skew_seconds=skew,
                now=now,
            )
        assert exc_info.value.code == "CLOCK_SKEW_EXCEEDED"
        assert exc_info.value.skew_seconds > 0


# ---------------------------------------------------------------------------
# Test 10: Expired proof rejected with PROOF_EXPIRED
# ---------------------------------------------------------------------------


class TestProofExpired:
    def test_expired_exp_rejected_as_proof_expired(self):
        now = time.time()
        skew = 30
        with pytest.raises(ClockSkewError) as exc_info:
            validate_temporal_claims(
                iat=now - 120,
                exp=now - skew - 1,  # one second past the tolerated boundary
                max_clock_skew_seconds=skew,
                now=now,
            )
        error = exc_info.value
        assert error.code == "PROOF_EXPIRED", (
            f"Expected PROOF_EXPIRED but got {error.code}"
        )
        assert error.skew_seconds > 0

    def test_future_iat_raises_clock_skew_not_proof_expired(self):
        now = time.time()
        skew = 10
        with pytest.raises(ClockSkewError) as exc_info:
            validate_temporal_claims(
                iat=now + skew + 5,  # too far in future
                exp=now + 3600,
                max_clock_skew_seconds=skew,
                now=now,
            )
        assert exc_info.value.code == "CLOCK_SKEW_EXCEEDED"


# ---------------------------------------------------------------------------
# Async sleep helper (avoid importing asyncio in test body directly)
# ---------------------------------------------------------------------------


async def _async_sleep(seconds: float) -> None:
    import asyncio
    await asyncio.sleep(seconds)
