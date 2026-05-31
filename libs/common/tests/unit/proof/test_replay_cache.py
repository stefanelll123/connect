"""Unit tests for common.proof.replay_cache."""

from __future__ import annotations

import threading
import time

import pytest

from common.proof.replay_cache import InMemoryReplayCache, ReplayCache, make_cache_key


# ---------------------------------------------------------------------------
# make_cache_key
# ---------------------------------------------------------------------------


class TestMakeCacheKey:
    def test_format(self) -> None:
        key = make_cache_key("jti-123", "did:key:z6Mktest")
        assert key == "replay:jti-123:did:key:z6Mktest"

    def test_different_jti_different_key(self) -> None:
        k1 = make_cache_key("aaa", "did:key:z6Mk")
        k2 = make_cache_key("bbb", "did:key:z6Mk")
        assert k1 != k2

    def test_different_iss_different_key(self) -> None:
        k1 = make_cache_key("jti", "did:key:z6MkA")
        k2 = make_cache_key("jti", "did:key:z6MkB")
        assert k1 != k2


# ---------------------------------------------------------------------------
# InMemoryReplayCache
# ---------------------------------------------------------------------------


class TestInMemoryReplayCacheBasic:
    def test_new_key_is_not_seen(self) -> None:
        cache = InMemoryReplayCache()
        assert not cache.is_seen("replay:abc:iss")

    def test_mark_seen_returns_true_for_new_key(self) -> None:
        cache = InMemoryReplayCache()
        result = cache.mark_seen("replay:key1:iss", ttl_seconds=60)
        assert result is True

    def test_is_seen_returns_true_after_mark(self) -> None:
        cache = InMemoryReplayCache()
        cache.mark_seen("replay:key2:iss", ttl_seconds=60)
        assert cache.is_seen("replay:key2:iss")

    def test_mark_seen_returns_false_for_duplicate(self) -> None:
        cache = InMemoryReplayCache()
        cache.mark_seen("replay:dup:iss", ttl_seconds=60)
        result = cache.mark_seen("replay:dup:iss", ttl_seconds=60)
        assert result is False

    def test_size_increases_on_insert(self) -> None:
        cache = InMemoryReplayCache()
        assert cache.size() == 0
        cache.mark_seen("k1", 60)
        assert cache.size() == 1
        cache.mark_seen("k2", 60)
        assert cache.size() == 2


class TestInMemoryReplayCacheTTL:
    def test_expired_entry_is_not_seen(self) -> None:
        cache = InMemoryReplayCache()
        cache.mark_seen("replay:exp:iss", ttl_seconds=1)
        # Manually expire by patching the expiry to the past
        with cache._lock:
            cache._store["replay:exp:iss"] = time.time() - 1
        assert not cache.is_seen("replay:exp:iss")

    def test_expired_entry_can_be_reinserted(self) -> None:
        cache = InMemoryReplayCache()
        cache.mark_seen("replay:reinsertion:iss", ttl_seconds=1)
        # Expire it manually
        with cache._lock:
            cache._store["replay:reinsertion:iss"] = time.time() - 1
        # Should now be insertable again
        result = cache.mark_seen("replay:reinsertion:iss", ttl_seconds=60)
        assert result is True

    def test_expired_entries_evicted_on_mark_seen_when_at_capacity(self) -> None:
        cache = InMemoryReplayCache(max_size=5)
        # Fill with expired entries
        for i in range(5):
            cache.mark_seen(f"key:{i}", ttl_seconds=1)
        # Manually expire all
        with cache._lock:
            for k in list(cache._store):
                cache._store[k] = time.time() - 1
        # Insert one more — expired keys should be evicted
        cache.mark_seen("new_key", ttl_seconds=60)
        assert cache.size() == 1


class TestInMemoryReplayCacheThreadSafety:
    def test_concurrent_mark_seen_exactly_one_wins(self) -> None:
        """Under concurrent writes, only one thread should win mark_seen."""
        cache = InMemoryReplayCache()
        results = []
        lock = threading.Lock()

        def _mark():
            result = cache.mark_seen("shared_key", ttl_seconds=60)
            with lock:
                results.append(result)

        threads = [threading.Thread(target=_mark) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly one thread should have won (True), all others False
        assert results.count(True) == 1
        assert results.count(False) == 19


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestReplayCacheProtocol:
    def test_in_memory_is_replay_cache_protocol(self) -> None:
        assert isinstance(InMemoryReplayCache(), ReplayCache)
