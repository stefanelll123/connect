"""In-memory LRU cache with TTL enforcement — anti-replay fallback (TASK-050).

Used when Redis is unavailable.  Does NOT survive process restart — this is
intentional: proof JWTs have short TTLs (≤60s) and the risk window is bounded.
"""
from __future__ import annotations

import collections
import logging
import time

logger = logging.getLogger(__name__)

_CLEANUP_INTERVAL = 1_000  # batch-evict expired entries every N inserts


class MemoryLRUCache:
    """Bounded LRU in-memory store with per-entry TTL.

    Designed as a thread-safe (GIL) drop-in fallback for Redis SET NX EX.
    Used by :class:`~common.anti_replay.replay_cache.ReplayCache`.

    Args:
        max_entries: Maximum number of live entries before LRU eviction.
    """

    def __init__(self, max_entries: int = 50_000) -> None:
        # key → (inserted_at, ttl_seconds)
        self._store: collections.OrderedDict[str, tuple[float, int]] = (
            collections.OrderedDict()
        )
        self._max = max_entries
        self._insert_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_nx_ex(self, key: str, ttl_seconds: int) -> bool:
        """Atomically insert *key* with a TTL if it is not already present.

        Returns:
            ``True``  — key was new and has been inserted.
            ``False`` — key already exists and TTL has not yet elapsed (replay).
        """
        now = time.time()

        if key in self._store:
            inserted_at, ttl = self._store[key]
            if now - inserted_at < ttl:
                return False  # still valid → replay
            # expired → allow re-insert (fall through)
            del self._store[key]

        # Evict LRU entry when at capacity
        while len(self._store) >= self._max:
            self._store.popitem(last=False)

        self._store[key] = (now, ttl_seconds)
        self._insert_count += 1

        if self._insert_count % _CLEANUP_INTERVAL == 0:
            self.cleanup_expired()

        return True

    def cleanup_expired(self) -> int:
        """Remove all entries whose TTL has elapsed.

        Returns:
            Number of entries removed.
        """
        now = time.time()
        expired = [
            k for k, (inserted_at, ttl) in self._store.items()
            if now - inserted_at >= ttl
        ]
        for k in expired:
            del self._store[k]
        if expired:
            logger.debug("event=memory_lru_cleanup removed=%d", len(expired))
        return len(expired)

    def __len__(self) -> int:  # for tests
        return len(self._store)
