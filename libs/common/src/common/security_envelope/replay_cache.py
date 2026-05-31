"""ReplayCache — atomic JTI replay detection (TASK-043).

Primary store: Redis (SET key NX EX ttl).
Fallback: in-memory LRU dict with TTL enforcement (single-process only).

The in-memory fallback is explicitly noted as NOT persisting across restarts.
For proof JWTs with 60s TTL, the risk window is small and acceptable.
"""
from __future__ import annotations

import collections
import hashlib
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

_FALLBACK_MAX_ENTRIES = 50_000


def _jti_key(jti: str, iss: str, aud: str) -> str:
    """Compute the Redis key for a (jti, iss, aud) triple."""
    raw = f"{jti}:{iss}:{aud}".encode()
    return f"replay:{hashlib.sha256(raw).hexdigest()}"


class _MemoryFallback:
    """Bounded LRU in-memory replay store with TTL enforcement."""

    def __init__(self, max_entries: int = _FALLBACK_MAX_ENTRIES) -> None:
        # key → expiry timestamp
        self._store: collections.OrderedDict[str, float] = collections.OrderedDict()
        self._max = max_entries

    def check_and_insert(self, key: str, ttl_seconds: int) -> bool:
        """Return True (inserted) if key is new, False if already present."""
        now = time.time()
        if key in self._store:
            if self._store[key] > now:
                return False  # still valid — replay
            # expired — allow re-insert
            del self._store[key]

        # Evict LRU if at capacity
        while len(self._store) >= self._max:
            self._store.popitem(last=False)

        self._store[key] = now + ttl_seconds
        return True


class ReplayCache:
    """JTI replay cache backed by Redis with in-memory fallback.

    Args:
        redis_client:   Optional async Redis client (e.g. ``redis.asyncio.Redis``).
                        If None or if Redis raises, falls back to in-memory store.
    """

    def __init__(self, redis_client=None) -> None:
        self._redis = redis_client
        self._fallback = _MemoryFallback()

    async def check_and_insert(
        self,
        jti: str,
        iss: str,
        aud: str,
        ttl_seconds: int,
    ) -> bool:
        """Atomically check-and-insert a JTI.

        Returns:
            True  — jti was NEW (inserted successfully, not a replay).
            False — jti already present (REPLAY DETECTED).
        """
        key = _jti_key(jti, iss, aud)
        if self._redis is not None:
            try:
                result = await self._redis.set(key, "1", nx=True, ex=ttl_seconds)
                return result is not None  # SET NX returns None if key already existed
            except Exception as exc:
                logger.warning(
                    "ReplayCache Redis error (falling back to in-memory): %s", exc
                )
        return self._fallback.check_and_insert(key, ttl_seconds)
