"""JTI replay cache implementations for the Request Security Envelope.

The replay cache is the primary defence against proof replay attacks.

Security invariant (from spec §7):
    The ``jti`` MUST be inserted into the replay cache **BEFORE** the
    request is forwarded to the backend service.  Inserting it after
    forwarding creates a TOCTOU window that allows race-condition replay.

Implementations
---------------
* :class:`InMemoryReplayCache` — single-node, in-process LRU/TTL cache.
  Suitable for development and single-instance deployments.  Provides
  **no** cross-instance replay protection.
* :class:`RedisReplayCache` — distributed cache backed by Redis ``SET NX``
  with automatic TTL.  Required for multi-instance (HA) deployments.

Both implement the :class:`ReplayCache` protocol so callers can swap them
without changing verification logic.
"""

from __future__ import annotations

import threading
import time
from typing import Protocol, runtime_checkable

__all__ = [
    "ReplayCache",
    "InMemoryReplayCache",
    "RedisReplayCache",
    "make_cache_key",
]

# ---------------------------------------------------------------------------
# Cache key helper
# ---------------------------------------------------------------------------

def make_cache_key(jti: str, iss: str) -> str:
    """Return the replay-cache lookup key for a proof.

    The key is ``replay:{jti}:{iss}`` — combining issuer DID prevents
    cross-issuer JTI collisions even if two Consumer Sentinels generate the
    same UUID by coincidence.

    Args:
        jti: Unique proof identifier (UUIDv4 string).
        iss: Issuer DID (Consumer Sentinel ``iss`` claim).

    Returns:
        Cache key string.
    """
    return f"replay:{jti}:{iss}"


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ReplayCache(Protocol):
    """Protocol for JTI replay detection stores.

    The two methods correspond to an atomic check-and-set: :meth:`is_seen`
    checks whether a key exists, and :meth:`mark_seen` inserts it with a
    TTL.  Callers MUST call :meth:`is_seen` first, then call
    :meth:`mark_seen` — but only if :meth:`is_seen` returned ``False``.

    .. warning::
       In Redis the atomic ``SET NX`` guarantees this.  In the in-memory
       implementation the GIL provides the atomicity.  In any distributed
       context, use :class:`RedisReplayCache`.
    """

    def is_seen(self, key: str) -> bool:
        """Return ``True`` if *key* has been recorded in the cache."""
        ...

    def mark_seen(self, key: str, ttl_seconds: int) -> bool:
        """Record *key* with expiry *ttl_seconds* from now.

        Returns:
            ``True`` if the key was newly inserted.
            ``False`` if it already existed (replay detected).

        The return value is equivalent to Redis ``SET NX``: callers must
        check it and reject the proof if ``False`` is returned.
        """
        ...


# ---------------------------------------------------------------------------
# In-memory implementation (single-node, LRU-evicting on max size)
# ---------------------------------------------------------------------------


class InMemoryReplayCache:
    """Thread-safe in-process replay cache using a dict with TTL.

    Entries are evicted lazily on each :meth:`is_seen` / :meth:`mark_seen`
    call when they fall past their expiry timestamp.

    Args:
        max_size: Maximum number of concurrent entries before the oldest
            *expired* entries are evicted.  If all entries are still live
            the cache will exceed *max_size* briefly.  Default: 10 000.

    .. note::
       This cache provides **no cross-instance protection**.  Deploy
       :class:`RedisReplayCache` for multi-instance Sentinel deployments.
    """

    def __init__(self, max_size: int = 10_000) -> None:
        self._store: dict[str, float] = {}  # key → expiry_timestamp
        self._lock = threading.Lock()
        self._max_size = max_size

    # ------------------------------------------------------------------
    # ReplayCache protocol implementation
    # ------------------------------------------------------------------

    def is_seen(self, key: str) -> bool:
        """Return ``True`` if *key* exists and has not expired."""
        with self._lock:
            expiry = self._store.get(key)
            if expiry is None:
                return False
            if time.time() > expiry:
                del self._store[key]
                return False
            return True

    def mark_seen(self, key: str, ttl_seconds: int) -> bool:
        """Atomically insert *key* if not already present.

        Returns:
            ``True`` if inserted (key was new).
            ``False`` if key already existed (replay — caller must reject).
        """
        with self._lock:
            now = time.time()
            existing = self._store.get(key)
            if existing is not None and now <= existing:
                return False  # already present and not yet expired → replay

            # Lazy eviction of expired entries when near capacity
            if len(self._store) >= self._max_size:
                expired_keys = [k for k, exp in self._store.items() if now > exp]
                for k in expired_keys:
                    del self._store[k]

            self._store[key] = now + ttl_seconds
            return True

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def size(self) -> int:
        """Return the current number of stored (possibly stale) entries."""
        with self._lock:
            return len(self._store)


# ---------------------------------------------------------------------------
# Redis implementation
# ---------------------------------------------------------------------------


class RedisReplayCache:
    """Distributed replay cache backed by Redis.

    Uses ``SET NX PX <ms>`` for atomic check-and-insert, which is the only
    correct implementation in a distributed environment.

    Args:
        redis_client: A ``redis.Redis`` (or compatible) client instance.
            Must be connected before passing to this class.

    Raises:
        ImportError: If the ``redis`` package is not installed.
    """

    def __init__(self, redis_client) -> None:  # type: ignore[no-untyped-def]
        self._redis = redis_client

    def is_seen(self, key: str) -> bool:
        """Return ``True`` if *key* exists in Redis."""
        return bool(self._redis.exists(key))

    def mark_seen(self, key: str, ttl_seconds: int) -> bool:
        """Atomically set *key* in Redis with expiry (``SET NX PX``).

        Returns:
            ``True`` if the key was newly inserted.
            ``False`` if it already existed (replay — caller must reject).
        """
        ttl_ms = max(1, ttl_seconds * 1000)
        result = self._redis.set(key, "1", px=ttl_ms, nx=True)
        return result is not None  # SET NX returns None if key existed
