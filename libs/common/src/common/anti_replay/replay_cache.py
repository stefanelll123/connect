"""Redis-backed replay cache with in-memory LRU fallback (TASK-050).

Key layout:  ``replay:{service_id}:{env}:{sha256(jti|iss|aud)}``

The ``{service_id}:{env}`` prefix prevents cross-service JTI collisions on a
shared Redis instance.  All inserts are atomic (SET NX EX) to close the TOCTOU
race window that a GET-then-SET pattern would leave open.
"""
from __future__ import annotations

import hashlib
import logging

from common.anti_replay.memory_lru import MemoryLRUCache
from common.anti_replay.metrics import (
    REPLAY_INSERTS,
    REPLAY_REDIS_FALLBACK,
    REPLAY_REJECTS,
)

logger = logging.getLogger(__name__)


def _make_key(service_id: str, env: str, jti: str, iss: str, aud: str) -> str:
    """Compute the namespaced Redis key for a (jti, iss, aud) triple."""
    digest = hashlib.sha256(f"{jti}|{iss}|{aud}".encode()).hexdigest()
    return f"replay:{service_id}:{env}:{digest}"


class ReplayCache:
    """JTI deduplication cache.

    Primary: Redis (async SET NX EX).
    Fallback: :class:`~common.anti_replay.memory_lru.MemoryLRUCache`.

    Args:
        redis_client: An async Redis client (``redis.asyncio.Redis`` or compatible).
                      May be ``None`` — the in-memory fallback will be used exclusively.
        service_id:   Sentinel service identifier (used as key namespace).
        env:          Deployment environment (e.g. ``"prod"``, ``"staging"``).
        fallback:     Optional pre-constructed :class:`MemoryLRUCache`.
                      Created automatically if not provided.
    """

    def __init__(
        self,
        redis_client=None,
        service_id: str = "default",
        env: str = "default",
        fallback: MemoryLRUCache | None = None,
    ) -> None:
        self._redis = redis_client
        self._service_id = service_id
        self._env = env
        self._fallback: MemoryLRUCache = fallback or MemoryLRUCache()

    async def check_and_insert(
        self,
        jti: str,
        iss: str,
        aud: str,
        ttl_seconds: int,
    ) -> bool:
        """Atomically check-and-insert a JTI.

        Returns:
            ``True``  — JTI was new; inserted successfully (not a replay).
            ``False`` — JTI already present; **REPLAY DETECTED**.
        """
        key = _make_key(self._service_id, self._env, jti, iss, aud)

        if self._redis is not None:
            try:
                result = await self._redis.set(key, "1", nx=True, ex=ttl_seconds)
                inserted = result is not None  # SET NX returns None if key existed
                if inserted:
                    REPLAY_INSERTS.inc()
                else:
                    REPLAY_REJECTS.inc()
                return inserted
            except Exception as exc:
                logger.warning(
                    "event=replay_cache_redis_fallback service_id=%s env=%s error=%s",
                    self._service_id,
                    self._env,
                    exc,
                )
                REPLAY_REDIS_FALLBACK.inc()

        # Fall through to in-memory LRU when Redis is unavailable or not configured.
        inserted = self._fallback.set_nx_ex(key, ttl_seconds)
        if inserted:
            REPLAY_INSERTS.inc()
        else:
            REPLAY_REJECTS.inc()
        return inserted
