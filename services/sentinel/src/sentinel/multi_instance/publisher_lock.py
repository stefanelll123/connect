"""Redis-based descriptor publish lock for multi-instance coordination (TASK-048).

Prevents simultaneous descriptor publication conflicts when N sentinel instances
start at the same time.  Uses ``SET key value NX EX ttl`` — one atomic command
with no TOCTOU race window.

Usage::

    lock = PublisherLock(
        redis_client=redis,
        service_id="payment-service",
        env="prod",
        instance_id=instance_id,
    )
    async with lock:
        await publish_descriptor(...)
    # lock released automatically on context-manager exit
"""
from __future__ import annotations

import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_TTL = 30      # seconds — Redis key TTL
_DEFAULT_WAIT = 5      # seconds — max time to wait for lock


class PublisherLock:
    """Distributed lock for descriptor publication.

    Args:
        redis_client: Async Redis client.  If ``None``, the lock is a no-op
                      (single-instance mode or Redis unavailable).
        service_id:   Service being registered.
        env:          Deployment environment.
        instance_id:  Unique ID of this sentinel instance (used as lock value
                      for safe release — only the holder can delete the key).
        ttl:          Lock key TTL in seconds (auto-released on crash).
        wait:         Seconds to wait for lock acquisition before giving up.
    """

    def __init__(
        self,
        redis_client=None,
        service_id: str = "",
        env: str = "dev",
        instance_id: str = "",
        ttl: int = _DEFAULT_TTL,
        wait: int = _DEFAULT_WAIT,
    ) -> None:
        self._redis = redis_client
        self._service_id = service_id
        self._env = env
        self._instance_id = instance_id
        self._ttl = ttl
        self._wait = wait
        self._key = f"sentinel_desc_lock:{service_id}:{env}"

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "PublisherLock":
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.release()

    # ------------------------------------------------------------------
    # Acquire / release
    # ------------------------------------------------------------------

    async def acquire(self) -> bool:
        """Try to acquire the lock within the wait window.

        Returns:
            ``True`` if acquired, ``False`` if timed out.  When Redis is
            unavailable, returns ``True`` to allow single-winner behaviour
            via last-write-wins at Discovery.
        """
        if self._redis is None:
            return True  # no-op mode

        deadline = time.monotonic() + self._wait
        poll_interval = 0.25

        while time.monotonic() < deadline:
            try:
                acquired = await self._redis.set(
                    self._key,
                    self._instance_id or "1",
                    nx=True,
                    ex=self._ttl,
                )
                if acquired:
                    logger.info(
                        "event=publisher_lock_acquired key=%s instance=%s",
                        self._key,
                        (self._instance_id or "?")[:8],
                    )
                    return True
            except Exception as exc:
                logger.warning(
                    "event=publisher_lock_redis_error key=%s error=%s — proceeding without lock",
                    self._key,
                    exc,
                )
                return True  # graceful degradation

            import asyncio
            await asyncio.sleep(poll_interval)

        logger.info(
            "event=publisher_lock_timeout key=%s — will check existing descriptor",
            self._key,
        )
        return False

    async def release(self) -> None:
        """Release the lock if this instance holds it.

        Uses a Lua-style conditional DEL by checking the stored value matches
        our ``instance_id`` — avoids deleting a lock held by another instance
        after TTL expiry.
        """
        if self._redis is None:
            return

        try:
            stored = await self._redis.get(self._key)
            stored_str = stored.decode() if isinstance(stored, bytes) else stored
            if stored_str == (self._instance_id or "1"):
                await self._redis.delete(self._key)
                logger.debug(
                    "event=publisher_lock_released key=%s", self._key
                )
        except Exception as exc:
            logger.warning(
                "event=publisher_lock_release_error key=%s error=%s", self._key, exc
            )
