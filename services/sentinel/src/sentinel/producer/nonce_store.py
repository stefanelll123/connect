"""NonceStore — single-use nonce management for the session-exchange handshake.

Producer sentinels issue short-lived nonces via ``GET /auth/nonce``.  The
consumer embeds the nonce in its KB-JWT.  The producer then calls
:meth:`NonceStore.consume` to atomically verify *and* delete the nonce,
preventing replay attacks on the session-exchange endpoint.

Backend selection
-----------------
* **Redis** (production): atomic ``SET NX EX`` + ``GETDEL`` ensure that nonces
  are visible across multiple producer instances and survive per-process memory
  resets.
* **In-memory dict** (dev / unit tests): used automatically when no Redis
  client is provided.  Not safe for multi-instance deployments.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Optional

logger = logging.getLogger(__name__)

_REDIS_KEY_PREFIX = "sentinel:nonce:"


class NonceStore:
    """Single-use nonce registry backed by Redis or an in-memory fallback.

    Parameters
    ----------
    redis_client:
        An async Redis client (e.g. ``redis.asyncio.Redis``).  When ``None``
        the store falls back to an in-process dict — **not** safe for
        production multi-instance deployments.
    ttl:
        Nonce lifetime in seconds.  After this the nonce is automatically
        invalid even if :meth:`consume` was never called.
    """

    def __init__(self, redis_client=None, ttl: int = 60) -> None:
        self._redis = redis_client
        self._ttl = ttl
        # In-memory fallback: {nonce: exp_timestamp}
        self._mem: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def issue(self) -> str:
        """Generate and store a fresh single-use nonce.

        Returns
        -------
        str
            UUID4 nonce string.
        """
        nonce = str(uuid.uuid4())
        if self._redis is not None:
            try:
                key = f"{_REDIS_KEY_PREFIX}{nonce}"
                # SET key 1 NX EX ttl — only sets if not exists (guaranteed unique)
                await self._redis.set(key, "1", nx=True, ex=self._ttl)
                return nonce
            except Exception as exc:
                logger.warning("Redis nonce issue failed, using in-memory fallback: %s", exc)
        # In-memory fallback
        self._mem[nonce] = time.time() + self._ttl
        self._purge_expired()
        return nonce

    async def consume(self, nonce: str) -> bool:
        """Atomically verify and delete a nonce (single-use guarantee).

        Parameters
        ----------
        nonce:
            The nonce string to consume.

        Returns
        -------
        bool
            ``True`` if the nonce existed and was successfully deleted.
            ``False`` if the nonce was not found or already consumed.
        """
        if not nonce:
            return False

        if self._redis is not None:
            try:
                key = f"{_REDIS_KEY_PREFIX}{nonce}"
                # GETDEL is atomic: returns the value and deletes in one step
                result = await self._redis.getdel(key)
                return result is not None
            except Exception as exc:
                logger.warning("Redis nonce consume failed, using in-memory fallback: %s", exc)

        # In-memory fallback
        exp = self._mem.pop(nonce, None)
        if exp is None:
            return False
        if time.time() > exp:
            return False  # expired
        return True

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _purge_expired(self) -> None:
        """Remove expired entries from the in-memory fallback dict."""
        now = time.time()
        expired = [k for k, exp in self._mem.items() if now > exp]
        for k in expired:
            del self._mem[k]
