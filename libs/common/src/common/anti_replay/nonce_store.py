"""NonceStore — one-time PoP challenge nonces (TASK-050).

Key layout:  ``nonce:{service_id}:{context_id}``

``consume()`` uses an atomic GET+DEL pipeline: the GET retrieves the value, the
immediate DEL in the same pipeline ensures only the first consumer succeeds
(subsequent DEL calls on the same key return 0, signalling a second consume
attempt).  The constant-time compare with :func:`hmac.compare_digest` prevents
timing oracles even when the key is absent.
"""
from __future__ import annotations

import hmac
import logging
import secrets

from common.anti_replay.metrics import NONCE_CONSUMED

logger = logging.getLogger(__name__)


class NonceStore:
    """One-time nonce store backed by Redis.

    Args:
        redis_client: Async Redis client (may not be ``None`` — NonceStore
                      requires Redis for atomic operations).
        service_id:   Used as key namespace prefix.
    """

    def __init__(self, redis_client, service_id: str = "default") -> None:
        self._redis = redis_client
        self._service_id = service_id

    def _key(self, context_id: str) -> str:
        return f"nonce:{self._service_id}:{context_id}"

    async def generate(self, context_id: str, ttl_seconds: int = 120) -> str:
        """Generate a cryptographically random nonce and store it.

        Args:
            context_id:   Unique identifier for the onboarding/session context.
            ttl_seconds:  Nonce lifetime (default 120 s).

        Returns:
            URL-safe base64 nonce string (32 bytes entropy).
        """
        nonce = secrets.token_urlsafe(32)
        key = self._key(context_id)
        # SET NX EX — if context_id already active, overwrite (idempotent)
        stored = await self._redis.set(key, nonce, nx=True, ex=ttl_seconds)
        if stored is None:
            await self._redis.set(key, nonce, ex=ttl_seconds)
        return nonce

    async def consume(self, context_id: str, provided_nonce: str) -> bool:
        """Validate and atomically consume a nonce (one-time use).

        Atomicity is achieved via a Redis pipeline: GET and DEL are issued in
        the same round-trip.  If a concurrent request also calls consume(), the
        one whose DEL returns 0 loses and returns False.

        The value comparison uses :func:`hmac.compare_digest` to prevent
        timing-based nonce oracle attacks.

        Args:
            context_id:     The same context ID used in :meth:`generate`.
            provided_nonce: Nonce to validate.

        Returns:
            ``True``  on match; the nonce has been deleted.
            ``False`` if not found, expired, or mismatched.
        """
        key = self._key(context_id)

        # Atomic GET then DEL in a pipeline — both commands execute in one
        # server round-trip.  DEL returns the number of deleted keys (0 or 1).
        async with self._redis.pipeline(transaction=False) as pipe:
            pipe.get(key)
            pipe.delete(key)
            stored_raw, deleted_count = await pipe.execute()

        if stored_raw is None:
            NONCE_CONSUMED.labels(result="expired").inc()
            logger.debug("event=nonce_not_found context_id=%s", context_id[:16])
            return False

        stored_str = stored_raw.decode() if isinstance(stored_raw, bytes) else stored_raw

        # Constant-time comparison (compare_digest requires equal-length strings
        # or bytes — pad only for the timing equality; actual mismatches still
        # return False).
        if not hmac.compare_digest(stored_str, provided_nonce):
            NONCE_CONSUMED.labels(result="mismatch").inc()
            logger.warning("event=nonce_mismatch context_id=%s", context_id[:16])
            return False

        # Concurrent consume: DEL already happened above; deleted_count would be
        # 0 if another consumer deleted it first (rare but handled).
        if deleted_count == 0:
            NONCE_CONSUMED.labels(result="mismatch").inc()
            logger.warning("event=nonce_concurrent_consume context_id=%s", context_id[:16])
            return False

        NONCE_CONSUMED.labels(result="match").inc()
        return True
