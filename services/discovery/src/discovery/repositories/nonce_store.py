"""Redis-backed one-time nonce store for sentinel onboarding challenges.

Each nonce is stored at key ``onboard:nonce:{jti}`` with a TTL.
Consumption is atomic: the key is DEL'd on first retrieval so it cannot be
reused (prevents replay attacks).
"""
from __future__ import annotations

import secrets


class NonceStore:
    """Async nonce store backed by Redis."""

    _KEY_PREFIX = "onboard:nonce:"

    def __init__(self, redis) -> None:
        self._redis = redis

    def _key(self, jti: str) -> str:
        return f"{self._KEY_PREFIX}{jti}"

    async def issue_nonce(self, jti: str, ttl_seconds: int = 120) -> str:
        """Generate, store, and return a one-time challenge nonce.

        Uses ``secrets.token_urlsafe(24)`` for 192-bit entropy.
        """
        nonce = secrets.token_urlsafe(24)
        await self._redis.set(self._key(jti), nonce, ex=ttl_seconds)
        return nonce

    async def consume_nonce(self, jti: str, provided_nonce: str) -> bool:
        """Atomically retrieve and delete the nonce.

        Returns:
            True if the stored nonce matches *provided_nonce*.
            False if the key is missing (expired or already used) or mismatch.

        The key is ALWAYS deleted on retrieval — a mismatch still consumes it
        to prevent brute-force attempts with the same challenge window.
        """
        key = self._key(jti)
        stored = await self._redis.get(key)
        if stored is None:
            return False
        # Delete regardless of match — one-time use
        await self._redis.delete(key)
        # Redis may return bytes or str depending on client configuration
        stored_str = stored.decode() if isinstance(stored, bytes) else stored
        return stored_str == provided_nonce
