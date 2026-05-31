"""VaultClient — HashiCorp Vault integration for Sentinel key storage (TASK-038).

Features:
- Token-based authentication with automatic renewal (renew when TTL < 1 hour).
- ``vault_available`` flag: False when Vault is unreachable.
- ``VAULT_OUTAGE_POLICY``: fail_closed (raise) or read_only (use cache only).

Secret paths:
    sentinel/{sentinel_id}/did_private_key
    sentinel/{sentinel_id}/credentials/{jti}

Usage::

    client = VaultClient(settings)
    await client.start()            # begins the renewal loop

    key = await client.get_secret("did_private_key")
    await client.set_secret("did_private_key", key_bytes)

    await client.stop()
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from sentinel.config import SentinelSettings

logger = logging.getLogger(__name__)

_RENEWAL_CHECK_INTERVAL = 300   # seconds between TTL checks
_RENEWAL_THRESHOLD = 3600       # renew when TTL drops below 1 hour


class VaultClient:
    """Async Vault client with background token-renewal loop."""

    def __init__(self, settings: "SentinelSettings") -> None:
        self._vault_addr = settings.vault_addr
        self._token = settings.vault_token.get_secret_value()
        self._sentinel_id = settings.sentinel_id
        self._outage_policy = settings.vault_outage_policy
        self._client = None
        self._renewal_task: Optional[asyncio.Task] = None
        self.vault_available: bool = False

    # ── Lifecycle ───────────────────────────────────────────────────────

    async def start(self) -> None:
        """Initialise HVAC client and start the renewal loop."""
        try:
            import hvac
            self._client = hvac.Client(
                url=self._vault_addr,
                token=self._token,
            )
            if not self._client.is_authenticated():
                raise RuntimeError("Vault authentication failed")
            self.vault_available = True
            logger.info("Vault client authenticated at %s", self._vault_addr)
        except ImportError:
            logger.warning("hvac not installed; Vault integration disabled.")
            return
        except Exception as exc:
            logger.error("Vault unavailable at startup: %s", exc)
            self.vault_available = False
            return

        self._renewal_task = asyncio.create_task(self._renewal_loop())

    async def stop(self) -> None:
        """Cancel the renewal loop."""
        if self._renewal_task:
            self._renewal_task.cancel()
            try:
                await self._renewal_task
            except asyncio.CancelledError:
                pass

    # ── Secret operations ────────────────────────────────────────────────

    async def get_secret(self, key: str) -> bytes:
        """Read a secret from the sentinel's Vault path."""
        if not self.vault_available:
            if self._outage_policy == "fail_closed":
                raise RuntimeError("Vault unavailable and policy is fail_closed")
            raise RuntimeError("Vault unavailable (read_only policy — use cache)")

        path = f"sentinel/{self._sentinel_id}/{key}"
        return await asyncio.get_event_loop().run_in_executor(
            None, self._sync_read, path
        )

    async def set_secret(self, key: str, value: bytes) -> None:
        """Write a secret to the sentinel's Vault path."""
        if not self.vault_available:
            raise RuntimeError("Vault unavailable — cannot write secret")

        path = f"sentinel/{self._sentinel_id}/{key}"
        await asyncio.get_event_loop().run_in_executor(
            None, self._sync_write, path, value
        )

    # ── Internals ────────────────────────────────────────────────────────

    def _sync_read(self, path: str) -> bytes:
        response = self._client.secrets.kv.v2.read_secret_version(path=path)
        raw = response["data"]["data"].get("value", "")
        if isinstance(raw, str):
            import base64
            return base64.b64decode(raw)
        return raw

    def _sync_write(self, path: str, value: bytes) -> None:
        import base64
        self._client.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret={"value": base64.b64encode(value).decode()},
        )

    async def _renewal_loop(self) -> None:
        """Background task: renew the Vault token before it expires."""
        while True:
            await asyncio.sleep(_RENEWAL_CHECK_INTERVAL)
            try:
                loop = asyncio.get_event_loop()
                token_info = await loop.run_in_executor(
                    None,
                    lambda: self._client.auth.token.lookup_self(),
                )
                ttl = token_info["data"].get("ttl", 0)
                if ttl < _RENEWAL_THRESHOLD:
                    await loop.run_in_executor(
                        None,
                        lambda: self._client.auth.token.renew_self(),
                    )
                    logger.info("Vault token renewed (was %ds TTL)", ttl)
                else:
                    logger.debug("Vault token TTL=%ds — no renewal needed", ttl)
                self.vault_available = True
            except asyncio.CancelledError:
                return
            except Exception as exc:
                logger.error(
                    "Vault token renewal failed: %s. Marking vault_available=False", exc
                )
                self.vault_available = False
