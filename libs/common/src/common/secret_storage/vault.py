"""VaultSecretStorage — HashiCorp Vault KV v2 async backend.

Authentication uses the AppRole method. The client token is renewed at 75 % of its
``lease_duration`` to avoid expiry mid-operation. If renewal fails, the next request
triggers a full re-authentication.

Secret layout in Vault KV v2::

    <vault_kv_mount>/data/<key>
    e.g. secret/data/sentinels/svc1/producer/dev/did_private_key
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time

import httpx

from common.secret_storage.base import (
    SecretAccessDeniedError,
    SecretNotFoundError,
    SecretStorageCorruptedError,
    SecretStorageUnavailableError,
)

logger = logging.getLogger(__name__)


class VaultSecretStorage:
    """Async Vault KV v2 secret storage with AppRole authentication.

    Args:
        vault_addr:  Base URL of the Vault server (e.g. ``http://vault:8200``).
        role_id:     AppRole role ID.
        secret_id:   AppRole secret ID.
        kv_mount:    KV v2 mount path (default ``secret``).
        http_client: Optional pre-configured :class:`httpx.AsyncClient`; used for testing.
    """

    def __init__(
        self,
        vault_addr: str,
        role_id: str,
        secret_id: str,
        kv_mount: str = "secret",
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._vault_addr = vault_addr.rstrip("/")
        self._role_id = role_id
        self._secret_id = secret_id
        self._kv_mount = kv_mount.strip("/")
        self._client = http_client or httpx.AsyncClient(
            base_url=self._vault_addr, timeout=10.0
        )
        self._token: str | None = None
        self._token_expires_at: float = 0.0
        self._renewal_task: asyncio.Task[None] | None = None
        self._auth_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Authenticate and start the background token renewal loop."""
        await self._authenticate()
        self._renewal_task = asyncio.create_task(
            self._renewal_loop(), name="vault-token-renewal"
        )

    async def close(self) -> None:
        """Cancel the renewal loop and close the HTTP client."""
        if self._renewal_task is not None and not self._renewal_task.done():
            self._renewal_task.cancel()
            try:
                await self._renewal_task
            except asyncio.CancelledError:
                pass
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def get(self, key: str) -> bytes:
        """Return the secret bytes stored at *key*.

        Raises:
            SecretNotFoundError: HTTP 404 from Vault.
            SecretAccessDeniedError: HTTP 403 from Vault.
            SecretStorageCorruptedError: unexpected response structure.
            SecretStorageUnavailableError: network failure.
        """
        token = await self._ensure_authenticated()
        url = f"/v1/{self._kv_mount}/data/{key}"
        try:
            resp = await self._client.get(url, headers={"X-Vault-Token": token})
        except httpx.ConnectError as exc:
            raise SecretStorageUnavailableError(str(exc)) from exc
        if resp.status_code == 404:
            raise SecretNotFoundError(key)
        if resp.status_code == 403:
            raise SecretAccessDeniedError(key)
        resp.raise_for_status()
        try:
            encoded: str = resp.json()["data"]["data"]["value"]
            return base64.b64decode(encoded)
        except (KeyError, ValueError) as exc:
            raise SecretStorageCorruptedError(key) from exc

    async def set(self, key: str, value: bytes) -> None:
        """Store *value* (base64-encoded) under *key* in Vault KV v2.

        Raises:
            SecretAccessDeniedError: HTTP 403 from Vault.
            SecretStorageUnavailableError: network failure.
        """
        token = await self._ensure_authenticated()
        url = f"/v1/{self._kv_mount}/data/{key}"
        payload = {"data": {"value": base64.b64encode(value).decode()}}
        try:
            resp = await self._client.post(
                url, headers={"X-Vault-Token": token}, json=payload
            )
        except httpx.ConnectError as exc:
            raise SecretStorageUnavailableError(str(exc)) from exc
        if resp.status_code == 403:
            raise SecretAccessDeniedError(key)
        resp.raise_for_status()

    async def delete(self, key: str) -> None:
        """Hard-delete all versions and metadata for *key*. No-op on 404.

        Raises:
            SecretAccessDeniedError: HTTP 403 from Vault.
            SecretStorageUnavailableError: network failure.
        """
        token = await self._ensure_authenticated()
        url = f"/v1/{self._kv_mount}/metadata/{key}"
        try:
            resp = await self._client.delete(url, headers={"X-Vault-Token": token})
        except httpx.ConnectError as exc:
            raise SecretStorageUnavailableError(str(exc)) from exc
        if resp.status_code == 403:
            raise SecretAccessDeniedError(key)
        # 404 is acceptable (idempotent)
        if resp.status_code not in (200, 204, 404):
            resp.raise_for_status()

    async def exists(self, key: str) -> bool:
        """Return ``True`` if *key* is present in Vault."""
        try:
            await self.get(key)
            return True
        except SecretNotFoundError:
            return False

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    async def _ensure_authenticated(self) -> str:
        if self._token is not None and time.monotonic() < self._token_expires_at:
            return self._token
        async with self._auth_lock:
            # Double-checked locking: another coroutine may have refreshed the token
            if self._token is not None and time.monotonic() < self._token_expires_at:
                return self._token
            await self._authenticate()
        assert self._token is not None  # noqa: S101
        return self._token

    async def _authenticate(self) -> None:
        payload = {"role_id": self._role_id, "secret_id": self._secret_id}
        try:
            resp = await self._client.post("/v1/auth/approle/login", json=payload)
        except httpx.ConnectError as exc:
            raise SecretStorageUnavailableError(
                f"Cannot connect to Vault at {self._vault_addr}: {exc}"
            ) from exc
        if resp.status_code == 403:
            raise SecretAccessDeniedError("vault_approle_login")
        resp.raise_for_status()

        auth = resp.json()["auth"]
        self._token = auth["client_token"]
        lease_duration: int = auth.get("lease_duration", 3600)
        # Schedule renewal at 75 % of lease to avoid expiry mid-operation
        self._token_expires_at = time.monotonic() + lease_duration * 0.75
        # Token MUST NOT be logged
        logger.debug(
            "Vault: authenticated via AppRole (lease=%ds, renews_in=%.0fs)",
            lease_duration,
            lease_duration * 0.75,
        )

    async def _renewal_loop(self) -> None:
        """Background loop that re-authenticates before the token expires."""
        while True:
            sleep_s = max(0.0, self._token_expires_at - time.monotonic())
            await asyncio.sleep(sleep_s)
            try:
                await self._authenticate()
                logger.debug("Vault: token renewed")
            except Exception:
                logger.warning(
                    "Vault: token renewal failed; will re-authenticate on next request"
                )
                self._token = None
                self._token_expires_at = 0.0
                # Stop the renewal loop; _ensure_authenticated will re-auth
                break
