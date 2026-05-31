"""HashiCorp Vault KV v2 key storage backend.

Key path pattern::

    {kv_mount}/data/sentinels/{service_id}/{role}/{env}/did_private_key

Expected secret JSON stored at that path::

    {
        "private_key_hex": "<64 hex chars — 32 raw bytes>",
        "key_version": 1
    }

Authentication is token-based (``X-Vault-Token`` header).  For production
deployments, the token is obtained via Vault AppRole or Kubernetes auth before
constructing this backend; rotation of the token is the caller's responsibility.

This backend is **read-only in normal operation** — :meth:`write_key` is
provided only for initial provisioning and key rotation from the ``sentinelctl``
tooling.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx

from common.secret_storage.backend import KeyMaterial

__all__ = ["VaultKeyBackend"]


class VaultKeyBackend:
    """Vault KV v2 backed key storage.

    Args:
        vault_url: Base URL of the Vault server (e.g. ``"https://vault.example.com"``).
        token: Vault token with read (and optionally write) access to the key
            paths.
        kv_mount: KV v2 mount name (default ``"secret"``).
        timeout: HTTP timeout in seconds (default 5).
        http_client: Optional pre-configured :class:`httpx.Client` for
            dependency injection in tests.
    """

    def __init__(
        self,
        vault_url: str,
        token: str,
        kv_mount: str = "secret",
        timeout: float = 5.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._vault_url = vault_url.rstrip("/")
        self._token = token
        self._kv_mount = kv_mount
        self._timeout = timeout
        self._client = http_client or httpx.Client(timeout=timeout)

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _data_path(self, service_id: str, role: str, env: str) -> str:
        """Return the full Vault KV v2 data path (includes the /data/ segment)."""
        return (
            f"{self._vault_url}/v1/{self._kv_mount}/data/"
            f"sentinels/{service_id}/{role}/{env}/did_private_key"
        )

    def _metadata_path(self, service_id: str, role: str, env: str) -> str:
        return (
            f"{self._vault_url}/v1/{self._kv_mount}/metadata/"
            f"sentinels/{service_id}/{role}/{env}/did_private_key"
        )

    def _headers(self) -> dict[str, str]:
        return {"X-Vault-Token": self._token}

    # ------------------------------------------------------------------
    # KeyBackend interface
    # ------------------------------------------------------------------

    def has_key(self, service_id: str, role: str, env: str) -> bool:
        """Return ``True`` if the Vault secret exists (HEAD request to metadata)."""
        try:
            resp = self._client.head(
                self._metadata_path(service_id, role, env),
                headers=self._headers(),
            )
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    def read_key(self, service_id: str, role: str, env: str) -> KeyMaterial:
        """Read the Ed25519 private key from Vault KV v2.

        Raises:
            KeyError: If the Vault secret does not exist (404).
            RuntimeError: If the Vault request fails (non-2xx, network error).
            ValueError: If the secret data is malformed.
        """
        url = self._data_path(service_id, role, env)
        try:
            resp = self._client.get(url, headers=self._headers())
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Vault HTTP error reading key: {exc}") from exc

        if resp.status_code == 404:
            raise KeyError(
                f"Vault secret not found for {service_id}/{role}/{env} at {url}"
            )
        if resp.status_code != 200:
            raise RuntimeError(
                f"Vault returned HTTP {resp.status_code} reading key from {url}"
            )

        try:
            payload = resp.json()
            data = payload["data"]["data"]
            private_key_hex: str = data["private_key_hex"]
            key_version: int = int(data.get("key_version", 1))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                f"Malformed secret data at {url}: {exc}"
            ) from exc

        private_key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(private_key_hex)
        )
        return KeyMaterial(
            private_key=private_key,
            service_id=service_id,
            role=role,
            env=env,
            key_version=key_version,
        )

    def write_key(self, material: KeyMaterial) -> None:
        """Write the private key to Vault KV v2.

        Raises:
            RuntimeError: If the Vault write request fails.
        """
        url = self._data_path(material.service_id, material.role, material.env)
        private_bytes = material.private_key.private_bytes_raw()
        body = {
            "data": {
                "private_key_hex": private_bytes.hex(),
                "key_version": material.key_version,
            }
        }
        try:
            resp = self._client.post(url, headers=self._headers(), json=body)
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Vault HTTP error writing key: {exc}") from exc

        if resp.status_code not in (200, 204):
            raise RuntimeError(
                f"Vault returned HTTP {resp.status_code} writing key to {url}: "
                f"{resp.text}"
            )
