"""Protocol and shared types for Sentinel key storage backends.

Two concrete backends are provided:

* :class:`~common.secret_storage.local_backend.LocalKeyBackend` — AES-256-GCM
  encrypted JSON file, master key derived with scrypt.  Suitable for
  development, single-host deployments, and break-glass recovery.

* :class:`~common.secret_storage.vault_backend.VaultKeyBackend` — reads the
  Ed25519 private key from HashiCorp Vault KV v2.  Required for production
  multi-instance deployments.

The shared :class:`KeyMaterial` dataclass carries the decoded private key plus
the metadata that was stored alongside it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

__all__ = [
    "KeyMaterial",
    "KeyBackend",
]


@dataclass
class KeyMaterial:
    """Decoded private key plus associated metadata.

    Attributes:
        private_key: The Ed25519 private key object.
        service_id: The service identifier this key belongs to.
        role: ``"PRODUCER"`` or ``"CONSUMER"``.
        env: Deployment environment — ``"dev"``, ``"test"``, or ``"prod"``.
        key_version: Monotonically increasing version counter; incremented on
            each rotation.
    """

    private_key: Ed25519PrivateKey
    service_id: str
    role: str
    env: str
    key_version: int = 1


@runtime_checkable
class KeyBackend(Protocol):
    """Abstract interface for reading and writing Ed25519 private keys.

    Implementors **must** provide:

    * :meth:`read_key` — retrieve the current key material.
    * :meth:`write_key` — persist new key material (used only during initial
      setup or key rotation).
    * :meth:`has_key` — test whether a key exists without decrypting it.
    """

    def read_key(
        self,
        service_id: str,
        role: str,
        env: str,
    ) -> KeyMaterial:
        """Return the :class:`KeyMaterial` for the given (service_id, role, env).

        Args:
            service_id: Service identifier (e.g. ``"citizen-data-service"``).
            role: ``"PRODUCER"`` or ``"CONSUMER"``.
            env: ``"dev"``, ``"test"``, or ``"prod"``.

        Returns:
            Decoded :class:`KeyMaterial`.

        Raises:
            KeyError: If no key exists for the given inputs.
            ValueError: If the stored key is syntactically invalid.
        """
        ...

    def write_key(
        self,
        material: KeyMaterial,
    ) -> None:
        """Persist *material* to the underlying storage.

        Args:
            material: The key material to store.

        Raises:
            OSError: If the local file cannot be written.
            RuntimeError: If the Vault write request fails.
        """
        ...

    def has_key(
        self,
        service_id: str,
        role: str,
        env: str,
    ) -> bool:
        """Return ``True`` if a key exists for the given (service_id, role, env).

        This method MUST NOT decrypt or parse the key — it should only check
        for key existence (e.g., file present, Vault path has a secret).

        Args:
            service_id: Service identifier.
            role: ``"PRODUCER"`` or ``"CONSUMER"``.
            env: ``"dev"``, ``"test"``, or ``"prod"``.
        """
        ...
