"""SecretStorage async protocol and its exception hierarchy.

Key naming convention: ``sentinels/{service_id}/{role}/{env}/{secret_name}``
Examples:
  - ``sentinels/svc1/producer/dev/did_private_key``
  - ``sentinels/svc1/consumer/prod/signing_key``
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SecretNotFoundError(Exception):
    """Raised when the requested key does not exist in storage."""

    def __init__(self, key: str) -> None:
        super().__init__(f"Secret not found: {key!r}")
        self.key = key


class SecretAccessDeniedError(Exception):
    """Raised when the caller lacks permission (e.g. Vault 403, file mode 0700)."""

    def __init__(self, key: str) -> None:
        super().__init__(f"Secret access denied: {key!r}")
        self.key = key


class SecretStorageUnavailableError(Exception):
    """Raised when the storage backend is unreachable (network error, Vault down, etc.)."""


class SecretStorageCorruptedError(Exception):
    """Raised when decryption fails or the integrity tag check does not pass.

    .. warning::
        This should be logged as a SECURITY_ALERT — it indicates possible tampering.
    """

    def __init__(self, key: str) -> None:
        super().__init__(f"Integrity check failed for secret: {key!r}")
        self.key = key


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class SecretStorage(Protocol):
    """Async key-value store for opaque secret bytes.

    Both :class:`~common.secret_storage.local.LocalSecretStorage` and
    :class:`~common.secret_storage.vault.VaultSecretStorage` implement this interface.
    """

    async def get(self, key: str) -> bytes:
        """Return the stored bytes for *key*.

        Raises:
            SecretNotFoundError: if the key does not exist.
            SecretStorageCorruptedError: if the integrity check fails.
            SecretStorageUnavailableError: if the backend is unreachable.
        """
        ...

    async def set(self, key: str, value: bytes) -> None:
        """Store *value* under *key*, overwriting any existing entry.

        Raises:
            SecretStorageUnavailableError: if the backend is unreachable.
        """
        ...

    async def delete(self, key: str) -> None:
        """Delete the secret at *key*. No-op if the key does not exist.

        Raises:
            SecretStorageUnavailableError: if the backend is unreachable.
        """
        ...

    async def exists(self, key: str) -> bool:
        """Return ``True`` if *key* is present in storage.

        Raises:
            SecretStorageUnavailableError: if the backend is unreachable.
        """
        ...
