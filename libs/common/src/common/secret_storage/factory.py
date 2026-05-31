"""Factory function for selecting the appropriate SecretStorage backend."""

from __future__ import annotations

from common.secret_storage.base import SecretStorage
from common.secret_storage.local import LocalSecretStorage
from common.secret_storage.settings import SecretStorageSettings
from common.secret_storage.vault import VaultSecretStorage


def select_backend(settings: SecretStorageSettings) -> SecretStorage:
    """Return a :class:`~common.secret_storage.base.SecretStorage` instance
    configured according to *settings*.

    Call :meth:`~common.secret_storage.vault.VaultSecretStorage.start` on the
    returned instance if you need the background token-renewal loop for Vault.

    Raises:
        ValueError: if *settings.backend* is not ``"local"`` or ``"vault"``.
    """
    if settings.backend == "local":
        assert settings.master_key_hex is not None  # guaranteed by settings validator
        return LocalSecretStorage(
            master_key_hex=settings.master_key_hex.get_secret_value(),
            storage_path=settings.storage_path,
            weak_kdf=settings.test_weak_kdf,
        )
    if settings.backend == "vault":
        assert settings.vault_addr is not None  # guaranteed by settings validator
        assert settings.vault_role_id is not None
        assert settings.vault_secret_id is not None
        return VaultSecretStorage(
            vault_addr=str(settings.vault_addr),
            role_id=settings.vault_role_id.get_secret_value(),
            secret_id=settings.vault_secret_id.get_secret_value(),
            kv_mount=settings.vault_kv_mount,
        )
    raise ValueError(f"Unknown secret storage backend: {settings.backend!r}")
