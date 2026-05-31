"""Secret storage backends: Vault KV and local AES-GCM encrypted key files."""

# TASK-008 key-material backends (synchronous, Ed25519-specific)
from common.secret_storage.backend import KeyBackend, KeyMaterial
from common.secret_storage.local_backend import LocalKeyBackend
from common.secret_storage.vault_backend import VaultKeyBackend

# TASK-011 generic async secret storage (all secret types)
from common.secret_storage.base import (
    SecretAccessDeniedError,
    SecretNotFoundError,
    SecretStorage,
    SecretStorageCorruptedError,
    SecretStorageUnavailableError,
)
from common.secret_storage.factory import select_backend
from common.secret_storage.local import LocalSecretStorage
from common.secret_storage.settings import SecretStorageSettings
from common.secret_storage.vault import VaultSecretStorage

__all__ = [
    # TASK-008 (sync, Ed25519-specific)
    "KeyBackend",
    "KeyMaterial",
    "LocalKeyBackend",
    "VaultKeyBackend",
    # TASK-011 (async, generic)
    "SecretStorage",
    "SecretNotFoundError",
    "SecretAccessDeniedError",
    "SecretStorageUnavailableError",
    "SecretStorageCorruptedError",
    "LocalSecretStorage",
    "VaultSecretStorage",
    "SecretStorageSettings",
    "select_backend",
]
