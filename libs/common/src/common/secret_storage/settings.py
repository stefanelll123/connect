"""SecretStorageSettings — Pydantic-settings model for secret storage configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SecretStorageSettings(BaseSettings):
    """Configuration for the secret storage backend.

    Environment variables (all optional unless stated):

    * ``SENTINEL_SECRET_BACKEND`` — ``local`` (default) or ``vault``
    * ``SECRET_STORAGE_MASTER_KEY`` — required for local backend; 64 hex chars (32 bytes)
    * ``SECRET_STORAGE_PATH`` — directory for encrypted files (default ``/tmp/sentinel_secrets``)
    * ``VAULT_ADDR`` — required for vault backend; e.g. ``http://vault:8200``
    * ``VAULT_ROLE_ID`` — AppRole role ID
    * ``VAULT_SECRET_ID`` — AppRole secret ID
    * ``VAULT_KV_MOUNT`` — KV v2 mount path (default ``secret``)
    * ``TEST_WEAK_KDF`` — set to ``1`` to use n=2^14 scrypt in unit tests only
    """

    model_config = SettingsConfigDict(
        env_prefix="",
        populate_by_name=True,
        extra="ignore",
    )

    backend: Literal["local", "vault"] = Field(
        "local",
        validation_alias=AliasChoices("SENTINEL_SECRET_BACKEND", "backend"),
    )
    master_key_hex: SecretStr | None = Field(
        None,
        validation_alias=AliasChoices("SECRET_STORAGE_MASTER_KEY", "master_key_hex"),
    )
    storage_path: Path = Field(
        Path("/tmp/sentinel_secrets"),
        validation_alias=AliasChoices("SECRET_STORAGE_PATH", "storage_path"),
    )
    vault_addr: str | None = Field(
        None,
        validation_alias=AliasChoices("VAULT_ADDR", "vault_addr"),
    )
    vault_role_id: SecretStr | None = Field(
        None,
        validation_alias=AliasChoices("VAULT_ROLE_ID", "vault_role_id"),
    )
    vault_secret_id: SecretStr | None = Field(
        None,
        validation_alias=AliasChoices("VAULT_SECRET_ID", "vault_secret_id"),
    )
    vault_kv_mount: str = Field(
        "secret",
        validation_alias=AliasChoices("VAULT_KV_MOUNT", "vault_kv_mount"),
    )
    test_weak_kdf: bool = Field(
        False,
        validation_alias=AliasChoices("TEST_WEAK_KDF", "test_weak_kdf"),
    )

    @model_validator(mode="after")
    def _validate_backend_config(self) -> "SecretStorageSettings":
        if self.backend == "local":
            if self.master_key_hex is None:
                raise ValueError(
                    "SECRET_STORAGE_MASTER_KEY is required when SENTINEL_SECRET_BACKEND=local"
                )
            raw = self.master_key_hex.get_secret_value()
            try:
                bytes.fromhex(raw)
            except ValueError as exc:
                raise ValueError(
                    "SECRET_STORAGE_MASTER_KEY must be a valid hex string"
                ) from exc
            if len(raw) != 64:
                raise ValueError(
                    f"SECRET_STORAGE_MASTER_KEY must be exactly 64 hex characters (32 bytes), "
                    f"got {len(raw)}"
                )
        elif self.backend == "vault":
            if self.vault_addr is None:
                raise ValueError("VAULT_ADDR is required when SENTINEL_SECRET_BACKEND=vault")
            if self.vault_role_id is None:
                raise ValueError("VAULT_ROLE_ID is required when SENTINEL_SECRET_BACKEND=vault")
            if self.vault_secret_id is None:
                raise ValueError(
                    "VAULT_SECRET_ID is required when SENTINEL_SECRET_BACKEND=vault"
                )
        return self
