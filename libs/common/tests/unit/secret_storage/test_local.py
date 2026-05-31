"""Unit tests for LocalSecretStorage."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
from pathlib import Path

import pytest

from common.secret_storage.base import SecretNotFoundError, SecretStorageCorruptedError
from common.secret_storage.local import LocalSecretStorage


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def master_key() -> str:
    return secrets.token_hex(32)  # 64 hex chars = 32 bytes


@pytest.fixture
def storage(tmp_path: Path, master_key: str) -> LocalSecretStorage:
    """LocalSecretStorage using fast scrypt (n=2^14) and a temp directory."""
    return LocalSecretStorage(
        master_key_hex=master_key,
        storage_path=tmp_path / "secrets",
        weak_kdf=True,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLocalSecretStorageRoundTrip:
    async def test_set_get_returns_identical_bytes(
        self, storage: LocalSecretStorage
    ) -> None:
        value = b"super-secret-private-key-material-32bytes"
        await storage.set("sentinels/svc1/producer/dev/did_private_key", value)
        result = await storage.get("sentinels/svc1/producer/dev/did_private_key")
        assert result == value

    async def test_overwrite_returns_new_value(
        self, storage: LocalSecretStorage
    ) -> None:
        key = "sentinels/svc/role/env/overwrite"
        await storage.set(key, b"old-value")
        await storage.set(key, b"new-value")
        assert await storage.get(key) == b"new-value"

    async def test_multiple_distinct_keys(self, storage: LocalSecretStorage) -> None:
        await storage.set("key/a", b"alpha")
        await storage.set("key/b", b"beta")
        assert await storage.get("key/a") == b"alpha"
        assert await storage.get("key/b") == b"beta"


class TestLocalSecretStorageExistence:
    async def test_exists_true_after_set(self, storage: LocalSecretStorage) -> None:
        key = "sentinels/svc/role/env/key"
        await storage.set(key, b"value")
        assert await storage.exists(key) is True

    async def test_exists_false_missing_key(self, storage: LocalSecretStorage) -> None:
        assert await storage.exists("sentinels/never/registered") is False

    async def test_exists_false_after_delete(
        self, storage: LocalSecretStorage
    ) -> None:
        key = "sentinels/svc/role/env/deleted"
        await storage.set(key, b"data")
        await storage.delete(key)
        assert await storage.exists(key) is False


class TestLocalSecretStorageErrors:
    async def test_get_missing_raises_not_found(
        self, storage: LocalSecretStorage
    ) -> None:
        with pytest.raises(SecretNotFoundError) as exc_info:
            await storage.get("sentinels/nonexistent/key")
        assert "sentinels/nonexistent/key" in str(exc_info.value)

    async def test_delete_nonexistent_is_noop(
        self, storage: LocalSecretStorage
    ) -> None:
        await storage.delete("sentinels/never/existed")  # must not raise

    async def test_tampered_ciphertext_raises_corrupted(
        self, storage: LocalSecretStorage, tmp_path: Path
    ) -> None:
        key = "sentinels/svc/role/env/tampered_ct"
        await storage.set(key, b"sensitive-payload")

        enc_files = list((tmp_path / "secrets").glob("*.enc"))
        assert len(enc_files) == 1

        envelope = json.loads(enc_files[0].read_text())
        ct = bytes.fromhex(envelope["ciphertext"])
        # Flip the first byte to invalidate the GCM tag
        envelope["ciphertext"] = (bytes([ct[0] ^ 0xFF]) + ct[1:]).hex()
        enc_files[0].write_text(json.dumps(envelope))

        with pytest.raises(SecretStorageCorruptedError):
            await storage.get(key)

    async def test_tampered_tag_raises_corrupted(
        self, storage: LocalSecretStorage, tmp_path: Path
    ) -> None:
        key = "sentinels/svc/role/env/tampered_tag"
        await storage.set(key, b"sensitive-payload")

        enc_files = list((tmp_path / "secrets").glob("*.enc"))
        assert len(enc_files) == 1

        envelope = json.loads(enc_files[0].read_text())
        tag = bytes.fromhex(envelope["tag"])
        envelope["tag"] = (bytes([tag[0] ^ 0xFF]) + tag[1:]).hex()
        enc_files[0].write_text(json.dumps(envelope))

        with pytest.raises(SecretStorageCorruptedError):
            await storage.get(key)

    async def test_truncated_json_raises_corrupted(
        self, storage: LocalSecretStorage, tmp_path: Path
    ) -> None:
        key = "sentinels/svc/role/env/truncated"
        await storage.set(key, b"data")

        enc_files = list((tmp_path / "secrets").glob("*.enc"))
        assert len(enc_files) == 1
        enc_files[0].write_bytes(b"{not valid json")

        with pytest.raises(SecretStorageCorruptedError):
            await storage.get(key)


class TestLocalSecretStoragePermissions:
    async def test_storage_dir_has_0700_permissions(
        self, storage: LocalSecretStorage, tmp_path: Path
    ) -> None:
        await storage.set("sentinels/svc/role/env/perm_key", b"value")
        storage_dir = tmp_path / "secrets"
        if os.name != "nt":  # chmod is a no-op on Windows
            mode = oct(storage_dir.stat().st_mode)[-3:]
            assert mode == "700"


class TestLocalSecretStorageConcurrency:
    async def test_concurrent_writes_to_same_key(
        self, storage: LocalSecretStorage
    ) -> None:
        key = "sentinels/svc/role/env/concurrent"
        tasks = [storage.set(key, f"value-{i}".encode()) for i in range(8)]
        await asyncio.gather(*tasks)
        # After all writes, the key must be readable and contain one of the written values
        result = await storage.get(key)
        assert result.startswith(b"value-")

    async def test_concurrent_set_different_keys(
        self, storage: LocalSecretStorage
    ) -> None:
        tasks = [
            storage.set(f"sentinels/svc/role/env/key-{i}", f"val-{i}".encode())
            for i in range(8)
        ]
        await asyncio.gather(*tasks)
        for i in range(8):
            assert await storage.get(f"sentinels/svc/role/env/key-{i}") == f"val-{i}".encode()


class TestLocalSecretStorageInit:
    def test_invalid_master_key_length_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            LocalSecretStorage(
                master_key_hex="deadbeef",  # too short
                storage_path=tmp_path,
            )

    def test_valid_init(self, tmp_path: Path, master_key: str) -> None:
        s = LocalSecretStorage(master_key_hex=master_key, storage_path=tmp_path)
        assert s is not None
