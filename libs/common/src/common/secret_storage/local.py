"""LocalSecretStorage — AES-256-GCM encrypted file backend.

Each secret is stored as a JSON envelope at::

    <storage_path>/<SHA-256(key)[:16].hex()>.enc

File format (JSON)::

    {
      "version": 1,
      "alg": "AES-256-GCM",
      "kdf": "scrypt",
      "kdf_params": {"n": 131072, "r": 8, "p": 1},
      "salt": "<hex 32 bytes>",
      "iv":   "<hex 12 bytes>",
      "ciphertext": "<hex>",
      "tag":  "<hex 16 bytes>"
    }

The per-secret key is derived via scrypt from the master key and the random salt stored
in the envelope — every secret uses a unique derived key so IV reuse is impossible.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from common.secret_storage.base import SecretNotFoundError, SecretStorageCorruptedError

_DEFAULT_SCRYPT_N = 131_072  # 2^17  — production minimum
_TEST_SCRYPT_N = 16_384       # 2^14  — fast; enabled only with weak_kdf=True


class LocalSecretStorage:
    """Async secret storage backed by per-key AES-256-GCM encrypted local files.

    Args:
        master_key_hex: 64 hex characters (32 bytes) used as the scrypt password.
        storage_path:   Directory where ``.enc`` files are stored (created if absent).
        weak_kdf:       Use n=2^14 scrypt for speed in unit tests (never in production).
    """

    def __init__(
        self,
        master_key_hex: str,
        storage_path: Path | str,
        *,
        weak_kdf: bool = False,
    ) -> None:
        raw = bytes.fromhex(master_key_hex)
        if len(raw) != 32:
            raise ValueError(
                "master_key_hex must encode exactly 32 bytes (64 hex chars)"
            )
        self._master_key: bytes = raw
        self._storage_path = Path(storage_path)
        self._scrypt_n = _TEST_SCRYPT_N if weak_kdf else _DEFAULT_SCRYPT_N
        self._locks: dict[Path, asyncio.Lock] = {}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def get(self, key: str) -> bytes:
        """Return the decrypted bytes stored under *key*.

        Raises:
            SecretNotFoundError: if no ``.enc`` file exists for *key*.
            SecretStorageCorruptedError: if the GCM tag check fails.
        """
        path = self._key_path(key)
        if not path.exists():
            raise SecretNotFoundError(key)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._load_and_decrypt, key, path)

    async def set(self, key: str, value: bytes) -> None:
        """Encrypt *value* and persist it under *key* (atomic write-then-rename)."""
        self._ensure_storage_dir()
        path = self._key_path(key)
        lock = self._lock_for(path)
        async with lock:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._encrypt_and_save, value, path)

    async def delete(self, key: str) -> None:
        """Remove the secret file for *key*. No-op if it does not exist."""
        path = self._key_path(key)
        lock = self._lock_for(path)
        async with lock:
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    async def exists(self, key: str) -> bool:
        """Return ``True`` if a ``.enc`` file for *key* is present."""
        return self._key_path(key).exists()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _key_path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode()).digest()
        filename = digest[:16].hex() + ".enc"
        return self._storage_path / filename

    def _lock_for(self, path: Path) -> asyncio.Lock:
        if path not in self._locks:
            self._locks[path] = asyncio.Lock()
        return self._locks[path]

    def _ensure_storage_dir(self) -> None:
        self._storage_path.mkdir(parents=True, exist_ok=True)
        self._storage_path.chmod(0o700)

    def _derive_key(self, salt: bytes, n: int) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=n, r=8, p=1)
        return kdf.derive(self._master_key)

    def _encrypt_and_save(self, plaintext: bytes, path: Path) -> None:
        salt = os.urandom(32)
        iv = os.urandom(12)
        kdf_params = {"n": self._scrypt_n, "r": 8, "p": 1}

        aad_dict = {
            "version": 1,
            "alg": "AES-256-GCM",
            "kdf": "scrypt",
            "kdf_params": kdf_params,
            "salt": salt.hex(),
            "iv": iv.hex(),
        }
        aad = json.dumps(aad_dict, separators=(",", ":"), sort_keys=True).encode()

        derived_key = self._derive_key(salt, self._scrypt_n)
        ct_with_tag = AESGCM(derived_key).encrypt(iv, plaintext, aad)
        ciphertext, tag = ct_with_tag[:-16], ct_with_tag[-16:]

        envelope = {
            **aad_dict,
            "ciphertext": ciphertext.hex(),
            "tag": tag.hex(),
        }
        data = json.dumps(envelope, indent=2).encode()

        tmp_path = path.with_suffix(".tmp")
        tmp_path.write_bytes(data)
        tmp_path.chmod(0o600)
        os.replace(tmp_path, path)  # atomic replace on both Linux and Windows

    def _load_and_decrypt(self, key: str, path: Path) -> bytes:
        try:
            envelope = json.loads(path.read_bytes())
        except (json.JSONDecodeError, OSError) as exc:
            raise SecretStorageCorruptedError(key) from exc

        try:
            salt = bytes.fromhex(envelope["salt"])
            iv = bytes.fromhex(envelope["iv"])
            ciphertext = bytes.fromhex(envelope["ciphertext"])
            tag = bytes.fromhex(envelope["tag"])
            kdf_params: dict = envelope["kdf_params"]
        except (KeyError, ValueError) as exc:
            raise SecretStorageCorruptedError(key) from exc

        # Reconstruct AAD exactly as it was at encryption time
        aad_dict = {
            "version": envelope["version"],
            "alg": envelope["alg"],
            "kdf": envelope["kdf"],
            "kdf_params": kdf_params,
            "salt": envelope["salt"],
            "iv": envelope["iv"],
        }
        aad = json.dumps(aad_dict, separators=(",", ":"), sort_keys=True).encode()

        n = kdf_params.get("n", _DEFAULT_SCRYPT_N)
        r = kdf_params.get("r", 8)
        p = kdf_params.get("p", 1)
        kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
        derived_key = kdf.derive(self._master_key)

        try:
            return AESGCM(derived_key).decrypt(iv, ciphertext + tag, aad)
        except InvalidTag as exc:
            raise SecretStorageCorruptedError(key) from exc
