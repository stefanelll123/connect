"""Local AES-256-GCM encrypted key file backend.

Key file format (JSON):

.. code-block:: json

    {
        "version": 1,
        "service_id": "citizen-data-service",
        "role": "PRODUCER",
        "env": "dev",
        "key_version": 1,
        "salt": "<32 hex chars — 16 random bytes>",
        "nonce": "<24 hex chars — 12 random bytes>",
        "ciphertext": "<base64url — AES-256-GCM ciphertext + 16-byte tag>"
    }

Master key derivation::

    master_key = scrypt(password, salt=bytes.fromhex(salt),
                        n=32768, r=8, p=1, dklen=32)

Encrypted plaintext::

    plaintext = JSON({"private_key_hex": "<hex>"})

GCM additional authenticated data (AAD)::

    aad = (service_id + ":" + role + ":" + env).encode()

The AAD binds the ciphertext to the specific (service_id, role, env) tuple
so that a key file cannot be used for a different identity.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from common.secret_storage.backend import KeyMaterial

__all__ = ["LocalKeyBackend"]

# scrypt parameters (OWASP / NIST-recommended minimum for interactive logins)
_SCRYPT_N = 32_768
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32  # 256 bits — AES-256 key


def _derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from *password* using scrypt."""
    kdf = Scrypt(salt=salt, length=_SCRYPT_DKLEN, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(password)


def _aad(service_id: str, role: str, env: str) -> bytes:
    """Additional authenticated data that binds the ciphertext to an identity."""
    return f"{service_id}:{role}:{env}".encode()


class LocalKeyBackend:
    """AES-256-GCM encrypted key file backend.

    Key files are stored at::

        {data_dir}/keys/{service_id}-{role}-{env}.key.enc

    The master key is derived from *password* (typically the value of the
    ``SENTINEL_SECRET_KEY`` environment variable) using scrypt.

    Args:
        data_dir: Directory that contains (or will contain) the ``keys/``
            subdirectory.
        password: The passphrase or secret key used for scrypt derivation.
            Accepts either a ``str`` (UTF-8 encoded) or raw ``bytes``.
    """

    def __init__(self, data_dir: str | Path, password: str | bytes) -> None:
        self._data_dir = Path(data_dir)
        self._password: bytes = (
            password.encode() if isinstance(password, str) else password
        )

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _key_path(self, service_id: str, role: str, env: str) -> Path:
        return self._data_dir / "keys" / f"{service_id}-{role}-{env}.key.enc"

    # ------------------------------------------------------------------
    # KeyBackend interface
    # ------------------------------------------------------------------

    def has_key(self, service_id: str, role: str, env: str) -> bool:
        """Return ``True`` if the encrypted key file exists on disk."""
        return self._key_path(service_id, role, env).exists()

    def read_key(self, service_id: str, role: str, env: str) -> KeyMaterial:
        """Decrypt and return the key material for *(service_id, role, env)*.

        Raises:
            KeyError: If the key file does not exist.
            ValueError: If the file is corrupt, the identity metadata
                mismatches, or the GCM authentication tag is invalid.
        """
        path = self._key_path(service_id, role, env)
        if not path.exists():
            raise KeyError(
                f"No key file found for {service_id}/{role}/{env} at {path}"
            )

        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Key file {path} is not valid JSON: {exc}") from exc

        # Validate stored identity matches requested identity
        stored_sid = envelope.get("service_id", "")
        stored_role = envelope.get("role", "")
        stored_env = envelope.get("env", "")
        if (stored_sid, stored_role, stored_env) != (service_id, role, env):
            raise ValueError(
                f"Key file identity mismatch: stored ({stored_sid}/{stored_role}/{stored_env}) "
                f"!= requested ({service_id}/{role}/{env})"
            )

        salt = bytes.fromhex(envelope["salt"])
        nonce = bytes.fromhex(envelope["nonce"])
        # Re-add padding stripped during write
        ct_b64 = envelope["ciphertext"]
        padding = 4 - len(ct_b64) % 4
        if padding != 4:
            ct_b64 += "=" * padding
        ciphertext_with_tag = base64.urlsafe_b64decode(ct_b64)

        master_key = _derive_key(self._password, salt)
        aesgcm = AESGCM(master_key)
        aad = _aad(service_id, role, env)

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        except Exception as exc:
            raise ValueError(
                f"Failed to decrypt key file {path}: authentication tag mismatch "
                f"or corrupt data — {exc}"
            ) from exc

        inner = json.loads(plaintext.decode())
        private_key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(inner["private_key_hex"])
        )
        return KeyMaterial(
            private_key=private_key,
            service_id=service_id,
            role=role,
            env=env,
            key_version=envelope.get("key_version", 1),
        )

    def write_key(self, material: KeyMaterial) -> None:
        """Encrypt and persist *material* to a new key file.

        Creates parent directories if they do not exist.

        Raises:
            OSError: If the file cannot be written.
        """
        path = self._key_path(material.service_id, material.role, material.env)
        path.parent.mkdir(parents=True, exist_ok=True)

        salt = os.urandom(16)
        nonce = os.urandom(12)
        master_key = _derive_key(self._password, salt)
        aesgcm = AESGCM(master_key)
        aad = _aad(material.service_id, material.role, material.env)

        private_bytes = material.private_key.private_bytes_raw()
        plaintext = json.dumps({"private_key_hex": private_bytes.hex()}).encode()
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)

        envelope = {
            "version": 1,
            "service_id": material.service_id,
            "role": material.role,
            "env": material.env,
            "key_version": material.key_version,
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "ciphertext": base64.urlsafe_b64encode(ciphertext_with_tag)
            .rstrip(b"=")
            .decode(),
        }
        path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
