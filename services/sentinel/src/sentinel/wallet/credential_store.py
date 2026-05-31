"""CredentialStore — AES-256-GCM encrypted credential persistence (TASK-038).

Layout::

    <store_root>/
        {cred_type}_{jti[:8]}.enc    ← 16-byte nonce | 16-byte tag | ciphertext

The encryption key is derived from the sentinel's master key (SecretBytes)
using HKDF-SHA256 with the credential type as info context.

Usage::

    store = CredentialStore(Path("~/.sentinel/store/credentials"))
    store.store(jwt_string, master_key=secret_bytes)
    creds = store.get_active("StatusList2021", master_key=secret_bytes)
    store.invalidate(jti)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_NONCE_SIZE = 16
_TAG_SIZE = 16


def _derive_key(master_key: bytes, info: bytes) -> bytes:
    """Derive a 32-byte AES key from the master key using HKDF-SHA256."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(master_key)


def _encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with AES-256-GCM.  Returns nonce(16) + tag(16) + ciphertext."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    # cryptography lib appends 16-byte GCM tag at the end
    return nonce + ciphertext_with_tag


def _decrypt(blob: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM blob produced by ``_encrypt``."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = blob[:_NONCE_SIZE]
    ciphertext_with_tag = blob[_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)


def _decode_jwt_payload(jwt_string: str) -> dict:
    import base64

    parts = jwt_string.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


class CredentialStore:
    """Encrypted file-based credential store."""

    def __init__(self, store_dir: Path) -> None:
        self._dir = store_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    # ── Public API ──────────────────────────────────────────────────────

    def store(self, jwt_string: str, master_key) -> None:
        """Encrypt and persist a JWT credential.

        Args:
            jwt_string: A compact JWT string.
            master_key: A ``SecretBytes`` instance or raw ``bytes`` master key.
        """
        raw_key = _resolve_key(master_key)
        payload = _decode_jwt_payload(jwt_string)
        jti = payload.get("jti") or payload.get("sub", "unknown")
        cred_type = payload.get("type", "credential")
        if isinstance(cred_type, list):
            cred_type = cred_type[-1]  # use the most specific type

        key = _derive_key(raw_key, cred_type.encode())
        ciphertext = _encrypt(jwt_string.encode(), key)

        jti_hash = hashlib.sha256(jti.encode()).hexdigest()[:16]
        filename = f"{_safe_name(cred_type)}_{jti_hash}.enc"
        out_path = self._dir / filename
        out_path.write_bytes(ciphertext)
        _set_file_permissions(out_path)
        logger.debug("Stored credential jti=%s type=%s", jti, cred_type)

    def get_active(
        self,
        cred_type: str,
        master_key,
        *,
        now: Optional[float] = None,
    ) -> list[str]:
        """Return all non-expired credentials of *cred_type* (decrypted JWTs).

        Silently skips files that cannot be decrypted or have expired.
        """
        raw_key = _resolve_key(master_key)
        key = _derive_key(raw_key, cred_type.encode())
        now = now or time.time()
        results = []

        for enc_file in self._dir.glob(f"{_safe_name(cred_type)}_*.enc"):
            try:
                blob = enc_file.read_bytes()
                jwt_bytes = _decrypt(blob, key)
                jwt_string = jwt_bytes.decode()
                payload = _decode_jwt_payload(jwt_string)
                exp = payload.get("exp")
                if exp is not None and exp < now:
                    logger.debug("Skipping expired credential in %s", enc_file.name)
                    continue
                results.append(jwt_string)
            except Exception as exc:
                logger.warning("Could not load credential %s: %s", enc_file.name, exc)

        return results

    def list_all(self, master_key) -> list[dict]:
        """Return decoded payloads for all stored credentials.

        Iterates every ``*.enc`` file in the store directory, derives the
        decryption key from the credential type embedded in the filename,
        decrypts, and decodes the JWT payload.  Files that cannot be
        decrypted are skipped with a warning.
        """
        raw_key = _resolve_key(master_key)
        results: list[dict] = []
        for enc_file in sorted(self._dir.glob("*.enc")):
            # Filename pattern: {cred_type}_{jti_hash[:16]}.enc
            stem = enc_file.stem  # e.g. "sentinelidentitycredential_abc123"
            parts = stem.rsplit("_", 1)
            cred_type_slug = parts[0] if len(parts) == 2 else stem
            try:
                key = _derive_key(raw_key, cred_type_slug.encode())
                blob = enc_file.read_bytes()
                jwt_bytes = _decrypt(blob, key)
                payload = _decode_jwt_payload(jwt_bytes.decode())
                results.append({"payload": payload})
            except Exception as exc:
                logger.warning("Could not load credential %s: %s", enc_file.name, exc)
        return results

    def get_all_raw(self, master_key) -> list[str]:
        """Return all non-expired credentials as raw decrypted JWT strings.

        Infers the credential type from the filename (same as ``list_all``),
        derives the per-type AES key, decrypts and returns the JWT string.
        Skips expired or unreadable files silently.
        """
        raw_key = _resolve_key(master_key)
        now = time.time()
        results: list[str] = []
        for enc_file in sorted(self._dir.glob("*.enc")):
            stem = enc_file.stem
            parts = stem.rsplit("_", 1)
            cred_type_slug = parts[0] if len(parts) == 2 else stem
            try:
                key = _derive_key(raw_key, cred_type_slug.encode())
                blob = enc_file.read_bytes()
                jwt_string = _decrypt(blob, key).decode()
                payload = _decode_jwt_payload(jwt_string)
                exp = payload.get("exp")
                if exp is not None and float(exp) < now:
                    logger.debug("Skipping expired credential in %s", enc_file.name)
                    continue
                results.append(jwt_string)
            except Exception as exc:
                logger.warning("Could not load credential %s: %s", enc_file.name, exc)
        return results

    def get_all_raw_with_type(self, master_key) -> list[tuple[str, str]]:
        """Return all non-expired credentials as (cred_type_slug, jwt_string) pairs.

        Same as ``get_all_raw`` but also exposes the credential type slug
        inferred from the filename, so callers don't need to re-parse it.
        Skips expired or unreadable files silently.
        """
        raw_key = _resolve_key(master_key)
        now = time.time()
        results: list[tuple[str, str]] = []
        for enc_file in sorted(self._dir.glob("*.enc")):
            stem = enc_file.stem
            parts = stem.rsplit("_", 1)
            cred_type_slug = parts[0] if len(parts) == 2 else stem
            try:
                key = _derive_key(raw_key, cred_type_slug.encode())
                blob = enc_file.read_bytes()
                jwt_string = _decrypt(blob, key).decode()
                payload = _decode_jwt_payload(jwt_string)
                exp = payload.get("exp")
                if exp is not None and float(exp) < now:
                    logger.debug("Skipping expired credential in %s", enc_file.name)
                    continue
                results.append((cred_type_slug, jwt_string))
            except Exception as exc:
                logger.warning("Could not load credential %s: %s", enc_file.name, exc)
        return results

    def invalidate(self, jti: str) -> None:
        jti_hash = hashlib.sha256(jti.encode()).hexdigest()[:16]
        for enc_file in self._dir.glob(f"*_{jti_hash}.enc"):
            try:
                enc_file.unlink()
                logger.info("Invalidated credential jti=%s (%s)", jti, enc_file.name)
            except Exception as exc:
                logger.warning("Failed to delete %s: %s", enc_file, exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_name(cred_type: str) -> str:
    """Normalise type string to be safe for use as a filename prefix."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", cred_type).lower()


def _set_file_permissions(path: Path) -> None:
    """Set 0o600 permissions on the file (no-op on Windows)."""
    try:
        os.chmod(path, 0o600)
    except (NotImplementedError, AttributeError, OSError):
        pass


def _resolve_key(master_key) -> bytes:
    """Accept SecretBytes or plain bytes and return raw bytes."""
    if hasattr(master_key, "reveal"):
        return master_key.reveal()
    if isinstance(master_key, (bytes, bytearray)):
        return bytes(master_key)
    raise TypeError(f"Expected SecretBytes or bytes, got {type(master_key)}")
