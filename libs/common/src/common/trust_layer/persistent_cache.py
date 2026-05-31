"""Persistent encrypted cache for TrustLayerClient (TASK-042).

Serializes the MemoryCache to an AES-256-GCM encrypted .enc file
using the same scheme as sentinel/wallet/credential_store.py.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_NONCE_SIZE = 16


def _derive_cache_key(master_key: bytes) -> bytes:
    """Derive AES-256-GCM key for the trust cache from the master key."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"trust_layer_cache",
    ).derive(master_key)


def _encrypt(plaintext: bytes, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(_NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def _decrypt(blob: bytes, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = blob[:_NONCE_SIZE]
    return AESGCM(key).decrypt(nonce, blob[_NONCE_SIZE:], None)


class PersistentCache:
    """Encrypted JSON-serialised persistent cache backed by a single .enc file.

    The serialised format stores the MemoryCache's namespace dicts as nested
    JSON. Dataclass values must be serialisable (they are converted to dicts
    before storage).
    """

    def __init__(self, cache_path: Path, master_key: Optional[bytes] = None) -> None:
        self._path = cache_path
        self._master_key = master_key

    def flush(self, memory_cache, serialiser) -> None:
        """Encrypt and write memory_cache contents to disk.

        Args:
            memory_cache: MemoryCache instance with ``to_dict()`` method.
            serialiser:   Callable that converts dataclass values to JSON-safe dicts.
        """
        if self._master_key is None:
            return  # no encryption key — skip persistence
        try:
            raw = memory_cache.to_dict()
            serialised = {}
            for ns, entries in raw.items():
                serialised[ns] = {k: (serialiser(v), ts) for k, (v, ts) in entries.items()}
            plaintext = json.dumps(serialised).encode()
            key = _derive_cache_key(self._master_key)
            blob = _encrypt(plaintext, key)
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_bytes(blob)
            try:
                os.chmod(self._path, 0o600)
            except (OSError, NotImplementedError):
                pass
        except Exception as exc:
            logger.warning("PersistentCache flush failed: %s", exc)

    def load(self, deserialiser) -> Optional[dict]:
        """Read and decrypt persistent cache.  Returns raw dict or None on failure.

        Args:
            deserialiser: Callable(ns, key, value_dict, ts) → (value, ts) to reconstruct
                          dataclass instances.
        """
        if self._master_key is None or not self._path.exists():
            return None
        try:
            blob = self._path.read_bytes()
            key = _derive_cache_key(self._master_key)
            plaintext = _decrypt(blob, key)
            raw = json.loads(plaintext)
            result = {}
            for ns, entries in raw.items():
                result[ns] = {}
                for k, (v_dict, ts) in entries.items():
                    result[ns][k] = (deserialiser(ns, k, v_dict, ts), ts)
            return result
        except Exception as exc:
            logger.warning("PersistentCache load failed (starting fresh): %s", exc)
            return None
