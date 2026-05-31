"""Key rotation logic and grace window management (TASK-039)."""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from sentinel.wallet.key_manager import (
    Wallet,
    _key_path,
    _encrypt_key,
    derive_did_key,
    generate_ed25519_keypair,
    load_manifest,
    save_manifest,
    SentinelManifest,
)

logger = logging.getLogger(__name__)


class RotationManager:
    """Handles key rotation, grace window tracking, and old-key eviction."""

    def __init__(self, wallet: Wallet) -> None:
        self._wallet = wallet

    def rotate(
        self,
        passphrase: bytes,
        grace_period_seconds: int = 300,
    ) -> tuple[str, str]:
        """Generate a new keypair, derive new DID, update manifest.

        Returns:
            (old_did, new_did)
        """
        manifest = self._wallet.manifest
        store_dir = self._wallet._store_dir

        old_did = manifest.did
        old_version = manifest.key_version
        new_version = old_version + 1

        # Generate and store new key
        private_bytes, public_bytes = generate_ed25519_keypair()
        new_did = derive_did_key(public_bytes)
        new_key_path = _key_path(store_dir, new_version)
        blob = _encrypt_key(private_bytes, passphrase)
        new_key_path.write_bytes(blob)
        try:
            os.chmod(new_key_path, 0o600)
        except (OSError, NotImplementedError):
            pass

        now = time.time()
        manifest.previous_did = old_did
        manifest.did = new_did
        manifest.key_version = new_version
        manifest.rotation_started_at = now
        manifest.grace_until = now + grace_period_seconds

        save_manifest(store_dir, manifest)
        logger.info(
            "Key rotated: old_did=%s... new_did=%s... grace_until=%s",
            old_did[:20],
            new_did[:20],
            manifest.grace_until,
        )
        return old_did, new_did

    def evict_old_keys(self) -> int:
        """Remove key files for versions whose grace window has expired.

        Returns:
            Number of key files removed.
        """
        manifest = self._wallet.manifest
        store_dir = self._wallet._store_dir
        now = time.time()

        if manifest.grace_until is not None and now < manifest.grace_until:
            logger.debug("Grace window still active — not evicting old keys")
            return 0

        removed = 0
        for version in range(1, manifest.key_version):
            key_path = _key_path(store_dir, version)
            if key_path.exists():
                try:
                    key_path.unlink()
                    removed += 1
                    logger.info("Evicted old key v%d", version)
                except OSError as exc:
                    logger.warning("Could not evict key v%d: %s", version, exc)

        if removed > 0:
            manifest.previous_did = None
            manifest.grace_until = None
            manifest.rotation_started_at = None
            save_manifest(store_dir, manifest)

        return removed
