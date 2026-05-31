"""StatusCache — unencrypted status list cache with hash validation (TASK-038).

Layout::

    <cache_root>/
        {status_list_id}.bin         ← raw bytes of the status list
        {status_list_id}_meta.json   ← {"expires_at": ..., "current_hash": ...}

The hash is SHA-256 of the .bin file content to detect corruption.
A cache entry is considered stale if ``expires_at < now``.

Usage::

    cache = StatusCache(Path("~/.sentinel/store/status_cache"))
    cache.put("list-001", data_bytes, expires_at=time.time() + 3600)
    data = cache.get("list-001")        # → bytes or None
    cache.is_stale("list-001")          # → bool
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _safe_id(status_list_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", status_list_id)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class StatusCache:
    """File-based cache for status lists with expiry and hash validation."""

    def __init__(self, cache_dir: Path) -> None:
        self._dir = cache_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    # ── Public API ──────────────────────────────────────────────────────

    def put(self, status_list_id: str, data: bytes, expires_at: float) -> None:
        """Store *data* as the cached status list for *status_list_id*."""
        safe = _safe_id(status_list_id)
        bin_path = self._dir / f"{safe}.bin"
        meta_path = self._dir / f"{safe}_meta.json"

        bin_path.write_bytes(data)
        meta = {
            "status_list_id": status_list_id,
            "expires_at": expires_at,
            "current_hash": _sha256(data),
            "cached_at": time.time(),
        }
        meta_path.write_text(json.dumps(meta), encoding="utf-8")
        logger.debug("StatusCache: stored %s (expires_at=%.0f)", status_list_id, expires_at)

    def get(self, status_list_id: str) -> Optional[bytes]:
        """Return the cached bytes for *status_list_id*, or None if absent/corrupt."""
        safe = _safe_id(status_list_id)
        bin_path = self._dir / f"{safe}.bin"
        meta_path = self._dir / f"{safe}_meta.json"

        if not bin_path.exists() or not meta_path.exists():
            return None

        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            data = bin_path.read_bytes()
            if _sha256(data) != meta.get("current_hash", ""):
                logger.warning(
                    "StatusCache: hash mismatch for %s — discarding", status_list_id
                )
                self._evict(safe)
                return None
            return data
        except Exception as exc:
            logger.warning("StatusCache: read error for %s: %s", status_list_id, exc)
            return None

    def is_stale(self, status_list_id: str, now: Optional[float] = None) -> bool:
        """Returns True if the cache entry is missing or past its expiry."""
        safe = _safe_id(status_list_id)
        meta_path = self._dir / f"{safe}_meta.json"

        if not meta_path.exists():
            return True

        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            expires_at = float(meta.get("expires_at", 0))
            return (now or time.time()) >= expires_at
        except Exception:
            return True

    def evict(self, status_list_id: str) -> None:
        """Remove the cached entry for *status_list_id*."""
        self._evict(_safe_id(status_list_id))

    # ── Internals ───────────────────────────────────────────────────────

    def _evict(self, safe: str) -> None:
        for suffix in (".bin", "_meta.json"):
            path = self._dir / f"{safe}{suffix}"
            if path.exists():
                try:
                    path.unlink()
                except Exception as exc:
                    logger.warning("StatusCache: evict failed for %s%s: %s", safe, suffix, exc)
