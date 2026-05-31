"""File permission checks at startup (TASK-038).

Enforces that the sentinel's private store directory and its key files
have the correct UNIX permissions to prevent credential leakage.

Rules:
- Store directory must be mode 0o700  (owner rwx, no group/other access)
- Key files (*.enc, *.bin) must be mode 0o600  (owner rw-, no group/other)
- The process must NOT be running as root (UID 0)

On Windows these checks are silently skipped (os.stat() mode bits are
not meaningful on NTFS; rely on ACLs configured by the installer).

Usage::

    from sentinel.startup.permission_check import check_store_permissions
    from pathlib import Path

    check_store_permissions(Path("~/.sentinel/store"))
"""
from __future__ import annotations

import logging
import os
import platform
import stat
from pathlib import Path

logger = logging.getLogger(__name__)


class StartupPermissionError(RuntimeError):
    """Raised when the store directory has insecure permissions."""


def check_store_permissions(store_dir: Path) -> None:
    """Verify that *store_dir* and its key files have safe permissions.

    This function is a no-op on Windows.

    Raises:
        StartupPermissionError: if any permission check fails.
    """
    if platform.system() == "Windows":
        logger.debug("Permission checks are skipped on Windows.")
        return

    # ── Root process guard ──────────────────────────────────────────────
    if os.getuid() == 0:  # type: ignore[attr-defined]
        raise StartupPermissionError(
            "Sentinel process must not run as root (UID 0). "
            "Use a dedicated service account."
        )

    # ── Directory permissions ───────────────────────────────────────────
    _check_path(store_dir, expected_mode=0o700, label="store directory")

    # ── File permissions ────────────────────────────────────────────────
    for pattern in ("*.enc", "*.bin", "*.key"):
        for file_path in store_dir.rglob(pattern):
            _check_path(file_path, expected_mode=0o600, label=f"key file {file_path.name}")


def _check_path(path: Path, expected_mode: int, label: str) -> None:
    """Raise StartupPermissionError if *path* does not have *expected_mode*."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        # Path doesn't exist yet — will be created; skip check.
        return

    actual_mode = stat.S_IMODE(st.st_mode)
    if actual_mode != expected_mode:
        raise StartupPermissionError(
            f"Insecure permissions on {label} '{path}': "
            f"expected {oct(expected_mode)}, got {oct(actual_mode)}. "
            f"Run: chmod {oct(expected_mode)[2:]} '{path}'"
        )
    logger.debug("Permission OK [%s] mode=%s", label, oct(actual_mode))
