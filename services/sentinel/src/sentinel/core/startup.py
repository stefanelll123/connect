"""Startup file permission validation for sentinel core (TASK-053).

Called as the FIRST step in app startup.  Any insecure permission causes an
immediate :class:`InsecureFilePermissions` exception and process exit 1.

On Windows the check is silently skipped (NTFS ACLs are not reflected in
``os.stat()`` mode bits).

Usage::

    from sentinel.core.startup import check_file_permissions
    check_file_permissions()          # uses SENTINEL_HOME env-var
"""
from __future__ import annotations

import logging
import os
import platform
import stat
from pathlib import Path

logger = logging.getLogger(__name__)

# Bits that indicate group or world read/write access
_INSECURE_BITS = stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH


class InsecureFilePermissions(RuntimeError):
    """Raised when a key file or directory has insecure permissions."""

    def __init__(self, path: Path, mode: int) -> None:
        self.path = path
        self.mode = mode
        super().__init__(
            f"Insecure permissions on '{path}': {oct(mode)}. "
            "Key files must be 0600 and the store directory must be 0700. "
            f"Run: chmod 600 '{path}'"
        )


def check_file_permissions(sentinel_home: str | None = None) -> None:
    """Validate file permissions for the sentinel key store.

    Args:
        sentinel_home: Override for ``SENTINEL_HOME``. Defaults to the env var,
            then to ``~``.

    Raises:
        InsecureFilePermissions: immediately on the first offending path.
    """
    if platform.system() == "Windows":
        logger.debug("File permission checks skipped on Windows.")
        return

    home = Path(
        sentinel_home
        or os.getenv("SENTINEL_HOME", str(Path.home()))
    )
    store_dir = home / ".sentinel" / "store"
    mtls_dir = home / ".sentinel" / "mtls"

    # Check store directory
    _check_path(store_dir, expected_mode=0o700, label="store directory")

    # Check all *.enc credential files in the store
    if store_dir.exists():
        for enc_file in store_dir.rglob("*.enc"):
            _check_path(enc_file, expected_mode=0o600, label=f"key file {enc_file.name}")

    # Check mTLS client key
    mtls_key = mtls_dir / "client.key"
    if mtls_key.exists():
        _check_path(mtls_key, expected_mode=0o600, label="mTLS client key")


def _check_path(path: Path, expected_mode: int, label: str) -> None:
    """Check *path* permissions; raise if group- or world-readable/writable."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return  # Not yet created — nothing to check

    actual = stat.S_IMODE(st.st_mode)
    if actual & _INSECURE_BITS:
        logger.critical(
            "Insecure permissions on %s '%s': got %s, expected %s. Aborting.",
            label,
            path,
            oct(actual),
            oct(expected_mode),
        )
        raise InsecureFilePermissions(path, actual)

    logger.debug("Permission OK [%s] mode=%s", label, oct(actual))


def check_ui_exposure() -> None:
    """Log a CRITICAL warning when the UI is exposed on a non-loopback interface
    without authentication enabled.

    Does NOT prevent startup — the operator may consciously override this
    (e.g., in a Docker Compose dev environment).
    """
    ui_host = os.getenv("SENTINEL_UI_HOST", "127.0.0.1")
    ui_auth = os.getenv("SENTINEL_UI_AUTH", "none").lower()

    if ui_host != "127.0.0.1" and ui_auth == "none":
        logger.critical(
            "event=ui_insecure_exposure host=%s auth=none. "
            "Set SENTINEL_UI_AUTH=token and SENTINEL_UI_TOKEN to protect the UI.",
            ui_host,
        )
        # Increment insecure_config_warnings counter if prometheus_client available
        try:
            from prometheus_client import Counter

            _counter = Counter(
                "sentinel_insecure_config_warnings_total",
                "Number of insecure configuration warnings at startup",
            )
            _counter.inc()
        except Exception:
            pass
