"""Per-instance UUID generation and persistence (TASK-048).

The ``instance_id`` is a stable UUID that identifies this sentinel process
across restarts.  It is persisted to disk so that audit logs and Discovery
endpoint registrations stay consistent when a pod restarts in Kubernetes.

If the file is missing (first boot, migration, or ephemeral storage) a new
UUID is generated and persisted.  The file is written atomically using a
temporary file + rename to avoid partial writes.
"""
from __future__ import annotations

import logging
import os
import tempfile
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)

# Default location; overridden by SENTINEL_INSTANCE_ID_FILE env var.
_DEFAULT_FILENAME = "instance_id"


def get_or_create_instance_id(sentinel_home: str | None = None) -> str:
    """Return the persistent instance UUID for this sentinel process.

    On the first call the UUID is created and written to
    ``{sentinel_home}/.sentinel/instance_id``.  On subsequent calls the
    stored value is returned unchanged.

    Args:
        sentinel_home: Path to the sentinel home directory.  Defaults to
                       ``$SENTINEL_HOME`` or ``~/.sentinel``.

    Returns:
        A stable UUID4 string (e.g. ``"3f2504e0-4f89-11d3-9a0c-0305e82c3301"``).
    """
    path = _resolve_id_path(sentinel_home)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.is_file():
        stored = path.read_text().strip()
        if _is_valid_uuid(stored):
            logger.debug("event=instance_id_loaded path=%s id=%s", path, stored[:8])
            return stored
        logger.warning(
            "event=instance_id_corrupt path=%s value=%r — regenerating",
            path,
            stored[:40],
        )

    new_id = str(uuid.uuid4())
    _atomic_write(path, new_id)
    logger.info("event=instance_id_created path=%s id=%s", path, new_id[:8])
    return new_id


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_id_path(sentinel_home: str | None) -> Path:
    env_override = os.environ.get("SENTINEL_INSTANCE_ID_FILE")
    if env_override:
        return Path(env_override)

    if sentinel_home is None:
        sentinel_home = os.environ.get(
            "SENTINEL_HOME", os.path.join(os.path.expanduser("~"), ".sentinel")
        )

    return Path(sentinel_home) / _DEFAULT_FILENAME


def _is_valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def _atomic_write(path: Path, content: str) -> None:
    """Write *content* to *path* atomically (temp-file + rename)."""
    dir_ = path.parent
    fd, tmp_path = tempfile.mkstemp(dir=dir_, prefix=".instance_id_")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
