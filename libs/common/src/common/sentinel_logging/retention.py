"""Log file retention: delete log files older than max_days from the log directory.

Runs as an asyncio background task, waking every 24 h.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_SECONDS_PER_DAY = 86_400


def cleanup_old_log_files(log_dir: Path, max_days: int) -> int:
    """Delete ``*.log*`` files in *log_dir* older than *max_days*.

    Returns the number of files deleted.
    """
    if not log_dir.exists():
        return 0

    cutoff = time.time() - max_days * _SECONDS_PER_DAY
    deleted = 0
    for f in log_dir.iterdir():
        if not f.is_file():
            continue
        if f.suffix not in (".log",) and ".log." not in f.name:
            continue
        try:
            mtime = os.path.getmtime(f)
            if mtime < cutoff:
                f.unlink()
                deleted += 1
                logger.info("Deleted old log file %s (mtime=%s)", f.name, mtime)
        except OSError as exc:
            logger.warning("Could not remove log file %s: %s", f, exc)

    return deleted


async def run_retention_task(log_dir: Path, max_days: int) -> None:
    """Background task: run :func:`cleanup_old_log_files` every 24 hours."""
    while True:
        try:
            removed = cleanup_old_log_files(log_dir, max_days)
            if removed:
                logger.info("Log retention cleanup: removed %d file(s)", removed)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Log retention cleanup error: %s", exc)
        await asyncio.sleep(_SECONDS_PER_DAY)
