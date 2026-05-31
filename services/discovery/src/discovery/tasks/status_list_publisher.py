"""Status list publisher — periodic re-signing of dirty status lists (TASK-030).

Runs every 60 seconds.  For each status list with dirty=True, re-signs the
StatusListCredential JWT and clears the dirty flag.
"""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from discovery.config import DiscoverySettings
from discovery.services.status_list_service import publish_dirty

logger = logging.getLogger(__name__)


async def run_publish_sweep(session: AsyncSession, settings: DiscoverySettings) -> int:
    """Publish all dirty status lists.

    Returns:
        Number of status lists re-signed in this sweep.
    """
    count = await publish_dirty(session, settings)
    if count:
        logger.info("Status list publisher: %d list(s) re-signed and published", count)
    return count
