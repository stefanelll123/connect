"""Anchor retry worker — retries pending on-chain status list anchors (TASK-031).

Background task that picks up status_lists with anchor_pending=true and
retries the on-chain anchor call with exponential backoff (max 5 attempts).
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.chain.client import StatusRegistryClient
from discovery.db.models.status_lists import StatusList

logger = logging.getLogger(__name__)

_MAX_ATTEMPTS = 5
_BASE_BACKOFF_SECONDS = 30


def _backoff_seconds(attempts: int) -> int:
    """Exponential backoff: 30s, 60s, 120s, 240s, 480s."""
    return _BASE_BACKOFF_SECONDS * (2 ** attempts)


async def anchor_pending_status_lists(
    session: AsyncSession,
    settings,
    status_client: Optional[StatusRegistryClient] = None,
) -> int:
    """Process pending anchors.  Returns number of successful anchors."""
    if not settings.blockchain_integration:
        logger.debug("Blockchain integration disabled — skipping anchor retry")
        return 0

    if status_client is None:
        logger.debug("StatusRegistryClient not configured — skipping anchor retry")
        return 0

    now = datetime.now(timezone.utc)

    result = await session.execute(
        select(StatusList).where(
            StatusList.anchor_pending.is_(True),
            StatusList.anchor_attempts < _MAX_ATTEMPTS,
            (StatusList.anchor_next_retry_at.is_(None))
            | (StatusList.anchor_next_retry_at <= now),
        )
    )
    pending = list(result.scalars().all())

    if not pending:
        return 0

    anchored = 0
    for sl in pending:
        try:
            # current_hash is SHA-256(raw bitstring bytes) — use it directly.
            # It is always set by status_list_service.publish() before anchor_pending=True.
            if not sl.current_hash:
                logger.debug("No hash material for status list %s, skipping", sl.status_list_id)
                continue
            raw_hash: bytes = bytes.fromhex(sl.current_hash)

            # Derive a numeric index from the status_list_id for on-chain keying
            index = abs(hash(sl.status_list_id)) % (2 ** 32)

            tx_hash = await status_client.publish_status_anchor(
                issuer_did=sl.issuer_did,
                status_list_index=index,
                credential_hash=raw_hash,
                status_list_url=sl.bitstring_url or "",
                freshness_delta_seconds=3600,
            )
            sl.anchor_pending = False
            sl.anchor_tx_hash = tx_hash
            sl.anchor_pending = False
            sl.anchor_tx_hash = tx_hash
            sl.anchor_attempts += 1
            anchored += 1
            logger.info(
                "Anchored status list %s → tx %s", sl.status_list_id, tx_hash
            )
        except Exception as exc:
            sl.anchor_attempts += 1
            if sl.anchor_attempts >= _MAX_ATTEMPTS:
                sl.anchor_pending = False
                logger.critical(
                    "Anchor permanently failed for %s after %d attempts: %s",
                    sl.status_list_id,
                    sl.anchor_attempts,
                    exc,
                )
            else:
                sl.anchor_next_retry_at = now + timedelta(
                    seconds=_backoff_seconds(sl.anchor_attempts)
                )
                logger.error(
                    "Anchor attempt %d/%d failed for %s (retry at %s): %s",
                    sl.anchor_attempts,
                    _MAX_ATTEMPTS,
                    sl.status_list_id,
                    sl.anchor_next_retry_at.isoformat(),
                    exc,
                )

    await session.commit()
    return anchored

