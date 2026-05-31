"""Service chain sync worker — retries pending on-chain service registrations (TASK-031 Step 6).

Background task that picks up services with chain_sync_pending=true and
retries ServiceRegistry.registerService() with exponential backoff (max 5 attempts).
On failure after max attempts: sets chain_sync_pending=false, logs a critical alert.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.chain.client import ServiceRegistryClient
from discovery.db.models.services import Service

logger = logging.getLogger(__name__)

_MAX_ATTEMPTS = 5
_BASE_BACKOFF_SECONDS = 30


def _backoff_seconds(attempts: int) -> int:
    """Exponential backoff: 30s, 60s, 120s, 240s, 480s."""
    return _BASE_BACKOFF_SECONDS * (2 ** attempts)


async def sync_pending_service_registrations(
    session: AsyncSession,
    settings,
    service_client: Optional[ServiceRegistryClient] = None,
) -> int:
    """Process services with pending on-chain registration.

    Returns the number of successfully registered services.
    """
    if not settings.blockchain_integration or not settings.register_service_on_chain:
        logger.error("Blockchain integration or on-chain registration disabled — skipping chain sync")
        return 0

    if service_client is None:
        logger.error("ServiceRegistryClient not configured — skipping chain sync")
        return 0

    now = datetime.now(timezone.utc)

    result = await session.execute(
        select(Service).where(
            and_(
                Service.chain_sync_pending.is_(True),
                Service.chain_sync_attempts < _MAX_ATTEMPTS,
                or_(
                    Service.chain_next_retry_at.is_(None),
                    Service.chain_next_retry_at <= now,
                ),
            )
        )
    )
    pending = list(result.scalars().all())

    if not pending:
        return 0

    synced = 0
    for svc in pending:
        if not svc.base_url:
            # No URL yet — skip silently (contract requires non-empty URL)
            logger.info(
                "Skipping chain sync for service '%s': base_url not set",
                svc.service_id,
            )
            continue
        try:
            tx_hash = await service_client.register_service(
                service_id=svc.service_id,
                did=svc.owner_did or "",
                base_url=svc.base_url,
                role="producer",
                description=svc.description or "",
            )
            svc.chain_sync_pending = False
            svc.chain_tx_hash = tx_hash
            svc.updated_at = now
            synced += 1
            logger.info(
                "Service '%s' registered on-chain (tx=%s, after %d attempt(s))",
                svc.service_id,
                tx_hash,
                svc.chain_sync_attempts + 1,
            )
        except Exception as exc:
            svc.chain_sync_attempts = (svc.chain_sync_attempts or 0) + 1
            if svc.chain_sync_attempts >= _MAX_ATTEMPTS:
                # Give up — operator must intervene
                svc.chain_sync_pending = False
                logger.critical(
                    "On-chain registration PERMANENTLY FAILED for service '%s' "
                    "after %d attempts: %s. Manual operator action required.",
                    svc.service_id,
                    svc.chain_sync_attempts,
                    exc,
                )
            else:
                backoff = _backoff_seconds(svc.chain_sync_attempts)
                svc.chain_next_retry_at = now + timedelta(seconds=backoff)
                logger.warning(
                    "On-chain registration failed for service '%s' (attempt %d/%d, "
                    "next retry in %ds): %s",
                    svc.service_id,
                    svc.chain_sync_attempts,
                    _MAX_ATTEMPTS,
                    backoff,
                    exc,
                )

    await session.commit()
    return synced
