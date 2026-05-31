"""Chain events indexer — polls on-chain contract logs (TASK-031).

Runs as a background task polling every 30 seconds.  Parses relevant events
from all managed contracts and upserts them into the chain_events table.
Also maintains last_indexed_block in a simple state table.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.chain.client import (
    ISSUER_REGISTRY_ABI,
    SERVICE_REGISTRY_ABI,
    STATUS_REGISTRY_ABI,
    TRUST_POLICY_REGISTRY_ABI,
    ChainClient,
)
from discovery.db.models.chain_events import ChainEvent

logger = logging.getLogger(__name__)

# Events we care about from each contract
_WATCHED_EVENTS = {
    "issuer_registry": ["IssuerRegistered", "IssuerRevoked"],
    "trust_policy_registry": ["PolicyUpdated"],
    "service_registry": ["ServiceRegistered"],
    "status_registry": ["StatusAnchorPublished"],
}

_POLL_INTERVAL_SECONDS = 30
_BLOCK_CHUNK = 500  # max blocks per poll


class ChainIndexer:
    """Polls chain for new events and indexes them into the DB."""

    def __init__(self, settings: Any, chain_client: Optional[ChainClient] = None) -> None:
        self._settings = settings
        self._chain: Optional[ChainClient] = chain_client
        self._last_indexed_block: int = 0
        self._is_available: bool = False

    @property
    def is_available(self) -> bool:
        return self._is_available

    @property
    def last_indexed_block(self) -> int:
        return self._last_indexed_block

    async def load_last_block(self, session: AsyncSession) -> None:
        """Initialise _last_indexed_block from the highest block_number in chain_events.

        Avoids a full rescan from block 0 on every container restart.
        """
        result = await session.execute(
            text("SELECT COALESCE(MAX(block_number), 0) FROM chain_events")
        )
        row = result.fetchone()
        if row:
            self._last_indexed_block = int(row[0])
        logger.info("Chain indexer: resuming from block %d", self._last_indexed_block)

    async def check_availability(self) -> bool:
        """Try to reach the RPC endpoint and return availability."""
        if not self._settings.blockchain_integration:
            self._is_available = False
            return False
        if self._chain is None:
            self._is_available = False
            return False
        try:
            await self._chain.get_block_number()
            self._is_available = True
            return True
        except Exception as exc:
            logger.warning("Chain RPC unavailable: %s", exc)
            self._is_available = False
            return False

    async def poll_once(self, session: AsyncSession) -> int:
        """Poll for new events since last_indexed_block.  Returns event count."""
        if not self._settings.blockchain_integration or self._chain is None:
            return 0

        try:
            latest_block = await self._chain.get_block_number()
            if latest_block <= self._last_indexed_block:
                return 0

            to_block = min(latest_block, self._last_indexed_block + _BLOCK_CHUNK)
            events_indexed = await self._index_range(
                session,
                from_block=self._last_indexed_block + 1,
                to_block=to_block,
            )
            self._last_indexed_block = to_block
            return events_indexed
        except Exception as exc:
            logger.error("Chain indexer poll failed: %s", exc)
            return 0

    async def _index_range(
        self, session: AsyncSession, from_block: int, to_block: int
    ) -> int:
        """Fetch and store events for the given block range.  Returns count inserted."""
        s = self._settings
        contract_map = [
            ("issuer_registry", s.contract_issuer_registry, ISSUER_REGISTRY_ABI),
            ("trust_policy_registry", s.contract_trust_policy_registry, TRUST_POLICY_REGISTRY_ABI),
            ("service_registry", s.contract_service_registry, SERVICE_REGISTRY_ABI),
            ("status_registry", s.contract_status_registry, STATUS_REGISTRY_ABI),
        ]
        total = 0
        for contract_name, address, abi in contract_map:
            if not address:
                continue
            logs = await self._chain.get_logs(  # type: ignore[union-attr]
                address=address,
                abi=abi,
                from_block=from_block,
                to_block=to_block,
            )
            if logs:
                logger.info(
                    "Chain indexer: %d event(s) from %s in blocks %d-%d",
                    len(logs), contract_name, from_block, to_block,
                )
            for log in logs:
                await self._upsert_event(
                    session,
                    tx_hash=log["tx_hash"],
                    block_number=log["block_number"],
                    event_name=log["event_name"],
                    contract=contract_name,
                    args_json=log.get("args"),
                )
                total += 1
        await session.commit()
        return total

    async def _upsert_event(
        self,
        session: AsyncSession,
        *,
        tx_hash: str,
        block_number: int,
        event_name: str,
        contract: str,
        args_json: Optional[dict],
    ) -> None:
        """Idempotent upsert of a single chain event."""
        stmt = (
            pg_insert(ChainEvent)
            .values(
                tx_hash=tx_hash,
                block_number=block_number,
                event_name=event_name,
                contract=contract,
                args_json=args_json,
                indexed_at=datetime.now(timezone.utc),
            )
            .on_conflict_do_nothing(constraint="uq_chain_events_tx_event")
        )
        await session.execute(stmt)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_global_indexer: Optional[ChainIndexer] = None


def get_chain_indexer() -> Optional[ChainIndexer]:
    return _global_indexer


def set_chain_indexer(indexer: ChainIndexer) -> None:
    global _global_indexer
    _global_indexer = indexer
