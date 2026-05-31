"""Chain router — chain health and event browsing (TASK-031)."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from discovery.auth.rbac import require_roles
from discovery.db.models.chain_events import ChainEvent
from discovery.dependencies import get_db, get_settings
from discovery.services.chain_indexer import get_chain_indexer
from discovery.services.chain_policy_cache import get_chain_policy_cache

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/chain", tags=["Chain"])


@router.get("/status")
async def chain_status(
    session: AsyncSession = Depends(get_db),
    settings=Depends(get_settings),
    current_user=Depends(require_roles("viewer", "operator", "security-admin")),
):
    """Return chain connectivity and indexer lag information."""
    indexer = get_chain_indexer()
    cache = get_chain_policy_cache()

    is_available = indexer.is_available if indexer else False
    last_indexed_block = indexer.last_indexed_block if indexer else 0

    cache_age = cache.cache_age_seconds if cache else None
    is_stale = cache.is_stale if cache else True

    return {
        "network": "localnet" if settings.chain_id == 31337 else "sepolia",
        "chain_id": settings.chain_id,
        "rpc_url": "***",  # masked for security
        "is_available": is_available,
        "indexer_last_block": last_indexed_block,
        "blockchain_integration_enabled": settings.blockchain_integration,
        "policy_cache": {
            "is_stale": is_stale,
            "cache_age_seconds": cache_age,
        },
    }


@router.get("/events")
async def chain_events(
    contract: Optional[str] = Query(None, description="Filter by contract name"),
    event_name: Optional[str] = Query(None, description="Filter by event name"),
    from_block: Optional[int] = Query(None, description="Minimum block number"),
    since: Optional[str] = Query(None, description="ISO-8601 timestamp filter"),
    limit: int = Query(50, le=100, description="Max results (cap 100)"),
    session: AsyncSession = Depends(get_db),
    current_user=Depends(require_roles("viewer", "operator", "security-admin")),
):
    """Return paginated, indexed chain events."""
    query = select(ChainEvent).order_by(ChainEvent.block_number.desc())

    if contract:
        query = query.where(ChainEvent.contract == contract)
    if event_name:
        query = query.where(ChainEvent.event_name == event_name)
    if from_block is not None:
        query = query.where(ChainEvent.block_number >= from_block)
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            query = query.where(ChainEvent.indexed_at >= since_dt)
        except ValueError:
            pass

    query = query.limit(limit)
    result = await session.execute(query)
    events = list(result.scalars().all())

    return {
        "items": [
            {
                "id": str(e.id),
                "tx_hash": e.tx_hash,
                "block_number": e.block_number,
                "event_name": e.event_name,
                "contract": e.contract,
                "args": e.args_json,
                "indexed_at": e.indexed_at.isoformat() if e.indexed_at else None,
            }
            for e in events
        ],
        "count": len(events),
    }

