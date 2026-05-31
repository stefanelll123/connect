"""StatusListRefresher — background asyncio task for status list refresh (TASK-046).

Maintains a set of "active" status list IDs observed in recent check() calls
and schedules a refresh at Δ/2 ± 10% jitter.

Usage::

    refresher = StatusListRefresher(
        manager=revocation_manager,
        delta_seconds=600,  # from governance chain
    )
    task = asyncio.create_task(refresher.run())
    # ... on shutdown:
    refresher.stop()
    await task
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Dict, Optional, Set

logger = logging.getLogger(__name__)

_RETRY_BACKOFF_SECONDS = 30.0
_MIN_REFRESH_INTERVAL = 10.0   # never refresh faster than 10s regardless of Δ


class StatusListRefresher:
    """Background task that refreshes status lists before they go stale.

    Args:
        manager:        RevocationManager used to trigger re-checks.
        delta_seconds:  Governance-specified Δ (from TrustLayerClient or config).
                        The refresher runs at Δ/2 ± 10% jitter.
        trust_client:   TrustLayerClient to fetch current Δ dynamically.
    """

    def __init__(
        self,
        manager,  # RevocationManager
        delta_seconds: float = 600.0,
        trust_client=None,
    ) -> None:
        self._manager = manager
        self._delta_seconds = delta_seconds
        self._trust_client = trust_client
        self._running = False
        # status_list_id → next scheduled refresh time
        self._schedule: Dict[str, float] = {}
        # Set of active status list IDs (populated from RevocationManager.check calls)
        self._active_ids: Set[str] = set()

    def register(self, status_list_id: str) -> None:
        """Mark a status list ID as active (called from RevocationManager.check)."""
        self._active_ids.add(status_list_id)
        if status_list_id not in self._schedule:
            # Schedule an immediate first refresh
            self._schedule[status_list_id] = time.monotonic()

    def stop(self) -> None:
        """Signal the background loop to stop."""
        self._running = False

    async def run(self) -> None:
        """Main background loop.  Run as an asyncio task."""
        self._running = True
        logger.info("StatusListRefresher started (delta=%.0fs)", self._delta_seconds)

        while self._running:
            try:
                await self._tick()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("StatusListRefresher tick error: %s", exc)

            # Sleep 1 second between ticks to allow new IDs to be registered
            try:
                await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                break

        logger.info("StatusListRefresher stopped")

    async def _tick(self) -> None:
        """Process any status lists whose refresh time has passed."""
        now = time.monotonic()
        delta = await self._current_delta()

        for sl_id in list(self._active_ids):
            next_refresh = self._schedule.get(sl_id, 0.0)
            if now < next_refresh:
                continue

            logger.debug("Refreshing status list %s", sl_id)
            try:
                # "Refresh" by downloading and caching the list.
                anchor = await self._manager._get_anchor(sl_id)
                entry = await self._manager._get_entry(sl_id, anchor)
                if entry is not None:
                    # Schedule next refresh at Δ/2 ± 10% jitter
                    jitter = random.uniform(-delta * 0.1, delta * 0.1)
                    interval = max(_MIN_REFRESH_INTERVAL, delta / 2.0 + jitter)
                    self._schedule[sl_id] = now + interval
                    logger.debug(
                        "Status list %s refreshed, next in %.0fs", sl_id, interval
                    )
                else:
                    # Failed — retry sooner
                    self._schedule[sl_id] = now + _RETRY_BACKOFF_SECONDS
                    logger.warning("Status list %s refresh failed, retrying in %.0fs", sl_id, _RETRY_BACKOFF_SECONDS)

            except Exception as exc:
                logger.warning("Status list %s refresh error: %s; retrying in %.0fs", sl_id, exc, _RETRY_BACKOFF_SECONDS)
                self._schedule[sl_id] = now + _RETRY_BACKOFF_SECONDS

    async def _current_delta(self) -> float:
        """Get the current Δ from governance (or use configured default)."""
        if self._trust_client is None:
            return self._delta_seconds
        try:
            params = await self._trust_client.get_policy_params()
            delta = getattr(params, "revocation_delta_seconds", None)
            if delta is not None:
                return float(delta)
        except Exception:
            pass
        return self._delta_seconds
