"""TrustCacheRefresher — background proactive cache refresh (TASK-042)."""
from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Callable, Coroutine, Optional

logger = logging.getLogger(__name__)

# How early to refresh before TTL expiry (fraction of TTL)
_REFRESH_AT = 0.80
# Maximum jitter as a fraction of TTL
_JITTER_FRACTION = 0.10


@dataclass(order=True)
class _RefreshTask:
    """Scheduled refresh task, ordered by next_run time."""
    next_run: float
    # Exclude non-comparable fields from ordering
    key: str = field(compare=False)
    ns: str = field(compare=False)
    ttl: float = field(compare=False)
    fetcher: Callable[[], Coroutine] = field(compare=False)
    type_label: str = field(compare=False)


class TrustCacheRefresher:
    """Background refresh task that proactively re-fetches cache entries.

    Schedules entries for refresh at (TTL * 0.80) with ±10% jitter to
    avoid thundering herd.

    Args:
        trust_client:  The TrustLayerClient whose cache entries to refresh.
        max_workers:   Concurrency limit for simultaneous refreshes.
    """

    def __init__(self, trust_client, max_workers: int = 4) -> None:
        self._client = trust_client
        self._max_workers = max_workers
        self._queue: asyncio.PriorityQueue = None  # type: ignore[assignment]
        self._task: Optional[asyncio.Task] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._semaphore: Optional[asyncio.Semaphore] = None

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the background refresh loop."""
        self._queue = asyncio.PriorityQueue()
        self._stop_event = asyncio.Event()
        self._semaphore = asyncio.Semaphore(self._max_workers)
        self._task = asyncio.create_task(self._loop(), name="trust_cache_refresher")
        logger.info("TrustCacheRefresher started")

    async def stop(self) -> None:
        """Stop the refresh loop gracefully."""
        if self._stop_event:
            self._stop_event.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
                logger.warning("TrustCacheRefresher did not stop cleanly within 5s")
        logger.info("TrustCacheRefresher stopped")

    # ── Scheduling ───────────────────────────────────────────────────────

    def schedule(
        self,
        ns: str,
        key: str,
        ttl: float,
        fetcher: Callable[[], Coroutine],
        type_label: str,
        *,
        delay: Optional[float] = None,
    ) -> None:
        """Enqueue a refresh task.

        Args:
            ns:          Cache namespace (e.g. 'issuer').
            key:         Cache key.
            ttl:         Entry TTL in seconds.
            fetcher:     Async callable that fetches fresh data.
            type_label:  Human-readable label for logging.
            delay:       Override delay before first refresh (default: TTL*0.80+jitter).
        """
        if self._queue is None:
            logger.warning("schedule() called before start(); ignoring")
            return
        if delay is None:
            delay = self._next_delay(ttl)
        task = _RefreshTask(
            next_run=time.monotonic() + delay,
            key=key,
            ns=ns,
            ttl=ttl,
            fetcher=fetcher,
            type_label=type_label,
        )
        self._queue.put_nowait(task)

    # ── Internal loop ────────────────────────────────────────────────────

    async def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                await self._drain_ready()
                # Poll every 0.5s so we can notice stop_event
                try:
                    await asyncio.wait_for(
                        asyncio.shield(self._stop_event.wait()),
                        timeout=0.5,
                    )
                except asyncio.TimeoutError:
                    pass
            except Exception:
                logger.exception("Unexpected error in TrustCacheRefresher loop")

    async def _drain_ready(self) -> None:
        """Execute all tasks whose next_run <= now."""
        now = time.monotonic()
        pending: list[_RefreshTask] = []
        # Drain queue and collect tasks that are not yet due
        while not self._queue.empty():
            task: _RefreshTask = self._queue.get_nowait()
            if task.next_run <= now:
                asyncio.create_task(self._execute(task))
            else:
                pending.append(task)
        # Re-enqueue tasks that are not yet due
        for task in pending:
            self._queue.put_nowait(task)

    async def _execute(self, task: _RefreshTask) -> None:
        async with self._semaphore:
            try:
                result = await task.fetcher()
                if result is not None:
                    await self._client._mem.put(task.ns, task.key, result)
                    logger.debug(
                        "Proactively refreshed %s/%s", task.ns, task.key
                    )
            except Exception as exc:
                logger.warning(
                    "Proactive refresh failed for %s/%s: %s",
                    task.ns, task.key, exc,
                )
            finally:
                # Re-schedule for the next cycle
                self.schedule(
                    task.ns,
                    task.key,
                    task.ttl,
                    task.fetcher,
                    task.type_label,
                )

    def _next_delay(self, ttl: float) -> float:
        """Compute next refresh delay: 80% of TTL ± 10% jitter."""
        base = ttl * _REFRESH_AT
        jitter = ttl * _JITTER_FRACTION * (random.random() * 2 - 1)
        return max(0.0, base + jitter)
