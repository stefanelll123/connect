"""Thread-safe in-memory ring buffer for live UI log streaming (TASK-051 / TASK-055).

Backed by :class:`collections.deque` with *maxlen=10 000*.
Subscribers receive events via :class:`asyncio.Queue` instances and can be
iterated for SSE streaming.
"""
from __future__ import annotations

import asyncio
import threading
from collections import deque
from typing import Any

from common.sentinel_logging.schema import SentinelLogEvent

_MAX_ENTRIES = 10_000
_MAX_SUBSCRIBERS = 10


class LogRingBuffer:
    """Capped ring buffer with optional async subscriber queues."""

    def __init__(self, maxlen: int = _MAX_ENTRIES) -> None:
        self._buf: deque[SentinelLogEvent] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._subscribers: list[asyncio.Queue[SentinelLogEvent]] = []
        self._sub_lock = threading.Lock()
        self._dropped_counts: dict[int, int] = {}  # keyed by id(queue)

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    def append(self, event: SentinelLogEvent) -> None:
        """Append *event* to the ring buffer and fan-out to all subscribers.

        Backpressure: if a subscriber queue is full the *oldest* item is
        evicted (ring-buffer semantics) so the main logger thread is never
        blocked.  The dropped count for that queue is incremented and can
        be retrieved via :meth:`get_and_reset_dropped`.
        """
        with self._lock:
            self._buf.append(event)
        # Fan-out to async subscribers — non-blocking (put_nowait)
        with self._sub_lock:
            for q in self._subscribers:
                if q.full():
                    try:
                        q.get_nowait()  # drop oldest — preserve ring semantics
                    except asyncio.QueueEmpty:
                        pass
                    q_id = id(q)
                    self._dropped_counts[q_id] = self._dropped_counts.get(q_id, 0) + 1
                q.put_nowait(event)

    # ------------------------------------------------------------------
    # Read path
    # ------------------------------------------------------------------

    def get_recent(
        self,
        n: int,
        filter_decision: str | None = None,
        filter_service_id: str | None = None,
    ) -> list[SentinelLogEvent]:
        """Return the *n* most-recent events, optionally filtered.

        Args:
            n: maximum number of events to return.
            filter_decision: if set, only return events where ``decision``
                matches (case-insensitive).
            filter_service_id: if set, only return events where ``service_id``
                matches exactly.
        """
        with self._lock:
            snapshot = list(self._buf)

        if filter_decision is not None:
            fd = filter_decision.lower()
            snapshot = [e for e in snapshot if e.decision and e.decision.lower() == fd]
        if filter_service_id is not None:
            snapshot = [e for e in snapshot if e.service_id == filter_service_id]

        return snapshot[-n:]

    # ------------------------------------------------------------------
    # Subscriber management
    # ------------------------------------------------------------------

    def subscribe(self, maxsize: int = 200) -> asyncio.Queue[SentinelLogEvent]:
        """Return a new :class:`asyncio.Queue` that receives forwarded events.

        Raises:
            RuntimeError: if the subscriber limit (10) has been reached.
        """
        with self._sub_lock:
            if len(self._subscribers) >= _MAX_SUBSCRIBERS:
                raise RuntimeError(
                    f"Maximum number of log subscribers ({_MAX_SUBSCRIBERS}) reached."
                )
            q: asyncio.Queue[SentinelLogEvent] = asyncio.Queue(maxsize=maxsize)
            self._subscribers.append(q)
            return q

    def unsubscribe(self, q: asyncio.Queue[SentinelLogEvent]) -> None:
        """Remove *q* from the subscriber list."""
        with self._sub_lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass
            self._dropped_counts.pop(id(q), None)

    def get_and_reset_dropped(self, q: asyncio.Queue[SentinelLogEvent]) -> int:
        """Return the number of events dropped for *q* since the last call and
        reset the counter to zero.  Thread-safe."""
        with self._sub_lock:
            return self._dropped_counts.pop(id(q), 0)

    def subscriber_count(self) -> int:
        with self._sub_lock:
            return len(self._subscribers)

    def __len__(self) -> int:
        with self._lock:
            return len(self._buf)
