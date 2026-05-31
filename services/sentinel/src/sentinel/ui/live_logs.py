"""SSE live log streaming for the Sentinel UI (TASK-055).

Provides an async generator that pulls events from a :class:`LogRingBuffer`
subscriber queue and yields them as Server-Sent Events.

Backpressure strategy
---------------------
The ring buffer itself handles slow consumers: if a subscriber queue is full
the *oldest* event is evicted and the new one is enqueued (ring semantics).
The number of silently dropped events is tracked per-queue and reported to the
SSE client as an SSE comment ``': events_dropped=N'`` so the UI can display a
warning indicator.

Connection limit
----------------
A per-app counter ``active_sse_connections`` (protected by an
:class:`asyncio.Lock`) limits concurrent SSE subscriptions to 10.  The 11th
request receives HTTP 429.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import AsyncGenerator

logger = logging.getLogger(__name__)

_KEEPALIVE_TIMEOUT = 15.0  # seconds
_MAX_SSE_CONNECTIONS = 10


async def log_event_stream(
    subscriber_queue: asyncio.Queue,
    ring_buffer: object,
    filter_decision: str | None,
    filter_service_id: str | None,
) -> AsyncGenerator[str, None]:
    """Yield SSE-formatted strings from *subscriber_queue*.

    Args:
        subscriber_queue: the :class:`asyncio.Queue` returned by
            :meth:`LogRingBuffer.subscribe`.
        ring_buffer: the :class:`LogRingBuffer` instance (used to check the
            dropped-events counter).
        filter_decision: if set, skip events where ``decision`` doesn't match
            (case-insensitive).
        filter_service_id: if set, skip events where ``service_id`` doesn't
            match exactly.

    Yields:
        SSE-formatted strings (``data: {...}\\n\\n`` or ``: comment\\n\\n``).
    """
    fd = filter_decision.lower() if filter_decision else None

    try:
        while True:
            # ── Check & report dropped events ────────────────────────────────
            dropped = ring_buffer.get_and_reset_dropped(subscriber_queue)
            if dropped:
                yield f": events_dropped={dropped}\n\n"

            # ── Wait for next event (with keepalive timeout) ──────────────────
            try:
                event = await asyncio.wait_for(
                    subscriber_queue.get(), timeout=_KEEPALIVE_TIMEOUT
                )
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
                continue

            # ── Apply filters ─────────────────────────────────────────────────
            if fd is not None and (
                not event.decision or event.decision.lower() != fd
            ):
                continue
            if filter_service_id is not None and event.service_id != filter_service_id:
                continue

            # ── Serialize and yield ───────────────────────────────────────────
            try:
                json_str = event.to_json()
            except Exception as exc:
                logger.warning("Failed to serialize log event for SSE: %s", exc)
                continue

            yield f"data: {json_str}\n\n"

    except asyncio.CancelledError:
        logger.debug("SSE log stream cancelled — cleaning up")
