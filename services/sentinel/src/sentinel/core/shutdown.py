"""Graceful shutdown handler for the Sentinel Node (TASK-048).

On SIGTERM:
  1. Immediately PATCH Discovery: endpoint health_status → "draining".
  2. Set ``is_shutting_down`` flag — new inbound/outbound requests return 503.
  3. Wait for in-flight requests to drain (up to ``DRAIN_TIMEOUT_SECONDS``).
  4. PATCH Discovery: endpoint health_status → "offline".
  5. Cleanly close shared HTTP client.
  6. Exit(0) — Kubernetes ``terminationGracePeriodSeconds=35`` ensures SIGKILL
     is sent after our 30s drain window plus 5s buffer.

Usage::

    shutdown = GracefulShutdown(
        instance_id=instance_id,
        service_id=settings.service_id,
        env=settings.env,
        discovery_url=settings.discovery_url,
        http_client=http_client,
        in_flight_counter=in_flight_counter,  # threading.Semaphore or asyncio Event
    )
    shutdown.register()  # installs SIGTERM + SIGINT handlers
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from typing import Optional

logger = logging.getLogger(__name__)

_DRAIN_TIMEOUT_SECONDS = int(os.environ.get("DRAIN_TIMEOUT_SECONDS", "30"))
_PATCH_TIMEOUT_SECONDS = 5.0


class GracefulShutdown:
    """Coordinates graceful shutdown across the sentinel instance.

    Thread-safe flag: ``is_shutting_down`` is checked by the inbound/outbound
    middleware to return 503 immediately without touching the backend.
    """

    def __init__(
        self,
        instance_id: str,
        service_id: str,
        env: str,
        discovery_url: str,
        http_client=None,          # httpx.AsyncClient
        drain_timeout: int = _DRAIN_TIMEOUT_SECONDS,
    ) -> None:
        self._instance_id = instance_id
        self._service_id = service_id
        self._env = env
        self._discovery_url = discovery_url.rstrip("/")
        self._http_client = http_client
        self._drain_timeout = drain_timeout
        self._shutting_down = False
        self._in_flight: int = 0
        self._in_flight_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_shutting_down(self) -> bool:
        """True once SIGTERM has been received and draining has started."""
        return self._shutting_down

    def register(self) -> None:
        """Install SIGTERM and SIGINT signal handlers."""
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGTERM, self._on_signal)
        loop.add_signal_handler(signal.SIGINT, self._on_signal)
        logger.info(
            "event=graceful_shutdown_registered instance_id=%s", self._instance_id[:8]
        )

    async def increment_in_flight(self) -> None:
        """Called at the start of each inbound/outbound request."""
        async with self._in_flight_lock:
            self._in_flight += 1

    async def decrement_in_flight(self) -> None:
        """Called when a request completes (or raises)."""
        async with self._in_flight_lock:
            self._in_flight = max(0, self._in_flight - 1)

    # ------------------------------------------------------------------
    # Internal shutdown sequence
    # ------------------------------------------------------------------

    def _on_signal(self) -> None:
        loop = asyncio.get_event_loop()
        loop.create_task(self._shutdown_sequence())

    async def _shutdown_sequence(self) -> None:
        logger.info(
            "event=shutdown_initiated instance_id=%s service_id=%s",
            self._instance_id[:8],
            self._service_id,
        )
        self._shutting_down = True

        # Step 1: Mark instance as draining in Discovery
        await self._patch_health_status("draining")

        # Step 2: Drain in-flight requests
        await self._drain_in_flight()

        # Step 3: Mark instance as offline
        await self._patch_health_status("offline")

        # Step 4: Close shared HTTP client
        if self._http_client is not None:
            try:
                await self._http_client.aclose()
            except Exception as exc:
                logger.warning("event=http_client_close_error error=%s", exc)

        logger.info("event=shutdown_complete instance_id=%s", self._instance_id[:8])
        # Allow the event loop to exit naturally; Uvicorn will call sys.exit(0).

    async def _patch_health_status(self, health_status: str) -> None:
        if self._http_client is None:
            return
        url = (
            f"{self._discovery_url}/api/v1/services"
            f"/{self._service_id}/descriptor/endpoints"
        )
        payload = {
            "instance_id": self._instance_id,
            "health_status": health_status,
            "env": self._env,
        }
        try:
            resp = await self._http_client.patch(
                url, json=payload, timeout=_PATCH_TIMEOUT_SECONDS
            )
            logger.info(
                "event=endpoint_status_patched status=%s health=%s http_status=%d",
                health_status,
                health_status,
                resp.status_code,
            )
        except Exception as exc:
            logger.warning(
                "event=endpoint_patch_failed health=%s error=%s",
                health_status,
                exc,
            )

    async def _drain_in_flight(self) -> None:
        deadline = time.monotonic() + self._drain_timeout
        while True:
            async with self._in_flight_lock:
                count = self._in_flight
            if count == 0:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                logger.warning(
                    "event=drain_timeout in_flight=%d instance_id=%s",
                    count,
                    self._instance_id[:8],
                )
                break
            logger.debug(
                "event=draining in_flight=%d remaining_secs=%.1f",
                count,
                remaining,
            )
            await asyncio.sleep(0.5)

        logger.info(
            "event=drain_complete instance_id=%s", self._instance_id[:8]
        )
