"""DiscoverySyncLoop — background asyncio task for sync orchestration (TASK-040)."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable, Optional

from sentinel.clients.ds_client import DiscoveryClient

logger = logging.getLogger(__name__)


class DiscoverySyncLoop:
    """Background task that runs config/credential/heartbeat/descriptor syncs.

    Each sync type runs on its own interval independently; a failure in one
    does NOT block others.
    """

    def __init__(
        self,
        client: DiscoveryClient,
        instance_id: str,
        version: str,
        heartbeat_interval: float = 30.0,
        config_sync_interval: float = 60.0,
        credential_sync_interval: float = 120.0,
        descriptor_refresh_interval: float = 240.0,
        service_descriptor_jws: str = "",
        descriptor_builder: Optional[Callable[[], str]] = None,
        credential_store=None,
        master_key: Optional[bytes] = None,
    ) -> None:
        self._client = client
        self._instance_id = instance_id
        self._version = version
        self._heartbeat_interval = heartbeat_interval
        self._config_sync_interval = config_sync_interval
        self._credential_sync_interval = credential_sync_interval
        self._descriptor_refresh_interval = descriptor_refresh_interval
        self._service_descriptor_jws = service_descriptor_jws
        self._descriptor_builder = descriptor_builder
        self._credential_store = credential_store
        self._master_key = master_key

        self._last_heartbeat: float = 0.0
        self._last_config_sync: float = 0.0
        self._last_credential_sync: float = 0.0
        self._last_descriptor_publish: float = 0.0

        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    async def start(self) -> None:
        """Start the background sync loop."""
        self._stop_event.clear()
        self._task = asyncio.create_task(self._run(), name="ds_sync_loop")
        logger.info("DiscoverySyncLoop started")

    async def stop(self) -> None:
        """Stop the background sync loop gracefully."""
        self._stop_event.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
        logger.info("DiscoverySyncLoop stopped")

    async def _run(self) -> None:
        while not self._stop_event.is_set():
            now = time.monotonic()
            tasks = []

            if now - self._last_heartbeat >= self._heartbeat_interval:
                self._last_heartbeat = now
                tasks.append(self._do_heartbeat())

            if now - self._last_config_sync >= self._config_sync_interval:
                self._last_config_sync = now
                tasks.append(self._do_config_sync())

            if now - self._last_credential_sync >= self._credential_sync_interval:
                self._last_credential_sync = now
                tasks.append(self._do_credential_sync())

            if (
                (self._descriptor_builder or self._service_descriptor_jws)
                and now - self._last_descriptor_publish >= self._descriptor_refresh_interval
            ):
                self._last_descriptor_publish = now
                tasks.append(self._do_descriptor_publish())

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

            try:
                await asyncio.wait_for(
                    asyncio.shield(self._stop_event.wait()),
                    timeout=1.0,
                )
            except asyncio.TimeoutError:
                pass

    async def _do_heartbeat(self) -> None:
        try:
            await self._client.send_heartbeat(
                self._instance_id, self._version, {"status": "ok"}
            )
        except Exception as exc:
            logger.warning("Heartbeat task error: %s", exc)

    async def _do_config_sync(self) -> None:
        try:
            await self._client.sync_config()
        except Exception as exc:
            logger.warning("Config sync task error: %s", exc)

    async def _do_credential_sync(self) -> None:
        try:
            await self._client.sync_credentials(
                credential_store=self._credential_store,
                master_key=self._master_key,
            )
        except Exception as exc:
            logger.warning("Credential sync task error: %s", exc)

    async def _do_descriptor_publish(self) -> None:
        try:
            if self._descriptor_builder:
                jws = self._descriptor_builder()
            else:
                jws = self._service_descriptor_jws
            if jws:
                await self._client.publish_descriptor(jws)
        except Exception as exc:
            logger.warning("Descriptor publish task error: %s", exc)
