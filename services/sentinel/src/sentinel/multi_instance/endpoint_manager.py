"""Endpoint self-registration and health-status updates for multi-instance sentinels (TASK-048).

Each sentinel instance calls ``EndpointManager.register()`` on startup to add its
endpoint URL to the service descriptor's endpoint list in Discovery.  During
graceful shutdown, ``update_status("draining")`` is called before draining, and
``update_status("offline")`` immediately before exit.

Endpoint entries are partitioned by ``instance_id`` — each instance only owns its
own entry and cannot overwrite another instance's data.
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_WEIGHT = 100


class EndpointManager:
    """Manages this instance's endpoint entry in Discovery.

    Args:
        instance_id:    Stable UUID for this sentinel instance.
        service_id:     Service identifier (matches ServiceDescriptor).
        env:            Deployment environment.
        endpoint_url:   The URL this instance is reachable at by consumers.
        discovery_url:  Base URL of the Discovery Service.
        http_client:    Async HTTP client (``httpx.AsyncClient``).
        weight:         Load-balancing weight (1–100).  Default 100.
    """

    def __init__(
        self,
        instance_id: str,
        service_id: str,
        env: str,
        endpoint_url: str,
        discovery_url: str,
        http_client,
        weight: int = _DEFAULT_WEIGHT,
    ) -> None:
        self._instance_id = instance_id
        self._service_id = service_id
        self._env = env
        self._endpoint_url = endpoint_url
        self._discovery_url = discovery_url.rstrip("/")
        self._http_client = http_client
        self._weight = weight

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def register(self, health_status: str = "active") -> bool:
        """Register (or update) this instance's endpoint in Discovery.

        Returns:
            ``True`` on success (HTTP 200 or 201), ``False`` on error.
        """
        return await self._patch(health_status)

    async def update_status(self, health_status: str) -> bool:
        """Update this instance's health_status in Discovery.

        Args:
            health_status: ``"active"``, ``"draining"``, or ``"offline"``.

        Returns:
            ``True`` on success, ``False`` on error.
        """
        return await self._patch(health_status)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _patch(self, health_status: str) -> bool:
        url = (
            f"{self._discovery_url}/api/v1/services"
            f"/{self._service_id}/descriptor/endpoints"
        )
        payload = {
            "instance_id": self._instance_id,
            "endpoint_url": self._endpoint_url,
            "weight": self._weight,
            "health_status": health_status,
            "env": self._env,
        }
        try:
            resp = await self._http_client.patch(url, json=payload)
            ok = resp.status_code in (200, 201)
            if ok:
                logger.info(
                    "event=endpoint_registered instance_id=%s status=%s http=%d",
                    self._instance_id[:8],
                    health_status,
                    resp.status_code,
                )
            else:
                logger.warning(
                    "event=endpoint_register_failed instance_id=%s http=%d body=%s",
                    self._instance_id[:8],
                    resp.status_code,
                    resp.text[:200],
                )
            return ok
        except Exception as exc:
            logger.warning(
                "event=endpoint_register_error instance_id=%s error=%s",
                self._instance_id[:8],
                exc,
            )
            return False
