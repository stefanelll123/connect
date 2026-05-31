"""EndpointSelector — weighted round-robin with per-endpoint circuit breaker (TASK-044)."""
from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

_LOCAL_CB_FAIL_THRESHOLD = 3
_LOCAL_CB_RESET_SECONDS = 30.0


@dataclass
class _EndpointState:
    """Per-endpoint local health tracking."""
    consecutive_failures: int = 0
    unhealthy_until: float = 0.0

    def is_locally_healthy(self) -> bool:
        return time.time() >= self.unhealthy_until

    def record_failure(self) -> None:
        self.consecutive_failures += 1
        if self.consecutive_failures >= _LOCAL_CB_FAIL_THRESHOLD:
            self.unhealthy_until = time.time() + _LOCAL_CB_RESET_SECONDS
            logger.warning("Endpoint marked locally unhealthy for %ds", _LOCAL_CB_RESET_SECONDS)

    def record_success(self) -> None:
        self.consecutive_failures = 0
        self.unhealthy_until = 0.0


class NoEndpointsAvailable(Exception):
    """Raised when no healthy endpoint is found."""


class EndpointSelector:
    """Select a producer endpoint using weighted random selection.

    Endpoints with health_status 'draining' or 'unhealthy' are filtered out.
    Local circuit breaker: after 3 consecutive failures, an endpoint is
    marked unhealthy locally for 30 seconds.
    """

    def __init__(self) -> None:
        # endpoint_url → _EndpointState
        self._states: dict[str, _EndpointState] = {}

    def _state(self, url: str) -> _EndpointState:
        if url not in self._states:
            self._states[url] = _EndpointState()
        return self._states[url]

    def select(self, endpoints: list) -> str:
        """Select an endpoint URL from the descriptor endpoints list.

        Args:
            endpoints: List of dicts with keys ``url``, ``weight``, ``health_status``.

        Returns:
            Selected endpoint URL.

        Raises:
            NoEndpointsAvailable: if no eligible endpoint found.
        """
        if not endpoints:
            raise NoEndpointsAvailable("Endpoint list is empty")

        # Filter: exclude draining/unhealthy + locally circuit-broken
        eligible = [
            ep for ep in endpoints
            if ep.get("health_status", "healthy") not in ("draining", "unhealthy")
            and self._state(ep["url"]).is_locally_healthy()
        ]

        if not eligible:
            # Fallback: any non-draining endpoint
            fallback = [ep for ep in endpoints if ep.get("health_status", "healthy") != "draining"]
            if not fallback:
                raise NoEndpointsAvailable("All endpoints are draining or unavailable")
            logger.warning("All endpoints unhealthy; using any non-draining endpoint as fallback")
            return random.choice(fallback)["url"]

        # Weighted random selection
        total_weight = sum(float(ep.get("weight", 1)) for ep in eligible)
        if total_weight <= 0:
            return eligible[0]["url"]

        threshold = random.uniform(0, total_weight)
        cumulative = 0.0
        for ep in eligible:
            cumulative += float(ep.get("weight", 1))
            if cumulative >= threshold:
                return ep["url"]
        return eligible[-1]["url"]

    def record_failure(self, url: str) -> None:
        self._state(url).record_failure()

    def record_success(self, url: str) -> None:
        self._state(url).record_success()
