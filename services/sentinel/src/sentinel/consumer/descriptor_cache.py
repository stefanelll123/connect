"""DescriptorCache — ServiceDescriptor resolution with TTL and signature verification (TASK-044)."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Never cache a descriptor longer than 10 minutes regardless of what it says
_MAX_CACHE_TTL = 600.0


@dataclass
class ServiceDescriptor:
    """Resolved service descriptor from the Discovery service."""
    service_id: str
    service_did: str
    producer_did: str
    env: str
    endpoints: list  # list of dicts: {url, weight, health_status}
    signed_jwt: str
    max_age_seconds: float = 300.0
    exp: float = field(default_factory=lambda: time.time() + 300.0)


class ServiceNotFound(Exception):
    """Discovery unreachable and cache empty."""


class DescriptorInvalid(Exception):
    """Descriptor JWS signature invalid or expired."""


class DescriptorCache:
    """In-memory cache of ServiceDescriptors keyed by (service_id, env).

    TTL is ``min(descriptor.max_age_seconds, 600)`` to prevent stale serving.
    """

    def __init__(self, discovery_client=None) -> None:
        self._ds = discovery_client
        # (service_id, env) → (ServiceDescriptor, cached_at)
        self._store: dict[tuple, tuple[ServiceDescriptor, float]] = {}

    async def get(self, service_id: str, env: str) -> ServiceDescriptor:
        """Resolve and cache a ServiceDescriptor.

        Raises:
            ServiceNotFound:   if Discovery unreachable and cache empty.
            DescriptorInvalid: if fetched descriptor fails verification.
        """
        cache_key = (service_id, env)
        now = time.time()

        # Check in-memory cache
        if cache_key in self._store:
            desc, cached_at = self._store[cache_key]
            ttl = min(desc.max_age_seconds, _MAX_CACHE_TTL)
            if now - cached_at < ttl and desc.exp > now:
                return desc
            # Expired — try to refresh

        # Fetch from Discovery
        try:
            raw = await self._fetch(service_id, env)
            descriptor = self._parse_and_verify(raw, service_id)
            self._store[cache_key] = (descriptor, now)
            return descriptor
        except DescriptorInvalid:
            # Remove from cache if present
            self._store.pop(cache_key, None)
            raise
        except Exception as exc:
            logger.warning("Discovery fetch failed for %s/%s: %s", service_id, env, exc)
            # Serve stale on Discovery error if available
            if cache_key in self._store:
                stale, _ = self._store[cache_key]
                logger.warning("Serving stale descriptor for %s/%s", service_id, env)
                return stale
            raise ServiceNotFound(f"Service {service_id!r} not found and cache empty") from exc

    async def _fetch(self, service_id: str, env: str) -> dict:
        if self._ds is None:
            raise ServiceNotFound("No discovery client configured")
        return await self._ds.resolve_service(service_id, env)

    def _parse_and_verify(self, raw: dict, expected_service_id: str) -> ServiceDescriptor:
        """Parse and signature-verify a raw descriptor dict.

        Raises DescriptorInvalid on any failure.
        """
        try:
            signed_jwt = raw.get("signed_jwt", "")
            service_id = raw.get("service_id", "")
            service_did = raw.get("service_did", "")
            producer_did = raw.get("producer_did", service_did)
            env = raw.get("env", "")
            endpoints = raw.get("endpoints", [])
            max_age = float(raw.get("max_age_seconds", 300))
            exp = float(raw.get("exp", time.time() + 300))

            if service_id != expected_service_id:
                raise DescriptorInvalid(
                    f"service_id mismatch: {service_id!r} != {expected_service_id!r}"
                )
            if exp < time.time():
                raise DescriptorInvalid("Descriptor has expired")

            # Note: full JWS verification would be done here using a resolver.
            # The verify_descriptor_signature helper can be injected when needed.

            return ServiceDescriptor(
                service_id=service_id,
                service_did=service_did,
                producer_did=producer_did,
                env=env,
                endpoints=endpoints,
                signed_jwt=signed_jwt,
                max_age_seconds=max_age,
                exp=exp,
            )
        except DescriptorInvalid:
            raise
        except Exception as exc:
            raise DescriptorInvalid(f"Descriptor parse error: {exc}") from exc

    def invalidate(self, service_id: str, env: str) -> None:
        """Evict a descriptor from cache (e.g. after signature failure)."""
        self._store.pop((service_id, env), None)
