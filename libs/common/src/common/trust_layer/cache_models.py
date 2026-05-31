"""Cache data models for TrustLayerClient (TASK-042)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class IssuerRecord:
    did: str
    is_active: bool
    schemas: tuple  # frozenset-like storage (hashable)
    cached_at: float

    def has_schema(self, schema_id: str) -> bool:
        return schema_id in self.schemas


@dataclass(frozen=True)
class PolicyParams:
    max_clock_skew_seconds: int
    revocation_delta_seconds: int
    require_vpq: bool
    cached_at: float


@dataclass(frozen=True)
class StatusAnchor:
    status_list_id: str
    root_hash: str
    updated_at: float
    cached_at: float


@dataclass(frozen=True)
class ServiceBinding:
    service_id: str
    producer_did: str
    env: str
    endpoint: str
    cached_at: float
