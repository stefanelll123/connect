"""Config bundle Pydantic schemas (TASK-027)."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Bundle payload sub-objects
# ---------------------------------------------------------------------------

class BundleDiscoveryConfig(BaseModel):
    sync_url: str
    credentials_url: str
    heartbeat_url: str
    status_list_base_url: str


class BundleChainConfig(BaseModel):
    network: str
    chain_id: int
    rpc_urls: list[str]
    contract_addresses: dict[str, str]


class BundlePolicyDefaults(BaseModel):
    max_token_age_seconds: int = 300
    allow_unknown_issuers: bool = False
    fail_closed_on_chain_error: bool = True


class BundleRevocationConfig(BaseModel):
    delta_seconds: int = 300
    cache_ttl_seconds: int = 60
    mode: str = "strict"


class BundleObservabilityConfig(BaseModel):
    otlp_endpoint: str = ""
    log_level: str = "info"
    trace_sampling_rate: float = 0.1


# ---------------------------------------------------------------------------
# Full bundle payload (what gets signed)
# ---------------------------------------------------------------------------

class ConfigBundlePayload(BaseModel):
    bundle_version: int
    issued_at: str  # ISO-8601
    sentinel_did: str
    sentinel_id: str
    role: str
    env: str
    service_id: str
    discovery: BundleDiscoveryConfig
    chain: BundleChainConfig
    policy_defaults: BundlePolicyDefaults
    revocation: BundleRevocationConfig
    observability: BundleObservabilityConfig
    issued_by: str
    signature_kid: str


# ---------------------------------------------------------------------------
# API response schemas
# ---------------------------------------------------------------------------

class ConfigBundleResponse(BaseModel):
    signed_bundle_jws: str
    bundle_hash: str
    version: int
    issued_at: datetime

    model_config = {"from_attributes": True}


class ConfigBundleHistoryItem(BaseModel):
    version: int
    bundle_hash: str
    issued_at: Optional[datetime]
    is_current: bool

    model_config = {"from_attributes": True}


class ConfigBundleHistoryResponse(BaseModel):
    items: list[ConfigBundleHistoryItem]


class RollbackResponse(BaseModel):
    new_version: int
    rolled_back_to_content_version: int
    bundle_hash: str
    issued_at: datetime
