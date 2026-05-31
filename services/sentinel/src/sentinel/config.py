"""SentinelSettings — Pydantic v2 BaseSettings for the Sentinel Node.

Environment variables (no prefix):
  SENTINEL_ROLE        — "producer" or "consumer" (required)
  SENTINEL_ID          — UUID identifying this sentinel node (required in prod)
  SENTINEL_DID         — DID of this sentinel (generated on first run if absent)
  ENV                  — dev | test | prod (default: dev)
  SERVICE_ID           — Service identifier registered in the Discovery Service
  DISCOVERY_URL        — Base URL of the Discovery Service (required)
  BACKEND_URL          — Upstream backend URL (producer mode only)
  CHAIN_RPC_URL        — EVM JSON-RPC endpoint
  SENTINEL_HOME        — Directory for local key/credential storage
"""
from __future__ import annotations

import os
import uuid
from typing import Literal, Optional

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SentinelSettings(BaseSettings):
    """Configuration for a sentinel node."""

    # ------------------------------------------------------------------ #
    # Identity                                                            #
    # ------------------------------------------------------------------ #
    sentinel_role: Literal["producer", "consumer"]
    sentinel_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sentinel_did: str = ""

    # ------------------------------------------------------------------ #
    # App                                                                 #
    # ------------------------------------------------------------------ #
    env: Literal["dev", "test", "prod"] = "dev"
    service_id: str = ""

    # ------------------------------------------------------------------ #
    # Discovery Service                                                   #
    # ------------------------------------------------------------------ #
    discovery_url: str = "http://localhost:8000"

    # ------------------------------------------------------------------ #
    # Producer: upstream backend                                         #
    # ------------------------------------------------------------------ #
    backend_url: str = ""
    # The URL consumers use to reach this producer sentinel's inbound proxy.
    # Required for producer role if descriptor publishing is desired.
    inbound_url: str = ""

    # ------------------------------------------------------------------ #
    # Chain                                                               #
    # ------------------------------------------------------------------ #
    chain_rpc_url: str = "http://localhost:8545"
    contract_addresses: dict = Field(default_factory=dict)
    fail_closed_on_chain_error: bool = True

    # ------------------------------------------------------------------ #
    # Secret storage                                                      #
    # ------------------------------------------------------------------ #
    secret_storage_backend: Literal["local", "vault"] = "local"
    vault_addr: str = ""
    vault_token: SecretStr = SecretStr("")
    vault_outage_policy: Literal["fail_closed", "read_only"] = "fail_closed"

    # ------------------------------------------------------------------ #
    # Storage paths                                                       #
    # ------------------------------------------------------------------ #
    sentinel_home: str = Field(
        default_factory=lambda: os.path.join(
            os.path.expanduser("~"), ".sentinel"
        )
    )

    # ------------------------------------------------------------------ #
    # Behaviour                                                           #
    # ------------------------------------------------------------------ #
    # Max seconds to wait for an inbound/outbound request to complete
    request_timeout_seconds: int = 30
    # How many retries on transient HTTPX errors (exponential backoff)
    max_retries: int = 3
    # VP/credential freshness delta — credentials older than this are rejected
    delta_seconds: int = 300

    # ------------------------------------------------------------------ #
    # Revocation                                                          #
    # ------------------------------------------------------------------ #
    # Policy applied when the status list anchor is stale beyond delta.
    # fail_closed  → reject all requests (503) until the list is fresh
    # degrade      → serve from cache but mark the result as stale
    # use_cache    → serve from cache silently (warning logged only)
    revocation_outage_policy: Literal["fail_closed", "degrade", "use_cache"] = "fail_closed"
    # Maximum age (seconds) of a status list anchor before it is considered stale.
    # The governance chain value (TrustPolicyRegistry) overrides this at runtime.
    status_list_delta_seconds: int = 600
    # When True, every inbound VC also triggers an on-chain emergency-revoke lookup.
    # Adds ~50-100ms latency per request; only enable for high-value operations.
    require_emergency_check: bool = False

    # ------------------------------------------------------------------ #
    # Session exchange (SD-JWT / KB-JWT fast-path)                       #
    # ------------------------------------------------------------------ #
    # Lifetime of producer-issued session JWTs (seconds).  Max 3600.
    session_token_ttl: int = Field(default=900, ge=60, le=3600)
    # Lifetime of single-use nonces issued by GET /auth/nonce (seconds).
    session_nonce_ttl: int = Field(default=60, ge=10, le=300)
    # Max session-exchange requests allowed per consumer DID per minute.
    session_rate_limit_per_minute: int = Field(default=30, ge=1)
    # Redis URL used for nonce store and replay cache (optional — in-memory fallback used if absent).
    redis_url: str = ""

    # ------------------------------------------------------------------ #
    # Observability                                                       #
    # ------------------------------------------------------------------ #
    otlp_endpoint: str = ""
    otlp_insecure: bool = True

    # ------------------------------------------------------------------ #
    # CORS                                                                #
    # ------------------------------------------------------------------ #
    allowed_cors_origins: list[str] = []

    # ------------------------------------------------------------------ #
    # Validators                                                          #
    # ------------------------------------------------------------------ #
    @model_validator(mode="after")
    def _validate(self) -> "SentinelSettings":
        if self.sentinel_role == "producer" and not self.backend_url:
            raise ValueError(
                "BACKEND_URL is required when SENTINEL_ROLE=producer"
            )
        if self.env == "prod":
            if not self.sentinel_did:
                raise ValueError(
                    "SENTINEL_DID must be set in env=prod"
                )
            if not self.discovery_url.startswith("https://"):
                raise ValueError(
                    "DISCOVERY_URL must use HTTPS in env=prod"
                )
            if self.chain_rpc_url and not self.chain_rpc_url.startswith("https://"):
                raise ValueError(
                    "CHAIN_RPC_URL must use HTTPS in env=prod"
                )
            if self.session_token_ttl > 900:
                raise ValueError(
                    "SESSION_TOKEN_TTL must be <= 900 seconds in env=prod"
                )
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


_settings_cache: Optional[SentinelSettings] = None


def get_settings() -> SentinelSettings:
    global _settings_cache
    if _settings_cache is None:
        _settings_cache = SentinelSettings()  # type: ignore[call-arg]
    return _settings_cache
