"""DiscoverySettings — Pydantic v2 BaseSettings for the Discovery Service.

Environment variables (no prefix):
  DATABASE_URL        — PostgreSQL asyncpg DSN (required)
  REDIS_URL           — Redis DSN (default: redis://localhost:6379/0)
  JWT_ISSUER_KEY_ID   — Key ID used when signing JWTs
  JWT_ISSUER_DID      — Issuer DID embedded in JWTs
  ENV                 — Runtime environment: dev | test | prod (default: dev)
  ALLOWED_CORS_ORIGINS — JSON list of allowed CORS origins (default: [])
  BLOCKCHAIN_RPC_URL  — JSON-RPC endpoint (default: http://localhost:8545)
  CHAIN_ID            — EVM chain ID (default: 31337)
  SECRET_STORAGE_BACKEND — local | vault (default: local)
"""
from __future__ import annotations

import logging
from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class DiscoverySettings(BaseSettings):
    """Application configuration.  All fields load from environment variables."""

    # ------------------------------------------------------------------ #
    # Database — required; fail fast with clear message if absent         #
    # ------------------------------------------------------------------ #
    database_url: SecretStr

    # ------------------------------------------------------------------ #
    # Redis                                                               #
    # ------------------------------------------------------------------ #
    redis_url: SecretStr = SecretStr("redis://localhost:6379/0")

    # ------------------------------------------------------------------ #
    # JWT / Identity                                                      #
    # ------------------------------------------------------------------ #
    jwt_issuer_key_id: str = ""
    jwt_issuer_did: str = ""
    # Raw 32-byte Ed25519 private key seed as lowercase hex (64 chars).
    # Generate with: python scripts/generate_discovery_did.py
    # If empty, falls back to HS256 signing with local_jwt_secret (dev only).
    discovery_private_key_hex: str = ""
    # When true, credential issuance is blocked if the Discovery DID is not
    # active in the on-chain IssuerRegistry.
    verify_issuer_on_chain: bool = False

    # ------------------------------------------------------------------ #
    # App                                                                 #
    # ------------------------------------------------------------------ #
    env: Literal["dev", "test", "prod"] = "dev"

    # CORS — empty by default so all origins are blocked; must be
    # explicitly configured per environment.
    allowed_cors_origins: list[str] = []

    # ------------------------------------------------------------------ #
    # Blockchain                                                          #
    # ------------------------------------------------------------------ #
    blockchain_rpc_url: str = "http://localhost:8545"
    chain_id: int = 31337
    # Contract addresses — set from deployments/local.json after each deploy
    contract_issuer_registry: str = ""
    contract_trust_policy_registry: str = ""
    contract_status_registry: str = ""
    contract_service_registry: str = ""

    # ------------------------------------------------------------------ #
    # Authentication                                                      #
    # ------------------------------------------------------------------ #
    auth_mode: Literal["oidc", "local_jwt"] = "local_jwt"
    oidc_issuer_url: str = ""
    # Override JWKS fetch URL (useful when issuer URL is external but JWKS
    # must be fetched from an internal address, e.g. inside Docker)
    oidc_jwks_url: str = ""
    discovery_audience: str = "discovery"
    # SECURITY: local_jwt_secret MUST NOT be used in prod — enforced by validator.
    local_jwt_secret: SecretStr = SecretStr("dev-jwt-secret-change-in-production")
    auth_token_ttl_seconds: int = 900  # 15 minutes

    # ------------------------------------------------------------------ #
    # Enrollment                                                          #
    # ------------------------------------------------------------------ #
    # In prod this MUST remain False — enforced by startup validator.
    auto_approve_non_prod: bool = True

    # ------------------------------------------------------------------ #
    # Blockchain integration                                              #
    # ------------------------------------------------------------------ #
    blockchain_integration: bool = False
    # Anchor StatusList2021 entries on-chain after publication
    anchor_status_lists: bool = False
    # Fail fast at startup if chain RPC is unreachable (set True in prod)
    chain_required_at_startup: bool = False
    # Per-request RPC call timeout
    chain_rpc_timeout_seconds: int = 10
    # Register new services in ServiceRegistry on-chain after DB insert
    register_service_on_chain: bool = False

    # ------------------------------------------------------------------ #
    # Secrets backend                                                     #
    # ------------------------------------------------------------------ #
    secret_storage_backend: Literal["local", "vault"] = "local"

    # ------------------------------------------------------------------ #
    # API Hardening (TASK-035)                                            #
    # ------------------------------------------------------------------ #
    # When True, allow requests through even when Redis rate-limiter is   #
    # unavailable.  Should be False in production.                        #
    rate_limit_fail_open: bool = False
    # Maximum allowed request body size in bytes (default 2 MB).
    max_request_body_bytes: int = 2 * 1024 * 1024
    # Maximum total header size in bytes (default 16 KB).
    max_header_size_bytes: int = 16 * 1024
    # Per-endpoint rate limits: mapping of "METHOD /path" → [limit, window_s, key_type].
    # key_type: "ip" | "sub" | "token_jti"
    rate_limits: dict = {}
    # Operator token for /health/detailed endpoint (empty = endpoint blocked)
    operator_token: str = ""

    # ------------------------------------------------------------------ #
    # Observability — OpenTelemetry (TASK-036)                            #
    # ------------------------------------------------------------------ #
    # OTLP gRPC endpoint, e.g. "http://otel-collector:4317"
    otlp_endpoint: str = ""
    # Use insecure gRPC channel (no TLS) for OTLP export
    otlp_insecure: bool = True

    # ------------------------------------------------------------------ #
    # Startup validators                                                  #
    # ------------------------------------------------------------------ #
    @model_validator(mode="after")
    def _validate_config(self) -> "DiscoverySettings":
        if self.auth_mode == "oidc" and not self.oidc_issuer_url:
            raise ValueError(
                "OIDC_ISSUER_URL must be set when AUTH_MODE=oidc"
            )
        if self.auth_mode == "local_jwt" and self.env == "prod":
            raise ValueError(
                "AUTH_MODE=local_jwt is not permitted in env=prod"
            )
        if self.auto_approve_non_prod and self.env == "prod":
            raise ValueError(
                "auto_approve_non_prod must not be enabled for env=prod"
            )
        # CORS wildcard must never be used outside dev/test
        if self.env not in ("dev", "test") and "*" in self.allowed_cors_origins:
            raise ValueError(
                "Wildcard '*' in ALLOWED_CORS_ORIGINS is not permitted outside dev/test"
            )
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


@lru_cache
def get_settings() -> DiscoverySettings:
    """Return the cached DiscoverySettings singleton.

    Raises ValidationError with a clear message if required env vars are missing.
    """
    return DiscoverySettings()  # type: ignore[call-arg]
