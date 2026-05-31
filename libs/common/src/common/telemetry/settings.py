"""TelemetrySettings — Pydantic-settings model for observability configuration."""

from __future__ import annotations

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class TelemetrySettings(BaseSettings):
    """Configuration for the shared telemetry layer.

    Environment variables:

    * ``SERVICE_NAME``           — service identifier (e.g. ``discovery``)
    * ``SERVICE_VERSION``        — semantic version string (default ``"0.0.0"``)
    * ``OTEL_EXPORTER_OTLP_ENDPOINT`` — base URL of the OTel Collector (default ``http://localhost:4318``)
    * ``OTEL_ENABLED``           — disable all OTel export (default ``true``)
    * ``LOG_LEVEL``              — Python log level name (default ``"INFO"``)
    * ``PROMETHEUS_ENABLED``     — expose /metrics via prometheus_client (default ``true``)
    * ``DEPLOYMENT_ENVIRONMENT`` — e.g. ``dev`` | ``staging`` | ``prod`` (default ``"dev"``)
    """

    model_config = SettingsConfigDict(
        env_prefix="",
        populate_by_name=True,
        extra="ignore",
    )

    service_name: str = Field(
        "unknown-service",
        validation_alias=AliasChoices("SERVICE_NAME", "service_name"),
    )
    service_version: str = Field(
        "0.0.0",
        validation_alias=AliasChoices("SERVICE_VERSION", "service_version"),
    )
    otel_endpoint: str = Field(
        "http://localhost:4318",
        validation_alias=AliasChoices("OTEL_EXPORTER_OTLP_ENDPOINT", "otel_endpoint"),
    )
    otel_enabled: bool = Field(
        True,
        validation_alias=AliasChoices("OTEL_ENABLED", "otel_enabled"),
    )
    log_level: str = Field(
        "INFO",
        validation_alias=AliasChoices("LOG_LEVEL", "log_level"),
    )
    prometheus_enabled: bool = Field(
        True,
        validation_alias=AliasChoices("PROMETHEUS_ENABLED", "prometheus_enabled"),
    )
    deployment_environment: str = Field(
        "dev",
        validation_alias=AliasChoices("DEPLOYMENT_ENVIRONMENT", "deployment_environment"),
    )
