"""OTel meter setup and standard Prometheus/OTLP metric definitions.

All services should call ``configure_metrics(settings)`` once at startup, then
use ``get_meter(name)`` to obtain a meter for recording application metrics.

Standard sentinel metrics are pre-defined here so that their names and label sets
are consistent across services.
"""

from __future__ import annotations

from opentelemetry import metrics
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes

from common.telemetry.settings import TelemetrySettings

# ---------------------------------------------------------------------------
# Global meter provider
# ---------------------------------------------------------------------------

_meter_provider: MeterProvider | metrics.NoOpMeterProvider | None = None


def configure_metrics(settings: TelemetrySettings) -> metrics.MeterProvider:
    """Create and globally register a :class:`MeterProvider`.

    If OTel is disabled, registers a no-op provider.

    Returns the configured provider.
    """
    global _meter_provider  # noqa: PLW0603

    if not settings.otel_enabled:
        noop = metrics.NoOpMeterProvider()
        metrics.set_meter_provider(noop)
        _meter_provider = noop
        return noop

    resource = Resource.create(
        {
            ResourceAttributes.SERVICE_NAME: settings.service_name,
            ResourceAttributes.SERVICE_VERSION: settings.service_version,
            "deployment.environment": settings.deployment_environment,
        }
    )

    exporter = OTLPMetricExporter(
        endpoint=settings.otel_endpoint.rstrip("/") + "/v1/metrics",
    )
    reader = PeriodicExportingMetricReader(exporter, export_interval_millis=30_000)
    provider = MeterProvider(resource=resource, metric_readers=[reader])

    metrics.set_meter_provider(provider)
    _meter_provider = provider
    return provider


def get_meter(name: str) -> metrics.Meter:
    """Return a meter scoped to *name* from the globally registered provider."""
    return metrics.get_meter(name)


# ---------------------------------------------------------------------------
# Standard Sentinel metrics
# ---------------------------------------------------------------------------
# These are module-level instances so they can be imported directly.
# They are lazily initialised — concrete instruments are created on first use
# after configure_metrics() is called.

class SentinelMetrics:
    """Container for the standard per-service metric instruments.

    Usage::

        from common.telemetry.metrics import SentinelMetrics
        m = SentinelMetrics("discovery")
        m.http_requests_total.add(1, {"method": "GET", "path": "/health", "status_code": "200"})
    """

    def __init__(self, service_name: str) -> None:
        meter = get_meter(f"sentinel.{service_name}")

        self.http_requests_total = meter.create_counter(
            name="http_requests_total",
            description="Total HTTP requests handled.",
            unit="1",
        )
        self.http_request_duration_seconds = meter.create_histogram(
            name="http_request_duration_seconds",
            description="HTTP request processing time in seconds.",
            unit="s",
        )
        self.sentinel_vc_validations_total = meter.create_counter(
            name="sentinel_vc_validations_total",
            description="Total Verifiable Credential verifications (label: result=valid|invalid|expired).",
            unit="1",
        )
        self.sentinel_replay_cache_hits_total = meter.create_counter(
            name="sentinel_replay_cache_hits_total",
            description="Number of replay-cache hits (VP nonce already seen).",
            unit="1",
        )
        self.sentinel_active_instances = meter.create_up_down_counter(
            name="sentinel_active_instances",
            description="Number of currently active Sentinel service instances.",
            unit="1",
        )
