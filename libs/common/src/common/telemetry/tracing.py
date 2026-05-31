"""OTel tracer setup — TracerProvider, OTLP exporter, span processor."""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.semconv.resource import ResourceAttributes

from common.telemetry.settings import TelemetrySettings


def configure_tracing(settings: TelemetrySettings) -> trace.TracerProvider:
    """Create and globally register a :class:`TracerProvider`.

    If OTel is disabled, registers a no-op provider so all ``get_tracer()``
    and span operations are safe zero-cost no-ops.

    Returns the configured provider.
    """
    if not settings.otel_enabled:
        noop = trace.NoOpTracerProvider()
        trace.set_tracer_provider(noop)
        return noop

    resource = Resource.create(
        {
            ResourceAttributes.SERVICE_NAME: settings.service_name,
            ResourceAttributes.SERVICE_VERSION: settings.service_version,
            "deployment.environment": settings.deployment_environment,
        }
    )

    exporter = OTLPSpanExporter(
        endpoint=settings.otel_endpoint.rstrip("/") + "/v1/traces",
    )

    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)
    return provider


def get_tracer(name: str) -> trace.Tracer:
    """Return a tracer scoped to *name* from the globally registered provider."""
    return trace.get_tracer(name)
