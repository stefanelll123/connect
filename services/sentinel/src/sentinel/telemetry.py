"""Telemetry helpers for the Sentinel Node."""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def init_tracing(settings, app) -> None:  # type: ignore[type-arg]
    """Initialise OTel SDK for the sentinel service."""
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError:
        logger.warning("opentelemetry-sdk not installed; tracing disabled.")
        return

    resource = Resource.create({
        "service.name": "sentinel-node",
        "sentinel.role": getattr(settings, "sentinel_role", "unknown"),
        "deployment.environment": getattr(settings, "env", "dev"),
    })
    exporter = OTLPSpanExporter(
        endpoint=settings.otlp_endpoint,
        insecure=getattr(settings, "otlp_insecure", True),
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    try:
        FastAPIInstrumentor.instrument_app(
            app, excluded_urls="/health/live,/health/ready,/metrics"
        )
    except Exception as exc:
        logger.warning("FastAPIInstrumentor failed: %s", exc)
