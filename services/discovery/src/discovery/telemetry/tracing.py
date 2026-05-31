"""OpenTelemetry tracing initialisation (TASK-036).

Usage::

    from discovery.telemetry.tracing import init_tracing, get_tracer

    init_tracing(settings, app)          # call once at startup
    tracer = get_tracer()
    with tracer.start_as_current_span("my-operation") as span:
        span.set_attribute("key", "value")
"""
from __future__ import annotations

import logging
from functools import lru_cache

logger = logging.getLogger(__name__)

_EXCLUDED_URLS = ["/health/live", "/health/ready", "/metrics"]


def init_tracing(settings, app) -> None:  # type: ignore[type-arg]
    """Initialise the OTel SDK and instrument FastAPI + SQLAlchemy.

    Idempotent — calling more than once has no effect.
    """
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        logger.warning("opentelemetry-sdk not installed; tracing disabled.")
        return

    resource = Resource.create({
        "service.name": "discovery-service",
        "deployment.environment": getattr(settings, "env", "dev"),
    })

    exporter = OTLPSpanExporter(
        endpoint=settings.otlp_endpoint,
        insecure=getattr(settings, "otlp_insecure", True),
    )

    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    # Instrument FastAPI
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(
            app,
            excluded_urls=",".join(_EXCLUDED_URLS),
        )
    except Exception as exc:
        logger.warning("FastAPIInstrumentor failed: %s", exc)

    # Instrument SQLAlchemy (optional)
    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        SQLAlchemyInstrumentor().instrument()
    except Exception as exc:
        logger.debug("SQLAlchemyInstrumentor not available: %s", exc)

    logger.info("OTel tracing initialised → %s", settings.otlp_endpoint)


@lru_cache(maxsize=1)
def get_tracer():
    """Return the application tracer singleton."""
    try:
        from opentelemetry import trace
        return trace.get_tracer("discovery-service")
    except ImportError:
        return _NoOpTracer()


# ---------------------------------------------------------------------------
# No-op tracer for environments without opentelemetry-sdk
# ---------------------------------------------------------------------------

class _NoOpSpan:
    def set_attribute(self, key: str, value) -> None:
        pass

    def record_exception(self, exc: Exception) -> None:
        pass

    def set_status(self, status) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class _NoOpTracer:
    def start_as_current_span(self, name: str, **kwargs):
        return _NoOpSpan()

    def start_span(self, name: str, **kwargs):
        return _NoOpSpan()
