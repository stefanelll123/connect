"""OTel SDK setup and auto-instrumentation for sentinel nodes (TASK-052).

Usage::

    from common.sentinel_logging.otel import setup_tracing
    setup_tracing(
        service_name="sentinel",
        instance_id="abc123",
        env="dev",
        role="producer",
        otlp_endpoint="http://otel-collector:4317",
        sample_rate=1.0,
    )

Returns the globally-registered :class:`opentelemetry.trace.Tracer`.
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


def setup_tracing(
    service_name: str,
    instance_id: str,
    env: str,
    role: str,
    otlp_endpoint: str | None = None,
    sample_rate: float | None = None,
) -> Any:  # noqa: ANN401
    """Configure the OTel TracerProvider and return a Tracer.

    Args:
        service_name: ``service.name`` resource attribute.
        instance_id:  ``service.instance.id`` resource attribute.
        env:          Deployment environment (dev / staging / prod).
        role:         ``sentinel.role`` (producer | consumer).
        otlp_endpoint: gRPC OTLP endpoint; if *None* reads
            ``OTEL_EXPORTER_OTLP_ENDPOINT`` env var.  Falls back to
            :class:`ConsoleSpanExporter` in dev if still unset.
        sample_rate:  Trace sampling ratio 0.0–1.0; if *None* reads
            ``OTEL_TRACES_SAMPLE_RATE`` env var (default 1.0 dev / 0.1 prod).

    Returns:
        An :class:`opentelemetry.trace.Tracer` scoped to *service_name*.
    """
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import (
            ParentBasedTraceIdRatio,
        )
    except ImportError:
        logger.warning("opentelemetry-sdk not installed; tracing disabled.")
        from opentelemetry import trace as _trace
        return _trace.get_tracer(service_name)

    # Resolve sample rate
    if sample_rate is None:
        _env_rate = os.getenv("OTEL_TRACES_SAMPLE_RATE")
        if _env_rate is not None:
            sample_rate = float(_env_rate)
        else:
            sample_rate = 0.1 if env == "prod" else 1.0

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.instance.id": instance_id,
            "deployment.environment": env,
            "sentinel.role": role,
        }
    )

    sampler = ParentBasedTraceIdRatio(sample_rate)
    provider = TracerProvider(resource=resource, sampler=sampler)

    # Resolve OTLP endpoint
    endpoint = otlp_endpoint or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )
            exporter = OTLPSpanExporter(endpoint=endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
        except ImportError:
            logger.warning("OTLP gRPC exporter not installed; falling back to console.")
            _add_console_exporter(provider)
    else:
        _add_console_exporter(provider)

    trace.set_tracer_provider(provider)
    return trace.get_tracer(service_name)


def _add_console_exporter(provider: Any) -> None:  # noqa: ANN401
    try:
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    except ImportError:
        pass


def get_tracer(service_name: str) -> Any:  # noqa: ANN401
    """Return a tracer from the globally-registered provider."""
    from opentelemetry import trace
    return trace.get_tracer(service_name)


def instrument_fastapi(app: Any) -> None:  # noqa: ANN401
    """Auto-instrument a FastAPI app with :class:`FastAPIInstrumentor`."""
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor().instrument_app(app)
    except ImportError:
        logger.warning("opentelemetry-instrumentation-fastapi not installed.")


def instrument_httpx() -> None:
    """Auto-instrument the httpx client."""
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        HTTPXClientInstrumentor().instrument()
    except ImportError:
        logger.warning("opentelemetry-instrumentation-httpx not installed.")


def setup_log_bridge() -> None:
    """Bridge Python logging to OTel via LoggingInstrumentor."""
    try:
        from opentelemetry.instrumentation.logging import LoggingInstrumentor
        LoggingInstrumentor().instrument(set_logging_format=True)
    except ImportError:
        logger.warning("opentelemetry-instrumentation-logging not installed.")
