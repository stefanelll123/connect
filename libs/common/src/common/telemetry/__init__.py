"""OpenTelemetry, Prometheus, and structured-logging telemetry utilities.

Quick start::

    from common.telemetry import setup_telemetry, get_tracer, get_meter
    from common.telemetry.settings import TelemetrySettings

    settings = TelemetrySettings()
    tracer, meter = setup_telemetry("my-service", "1.0.0", settings)
"""

from __future__ import annotations

from opentelemetry import metrics, trace

from common.telemetry.logging import configure_logging
from common.telemetry.metrics import configure_metrics, get_meter
from common.telemetry.settings import TelemetrySettings
from common.telemetry.tracing import configure_tracing, get_tracer


def setup_telemetry(
    service_name: str,
    version: str,
    settings: TelemetrySettings | None = None,
) -> tuple[trace.Tracer, metrics.Meter]:
    """Configure tracing, metrics, and structured logging for a service.

    This function is the single entry point that services call at startup,
    before constructing the FastAPI application.

    Args:
        service_name: Short identifier for this service, e.g. ``"discovery"``.
        version:      Semantic version string, e.g. ``"1.0.0"``.
        settings:     Optional pre-built :class:`TelemetrySettings`; if *None*,
                      settings are loaded from environment variables.

    Returns:
        A ``(tracer, meter)`` tuple scoped to this service that can be passed
        to modules that need direct instrumentation.
    """
    if settings is None:
        settings = TelemetrySettings(service_name=service_name, service_version=version)
    else:
        # Preserve caller-supplied name/version if settings has defaults
        if settings.service_name == "unknown-service":
            settings = settings.model_copy(
                update={"service_name": service_name, "service_version": version}
            )

    configure_logging(settings)
    configure_tracing(settings)
    configure_metrics(settings)

    return get_tracer(service_name), get_meter(service_name)


__all__ = [
    "setup_telemetry",
    "get_tracer",
    "get_meter",
    "TelemetrySettings",
]

