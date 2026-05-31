"""Structured logging configuration using structlog with OTel trace correlation.

Call ``configure_logging(settings)`` once at application startup. After that,
obtain a logger via ``structlog.get_logger(__name__)`` in any module.

Every log event automatically includes:
  - ``trace_id`` and ``span_id`` when emitted from within an active OTel span
  - ``timestamp`` (ISO 8601)
  - ``level`` and ``logger``
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog
from opentelemetry import trace

from common.telemetry.settings import TelemetrySettings


# ---------------------------------------------------------------------------
# OTel trace context processor
# ---------------------------------------------------------------------------


def add_otel_trace_context(
    logger: Any,  # noqa: ANN401
    method: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    """structlog processor that injects ``trace_id`` and ``span_id`` if a span is active.

    The fields match the standard Grafana Loki/Tempo correlation format::

        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736"  (32 hex chars)
        span_id:  "00f067aa0ba902b7"                    (16 hex chars)
    """
    span = trace.get_current_span()
    if span.is_recording():
        ctx = span.get_span_context()
        event_dict["trace_id"] = format(ctx.trace_id, "032x")
        event_dict["span_id"] = format(ctx.span_id, "016x")
    return event_dict


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------


def configure_logging(settings: TelemetrySettings) -> None:
    """Configure structlog for JSON structured output with OTel trace correlation.

    This function is idempotent — calling it multiple times is safe.
    """
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    # Configure stdlib logging as the root handler so third-party libraries
    # that use stdlib logging are also captured.
    logging.basicConfig(
        stream=sys.stdout,
        level=log_level,
        format="%(message)s",  # structlog formats the full JSON
    )

    # Silence noisy third-party library loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        add_otel_trace_context,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        # Final renderer: JSON for production, coloured for dev
        processor=structlog.processors.JSONRenderer(),
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)
