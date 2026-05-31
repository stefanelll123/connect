"""Prometheus metric definitions for the Revocation module (TASK-046).

Metrics are defined module-globally and lazily imported, so they are only
created when prometheus_client is installed.  If prometheus_client is absent
(e.g. in unit tests with minimal deps), all metric objects fall back to
no-op stubs so callers never need to guard with try/except.
"""
from __future__ import annotations

from typing import Optional

__all__ = [
    "REVOCATION_CHECKS",
    "STATUS_LIST_CACHE_HITS",
    "STATUS_LIST_CACHE_MISSES",
    "STATUS_LIST_STALENESS",
    "STATUS_LIST_DOWNLOAD_DURATION",
    "EMERGENCY_CHECKS",
]


class _NoOpCounter:
    def labels(self, **_kwargs) -> "_NoOpCounter":
        return self

    def inc(self, amount: float = 1) -> None:
        pass


class _NoOpGauge:
    def labels(self, **_kwargs) -> "_NoOpGauge":
        return self

    def set(self, value: float) -> None:
        pass


class _NoOpHistogram:
    def labels(self, **_kwargs) -> "_NoOpHistogram":
        return self

    def observe(self, value: float) -> None:
        pass

    def time(self):
        """Context manager / decorator stub."""
        import contextlib
        return contextlib.nullcontext()


def _try_counter(name: str, help_text: str, labelnames=None):
    try:
        from prometheus_client import Counter
        return Counter(name, help_text, labelnames or [])
    except Exception:
        return _NoOpCounter()


def _try_gauge(name: str, help_text: str, labelnames=None):
    try:
        from prometheus_client import Gauge
        return Gauge(name, help_text, labelnames or [])
    except Exception:
        return _NoOpGauge()


def _try_histogram(name: str, help_text: str, labelnames=None, buckets=None):
    try:
        from prometheus_client import Histogram, DEFAULT_BUCKETS
        kwargs = {"labelnames": labelnames or []}
        if buckets:
            kwargs["buckets"] = buckets
        return Histogram(name, help_text, **kwargs)
    except Exception:
        return _NoOpHistogram()


# ── Metrics ────────────────────────────────────────────────────────────────

REVOCATION_CHECKS = _try_counter(
    "revocation_checks_total",
    "Total credential revocation checks by result",
    labelnames=["result"],
)

STATUS_LIST_CACHE_HITS = _try_counter(
    "status_list_cache_hits_total",
    "Status list in-memory cache hits",
)

STATUS_LIST_CACHE_MISSES = _try_counter(
    "status_list_cache_misses_total",
    "Status list in-memory cache misses",
)

STATUS_LIST_STALENESS = _try_gauge(
    "status_list_staleness_seconds",
    "Current staleness of cached status list in seconds",
    labelnames=["status_list_id"],
)

STATUS_LIST_DOWNLOAD_DURATION = _try_histogram(
    "status_list_download_duration_seconds",
    "Duration of status list downloads from Discovery",
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

EMERGENCY_CHECKS = _try_counter(
    "emergency_checks_total",
    "Total emergency on-chain revocation checks by result",
    labelnames=["result"],
)
