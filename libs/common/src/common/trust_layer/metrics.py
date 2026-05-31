"""Prometheus metrics for TrustLayerClient (TASK-042)."""
from __future__ import annotations

try:
    from prometheus_client import Counter, Gauge

    trust_cache_hits_total = Counter(
        "trust_cache_hits_total",
        "Cache hits per type",
        ["type"],
    )
    trust_cache_misses_total = Counter(
        "trust_cache_misses_total",
        "Cache misses per type",
        ["type"],
    )
    trust_cache_staleness_seconds = Gauge(
        "trust_cache_staleness_seconds",
        "Seconds since last successful chain refresh per type",
        ["type"],
    )
    chain_rpc_errors_total = Counter(
        "trust_chain_rpc_errors_total",
        "Chain RPC errors per method",
        ["method"],
    )
    trust_layer_unavailable_total = Counter(
        "trust_layer_unavailable_total",
        "Times the OUTAGE_POLICY was triggered",
    )

except ImportError:  # pragma: no cover
    # Graceful no-op if prometheus_client is not installed
    class _Noop:
        def labels(self, **_kw):
            return self
        def inc(self, *a, **kw): pass
        def set(self, *a, **kw): pass

    trust_cache_hits_total = _Noop()
    trust_cache_misses_total = _Noop()
    trust_cache_staleness_seconds = _Noop()
    chain_rpc_errors_total = _Noop()
    trust_layer_unavailable_total = _Noop()
