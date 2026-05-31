"""Full Prometheus/OTel metrics catalogue for sentinel nodes (TASK-052).

Defines all 18 sentinel-specific Prometheus metrics using ``prometheus_client``.
Import and use as a module-level singleton::

    from common.sentinel_logging.sentinel_metrics import SENTINEL_METRICS as m
    m.inbound_requests_total.labels(decision="permit", error_code="").inc()

Set ``SENTINEL_METRICS_ENABLED=false`` to use no-op stubs (test environments).
"""
from __future__ import annotations

import os
from typing import Any

_ENABLED = os.getenv("SENTINEL_METRICS_ENABLED", "true").lower() not in ("false", "0", "no")

try:
    import prometheus_client as _pc
    _HAS_PROMETHEUS = True
except ImportError:  # pragma: no cover
    _HAS_PROMETHEUS = False


# ---------------------------------------------------------------------------
# No-op stubs when prometheus_client is unavailable or metrics disabled
# ---------------------------------------------------------------------------

class _NoOpMetric:
    """Silent stub that absorbs any .labels() / .inc() / .set() / .observe() calls."""

    def labels(self, **kwargs: Any) -> "_NoOpMetric":  # noqa: ANN401
        return self

    def inc(self, amount: float = 1) -> None:
        pass

    def dec(self, amount: float = 1) -> None:
        pass

    def set(self, value: float) -> None:
        pass

    def observe(self, value: float) -> None:
        pass


def _counter(name: str, description: str, labelnames: list[str]) -> Any:  # noqa: ANN401
    if not _ENABLED or not _HAS_PROMETHEUS:
        return _NoOpMetric()
    return _pc.Counter(name, description, labelnames)


def _histogram(name: str, description: str, labelnames: list[str], buckets: list[float] | None = None) -> Any:  # noqa: ANN401
    if not _ENABLED or not _HAS_PROMETHEUS:
        return _NoOpMetric()
    kw: dict[str, Any] = {}
    if buckets:
        kw["buckets"] = buckets
    return _pc.Histogram(name, description, labelnames, **kw)


def _gauge(name: str, description: str, labelnames: list[str]) -> Any:  # noqa: ANN401
    if not _ENABLED or not _HAS_PROMETHEUS:
        return _NoOpMetric()
    return _pc.Gauge(name, description, labelnames)


# ---------------------------------------------------------------------------
# Metric 1 — Inbound requests
# ---------------------------------------------------------------------------
inbound_requests_total = _counter(
    "sentinel_inbound_requests_total",
    "Total inbound requests handled by the sentinel.",
    ["sentinel_role", "service_id", "env", "decision", "error_code"],
)

# ---------------------------------------------------------------------------
# Metric 2 — Outbound requests
# ---------------------------------------------------------------------------
outbound_requests_total = _counter(
    "sentinel_outbound_requests_total",
    "Total outbound requests forwarded to upstream services.",
    ["sentinel_role", "service_id", "env", "status_class"],
)

# ---------------------------------------------------------------------------
# Metric 3 — Inbound request duration histogram
# ---------------------------------------------------------------------------
_INBOUND_BUCKETS = [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
inbound_request_duration_seconds = _histogram(
    "sentinel_inbound_request_duration_seconds",
    "Inbound request processing time by pipeline stage.",
    ["sentinel_role", "service_id", "env", "stage"],
    buckets=_INBOUND_BUCKETS,
)

# ---------------------------------------------------------------------------
# Metric 4 — Upstream latency histogram
# ---------------------------------------------------------------------------
upstream_latency_seconds = _histogram(
    "sentinel_upstream_latency_seconds",
    "Latency of upstream (proxied) requests.",
    ["sentinel_role", "service_id", "env"],
)

# ---------------------------------------------------------------------------
# Metric 5 — Denies by reason
# ---------------------------------------------------------------------------
denies_total = _counter(
    "sentinel_denies_total",
    "Total request denials, broken down by reason.",
    ["sentinel_role", "service_id", "env", "reason"],
)

# ---------------------------------------------------------------------------
# Metric 6 — Replay rejects
# ---------------------------------------------------------------------------
replay_rejects_total = _counter(
    "sentinel_replay_rejects_total",
    "Total VP/JTI replay rejections.",
    ["sentinel_role", "service_id", "env"],
)

# ---------------------------------------------------------------------------
# Metric 7 — Replay cache Redis fallback
# ---------------------------------------------------------------------------
replay_cache_fallback_total = _counter(
    "sentinel_replay_cache_fallback_total",
    "Number of times the in-memory fallback was used instead of Redis.",
    ["sentinel_role", "service_id", "env"],
)

# ---------------------------------------------------------------------------
# Metric 8 — Revocation staleness events
# ---------------------------------------------------------------------------
revocation_stale_total = _counter(
    "sentinel_revocation_stale_total",
    "Number of times revocation data was detected as stale.",
    ["sentinel_role", "service_id", "env"],
)

# ---------------------------------------------------------------------------
# Metric 9 — Chain RPC errors
# ---------------------------------------------------------------------------
chain_rpc_errors_total = _counter(
    "sentinel_chain_rpc_errors_total",
    "Total chain RPC errors by method.",
    ["sentinel_role", "service_id", "env", "method"],
)

# ---------------------------------------------------------------------------
# Metric 10 — Chain cache misses
# ---------------------------------------------------------------------------
chain_cache_miss_total = _counter(
    "sentinel_chain_cache_miss_total",
    "Cache misses for chain resolution results.",
    ["sentinel_role", "service_id", "env", "cache_type"],
)

# ---------------------------------------------------------------------------
# Metric 11 — Trust layer unavailable
# ---------------------------------------------------------------------------
trust_layer_unavailable_total = _counter(
    "sentinel_trust_layer_unavailable_total",
    "Number of times the trust layer (chain / registry) was unavailable.",
    ["sentinel_role", "service_id", "env"],
)

# ---------------------------------------------------------------------------
# Metric 12 — VC verifications
# ---------------------------------------------------------------------------
vc_verifications_total = _counter(
    "sentinel_vc_verifications_total",
    "Total Verifiable Credential verifications by result.",
    ["sentinel_role", "service_id", "env", "result"],
)

# ---------------------------------------------------------------------------
# Metric 13 — Credential sync lag
# ---------------------------------------------------------------------------
credential_sync_lag_seconds = _gauge(
    "sentinel_credential_sync_lag_seconds",
    "Seconds since last successful credential sync.",
    ["sentinel_role", "service_id", "env"],
)

# ---------------------------------------------------------------------------
# Metric 14 — Policy evaluations
# ---------------------------------------------------------------------------
policy_evaluate_total = _counter(
    "sentinel_policy_evaluate_total",
    "Total policy evaluations by decision.",
    ["sentinel_role", "service_id", "env", "decision"],
)

# ---------------------------------------------------------------------------
# Metric 15 — Descriptor cache misses
# ---------------------------------------------------------------------------
descriptor_cache_misses_total = _counter(
    "sentinel_descriptor_cache_misses_total",
    "Number of cache misses when resolving service descriptors.",
    ["sentinel_role", "service_id", "env"],
)

# ---------------------------------------------------------------------------
# Metric 16 — Active connections (in-flight requests)
# ---------------------------------------------------------------------------
active_connections = _gauge(
    "sentinel_active_connections",
    "Current number of in-flight inbound requests.",
    ["sentinel_role", "service_id", "env"],
)

# ---------------------------------------------------------------------------
# Metric 17 — Emergency revocation checks
# ---------------------------------------------------------------------------
emergency_revocation_checks_total = _counter(
    "sentinel_emergency_revocation_checks_total",
    "Total emergency (on-chain) revocation checks.",
    ["sentinel_role", "service_id", "env", "result"],
)

# ---------------------------------------------------------------------------
# Metric 18 — Key rotations
# ---------------------------------------------------------------------------
key_rotation_total = _counter(
    "sentinel_key_rotation_total",
    "Total number of sentinel key rotation events.",
    ["sentinel_role", "service_id", "env"],
)
