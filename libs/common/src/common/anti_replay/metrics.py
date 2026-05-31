"""Prometheus metrics for the anti-replay subsystem (TASK-050).

On import, this module attempts to create real Prometheus counters.  If
``prometheus_client`` is not installed, no-op stubs are used so the rest of the
anti-replay code runs without modification.

Prometheus alert rule (for deployment):
  ClockSkewViolationSpike:
    expr: rate(clock_skew_violations_total[5m]) > 1
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: >
        Elevated clock skew violation rate — possible NTP misconfiguration or
        active replay-with-future-timestamp attack.
"""
from __future__ import annotations


class _NoOpCounter:
    """Stub counter when prometheus_client is absent."""

    def inc(self, amount: float = 1) -> None:  # noqa: D102
        pass

    def labels(self, **_kwargs):  # noqa: D102
        return self


try:
    from prometheus_client import Counter  # type: ignore[import]

    REPLAY_INSERTS: Counter = Counter(
        "replay_cache_inserts_total",
        "New JTI accepted by the replay cache (not a replay).",
    )
    REPLAY_REJECTS: Counter = Counter(
        "replay_cache_rejects_total",
        "Duplicate JTI rejected by the replay cache (replay detected).",
    )
    REPLAY_REDIS_FALLBACK: Counter = Counter(
        "replay_cache_redis_fallback_total",
        "Number of times Redis was unavailable and the in-memory fallback was used.",
    )
    CLOCK_SKEW_VIOLATIONS: Counter = Counter(
        "clock_skew_violations_total",
        "Clock skew violations detected during JWT temporal claim validation.",
        ["direction"],  # "future" | "past"
    )
    NONCE_CONSUMED: Counter = Counter(
        "nonce_consumed_total",
        "NonceStore consume outcomes.",
        ["result"],  # "match" | "mismatch" | "expired"
    )

except Exception:  # pragma: no cover — prometheus_client not installed
    REPLAY_INSERTS = _NoOpCounter()  # type: ignore[assignment]
    REPLAY_REJECTS = _NoOpCounter()  # type: ignore[assignment]
    REPLAY_REDIS_FALLBACK = _NoOpCounter()  # type: ignore[assignment]
    CLOCK_SKEW_VIOLATIONS = _NoOpCounter()  # type: ignore[assignment]
    NONCE_CONSUMED = _NoOpCounter()  # type: ignore[assignment]
