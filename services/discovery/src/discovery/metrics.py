"""Prometheus metrics for the Discovery Service (TASK-036).

All metric objects are defined here as module-level singletons.
Import and call the helper functions to record observations.

Usage example::

    from discovery.metrics import record_http_request, record_onboarding_attempt
    record_http_request("POST", "sentinels_onboard", 200, duration_seconds=0.123)
    record_onboarding_attempt(env="prod", role="issuer", outcome="success")
"""
from __future__ import annotations

try:
    from prometheus_client import Counter, Gauge, Histogram
    _ENABLED = True
except ImportError:  # pragma: no cover
    _ENABLED = False

# ---------------------------------------------------------------------------
# HTTP traffic
# ---------------------------------------------------------------------------

if _ENABLED:
    HTTP_REQUESTS_TOTAL = Counter(
        "http_requests_total",
        "Total HTTP requests",
        ["method", "endpoint", "status_code"],
    )

    HTTP_REQUEST_DURATION = Histogram(
        "http_request_duration_seconds",
        "HTTP request latency",
        ["method", "endpoint"],
        buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
    )

    # ---------------------------------------------------------------------------
    # Domain metrics
    # ---------------------------------------------------------------------------

    ONBOARDING_ATTEMPTS = Counter(
        "onboarding_attempts_total",
        "Sentinel onboarding attempts",
        ["env", "role", "outcome"],   # outcome: success | failure | abuse_blocked
    )

    CREDENTIAL_ISSUANCE = Counter(
        "credential_issuance_total",
        "Verifiable credentials issued",
        ["env", "cred_type", "outcome"],
    )

    REVOCATION_EVENTS = Counter(
        "revocation_events_total",
        "Credential revocation events",
        ["env", "outcome"],
    )

    # ---------------------------------------------------------------------------
    # Chain RPC
    # ---------------------------------------------------------------------------

    CHAIN_RPC_DURATION = Histogram(
        "chain_rpc_request_duration_seconds",
        "Chain JSON-RPC call latency",
        ["method"],
        buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0],
    )

    CHAIN_RPC_ERRORS = Counter(
        "chain_rpc_errors_total",
        "Chain JSON-RPC errors",
        ["method", "error_type"],
    )

    CHAIN_INDEXER_LAG = Gauge(
        "chain_indexer_lag_blocks",
        "Number of blocks the local indexer is behind chain head",
    )

    # ---------------------------------------------------------------------------
    # Operational
    # ---------------------------------------------------------------------------

    AUDIT_WRITE_FAILURES = Counter(
        "audit_write_failure_total",
        "Audit log write failures",
        ["reason"],
    )

    SENTINEL_STATUS = Gauge(
        "sentinel_status_gauge",
        "Current status of registered sentinels (1=active, 0=inactive)",
        ["env", "role", "status"],
    )


# ---------------------------------------------------------------------------
# Helper functions — no-op if prometheus_client not installed
# ---------------------------------------------------------------------------

def record_http_request(
    method: str,
    endpoint: str,
    status_code: int,
    duration_seconds: float,
) -> None:
    """Record a completed HTTP request."""
    if not _ENABLED:
        return
    labels = {"method": method, "endpoint": endpoint}
    HTTP_REQUESTS_TOTAL.labels(
        method=method, endpoint=endpoint, status_code=str(status_code)
    ).inc()
    HTTP_REQUEST_DURATION.labels(**labels).observe(duration_seconds)


def record_onboarding_attempt(
    env: str, role: str, outcome: str
) -> None:
    if not _ENABLED:
        return
    ONBOARDING_ATTEMPTS.labels(env=env, role=role, outcome=outcome).inc()


def record_credential_issuance(
    env: str, cred_type: str, outcome: str
) -> None:
    if not _ENABLED:
        return
    CREDENTIAL_ISSUANCE.labels(env=env, cred_type=cred_type, outcome=outcome).inc()


def record_revocation_event(env: str, outcome: str) -> None:
    if not _ENABLED:
        return
    REVOCATION_EVENTS.labels(env=env, outcome=outcome).inc()


def record_chain_rpc(method: str, duration_seconds: float) -> None:
    if not _ENABLED:
        return
    CHAIN_RPC_DURATION.labels(method=method).observe(duration_seconds)


def record_chain_rpc_error(method: str, error_type: str) -> None:
    if not _ENABLED:
        return
    CHAIN_RPC_ERRORS.labels(method=method, error_type=error_type).inc()


def record_audit_write_failure(reason: str) -> None:
    if not _ENABLED:
        return
    AUDIT_WRITE_FAILURES.labels(reason=reason).inc()
