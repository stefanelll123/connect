# Outage & Staleness Policy

**Document version:** 1.0  
**Status:** Approved  
**Applies to:** Producer Sentinel status-list cache, Consumer Sentinel config cache

---

## 1. Background

The system relies on two externally-fetched artefacts that are cached locally by Sentinels:

1. **Bitstring Status List** — retrieved from the Discovery service; authoritative source of VC revocation state  
2. **Config bundle** — retrieved from the Discovery service during onboarding and periodically refreshed

If the network or Discovery service becomes unavailable, the Sentinel must decide whether to continue serving requests using a potentially stale cache, or to block all requests until freshness is restored.

This document formalises that decision as a bounded-freshness (Δ) policy.

---

## 2. Definitions

| Term | Definition |
|------|-----------|
| **Δ (delta)** | The maximum age, in seconds, that a cached artefact may be before it is considered stale |
| **anchor_updated_at** | UTC timestamp embedded in the artefact when it was last written by the authoritative source |
| **staleness condition** | `now_utc() - anchor_updated_at > Δ` |
| **FAIL_CLOSED** | Reject all incoming requests when the cache is stale |
| **FAIL_OPEN_DEGRADED** | Accept requests using the stale cached state, but attach a degraded-mode header and increment stale counters |
| **ALLOW_CACHED** | Accept requests using the cached state; appropriate only in development |

---

## 3. Per-Environment Defaults

| Environment | Δ (seconds) | Mode on stale | Rationale |
|-------------|-------------|---------------|-----------|
| `prod` | 600 | FAIL_CLOSED | Revocation must propagate within 10 min in production |
| `staging` | 1800 | FAIL_CLOSED | Mirror prod behaviour; 30-min window for staging deployments |
| `test` | 3600 | FAIL_OPEN_DEGRADED | Avoid flaky test failures due to clock skew in CI |
| `dev` | 86400 | ALLOW_CACHED | Developer machines may be offline for hours |

Environment is read from the `ENV` environment variable. Unknown values fall back to `prod` behaviour.

---

## 4. Decision Algorithm

```
function check_status_list_freshness(cached_artefact, env):
    delta = DELTA_BY_ENV[env]            # from table above
    age = now_utc() - cached_artefact.anchor_updated_at

    if age <= delta:
        # artefact is fresh
        return FRESH

    mode = MODE_BY_ENV[env]

    if mode == FAIL_CLOSED:
        metrics.increment("status_stale_total", labels={env: env, action: "reject"})
        log.warning("Status list stale: age=%ds threshold=%ds — FAIL_CLOSED", age, delta)
        raise StatusListStaleError(age=age, threshold=delta)

    if mode == FAIL_OPEN_DEGRADED:
        metrics.increment("status_stale_total", labels={env: env, action: "degraded"})
        log.warning("Status list stale: age=%ds threshold=%ds — FAIL_OPEN_DEGRADED", age, delta)
        return DEGRADED

    # ALLOW_CACHED (dev only)
    metrics.increment("status_stale_total", labels={env: env, action: "allow_cached"})
    return ALLOW_CACHED
```

---

## 5. Error Type

`StatusListStaleError` is raised in FAIL_CLOSED mode. It is:

- A subclass of `RuntimeError`
- Caught at the request gateway and translated to HTTP **503 Service Unavailable**
- Never caught silently; every catch site must log or re-raise

Response body when FAIL_CLOSED triggers:

```json
{
  "error": "status_list_stale",
  "age_seconds": 612,
  "threshold_seconds": 600,
  "detail": "Revocation status list is stale; request rejected to preserve security invariant SI-004."
}
```

---

## 6. Metric Names

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `status_stale_total` | Counter | `env`, `action` | Incremented each time a stale-cache decision is made. `action` ∈ `{reject, degraded, allow_cached}` |
| `status_list_age_seconds` | Gauge | `env` | Current age of the cached status list artefact |
| `status_list_refresh_failures_total` | Counter | `env`, `reason` | Failed attempts to refresh the status list from Discovery |

All metrics are exported via OpenTelemetry (OTLP) to the configured metrics backend.

---

## 7. Alert Rules

```yaml
# Prometheus / Alertmanager example
- alert: StatusListStaleProd
  expr: status_list_age_seconds{env="prod"} > 540
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "Status list approaching stale threshold (prod)"
    description: "Current age {{ $value }}s is within 60s of the 600s FAIL_CLOSED threshold."

- alert: StatusListStaleRejecting
  expr: increase(status_stale_total{action="reject"}[5m]) > 0
  for: 0m
  labels:
    severity: critical
  annotations:
    summary: "Sentinel is rejecting requests due to stale status list"
    description: "FAIL_CLOSED triggered {{ $value }} times in the last 5 minutes."
```

---

## 8. Recovery Procedure

1. **Discovery available again** — the background refresh goroutine (interval = Δ/4) will fetch a fresh list and update `anchor_updated_at`. Requests resume automatically.
2. **Discovery degraded** — operator initiates manual cache refresh via admin API: `POST /admin/status-list/refresh`.
3. **Extended outage** — if outage exceeds Δ, operator may temporarily raise Δ via `DELTA_OVERRIDE_SECONDS` env var. This override must be removed before the next deployment and requires an incident ticket.

---

## 9. Security Invariant

This policy directly enforces **SI-004** (from `security-invariants.md`):

> *The Producer Sentinel MUST validate the revocation status of a VC on every verified request; a stale cache beyond Δ seconds MUST cause the Sentinel to reject all incoming requests in production.*

Violation of this invariant would allow a revoked credential to be accepted during an outage window, enabling threat **T-004** (stale status list acceptance after revocation).
