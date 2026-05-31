"""
Locust load tests for the Connect sentinel protocol.

Experiments (§5.2 of the paper):
  (a) Phase A vs Phase B latency — P50 / P95 / P99
      Phase A: first request per sentinel instance forces full VP credential
               exchange between consumer and producer (on-chain VC verification).
      Phase B: subsequent requests reuse a session token cached inside the
               consumer sentinel (SD-JWT fast-path, no on-chain lookup).
  (b) Throughput-vs-concurrency characterisation

Architecture note
-----------------
Locust targets the *consumer* sentinel at http://sentinel-consumer:8080.
The consumer sentinel's outbound pipeline handles ALL credential work
internally: it selects a VC from its enrolled wallet, builds a VP envelope
(SentinelProof + SentinelVP headers), and forwards the request to the
producer sentinel.  Locust itself sends NO auth headers.

Consumer routes exercised
--------------------------
  GET  /health/live
  GET  /health/ready
  POST /outbound/<service_id>/<path>   — full consumer → producer pipeline

Environment variables (optional)
---------------------------------
  LOCUST_TARGET_SERVICE_ID   — target service_id (default: aws-sentinel-producer)
  LOCUST_PAYLOAD_SIZE_BYTES  — approximate request body size  (default: 256)
"""
from __future__ import annotations

import os
import random
import string
import time

from locust import HttpUser, between, events, task


TARGET_SERVICE_ID = os.getenv("LOCUST_TARGET_SERVICE_ID", "aws-sentinel-producer")
PAYLOAD_SIZE = int(os.getenv("LOCUST_PAYLOAD_SIZE_BYTES", "256"))

# Outbound prefix for all cross-sentinel requests
_OUTBOUND = f"/outbound/{TARGET_SERVICE_ID}"


def _random_body(size: int) -> dict:
    data = "".join(random.choices(string.ascii_letters + string.digits, k=size))
    return {"data": data, "ts": time.time()}


# ── Base user: disable gzip so the sentinel proxy doesn't pass through a
#    Content-Encoding: gzip header on an already-decompressed body. ──────────

class SentinelUser(HttpUser):
    """Base class — disables Accept-Encoding so responses are plain JSON."""

    abstract = True

    def on_start(self) -> None:
        # The consumer sentinel decompresses the upstream gzip response but
        # keeps the Content-Encoding: gzip header, causing requests (used by
        # Locust) to try to double-decompress and fail.  Sending
        # Accept-Encoding: identity prevents the mock-backend from gzip-ing
        # in the first place.
        self.client.headers["Accept-Encoding"] = "identity"


# ── Phase A User ──────────────────────────────────────────────────────────────

class PhaseAUser(SentinelUser):
    """
    Experiment (a) — Phase A latency.

    Exercises the full VP credential exchange path:
      Locust → consumer sentinel → (VP build + on-chain verify) → producer → backend

    The first call to a given producer triggers Phase A at the consumer
    (no cached session token).  Subsequent calls within the same sentinel
    process reuse the cached session (Phase B internally), so this user
    class is most useful for initial warm-up measurements or after the
    consumer is freshly started.

    Think-time is kept short to maximize Phase A observations per run.
    """

    wait_time = between(0.1, 0.5)

    @task(1)
    def health_probe(self) -> None:
        with self.client.get("/health/live", name="GET /health/live", catch_response=True) as r:
            if r.status_code == 200:
                r.success()
            else:
                r.failure(f"liveness {r.status_code}")

    @task(9)
    def outbound_request(self) -> None:
        """POST through consumer → producer pipeline (measures Phase A / warm-up)."""
        with self.client.post(
            f"{_OUTBOUND}/api/echo",
            json=_random_body(PAYLOAD_SIZE),
            name=f"POST {_OUTBOUND}/api/echo [Phase A]",
            catch_response=True,
        ) as r:
            _handle_outbound_response(r)


# ── Phase B User ──────────────────────────────────────────────────────────────

class PhaseBUser(SentinelUser):
    """
    Experiment (a) — Phase B latency (session-token fast-path).

    After the consumer has a cached session token for the producer (obtained
    during the first Phase A exchange), all subsequent requests use only the
    lightweight SD-JWT session token.  This class models steady-state traffic
    once the sentinel pair is warmed up.
    """

    wait_time = between(0.05, 0.2)

    @task(1)
    def readiness_probe(self) -> None:
        with self.client.get("/health/ready", name="GET /health/ready", catch_response=True) as r:
            if r.status_code in (200, 503):
                r.success()
            else:
                r.failure(f"readiness {r.status_code}")

    @task(9)
    def outbound_request(self) -> None:
        """POST through consumer → producer pipeline (measures Phase B steady-state)."""
        with self.client.post(
            f"{_OUTBOUND}/api/echo",
            json=_random_body(PAYLOAD_SIZE),
            name=f"POST {_OUTBOUND}/api/echo [Phase B]",
            catch_response=True,
        ) as r:
            _handle_outbound_response(r)


# ── Throughput User ───────────────────────────────────────────────────────────

class ThroughputUser(SentinelUser):
    """
    Experiment (b) — Throughput-vs-concurrency characterisation.

    Mixed workload to find the saturation point of a single sentinel pair.
    Run with increasing concurrency (10 → 200 users) and record RPS vs. P95.
    """

    wait_time = between(0.0, 0.1)

    @task(7)
    def outbound_data(self) -> None:
        with self.client.post(
            f"{_OUTBOUND}/api/echo",
            json=_random_body(PAYLOAD_SIZE),
            name=f"POST {_OUTBOUND}/api/echo [throughput]",
            catch_response=True,
        ) as r:
            _handle_outbound_response(r)

    @task(2)
    def health_live(self) -> None:
        with self.client.get("/health/live", name="GET /health/live", catch_response=True) as r:
            if r.status_code == 200:
                r.success()
            else:
                r.failure(f"liveness {r.status_code}")

    @task(1)
    def health_ready(self) -> None:
        with self.client.get("/health/ready", name="GET /health/ready", catch_response=True) as r:
            if r.status_code in (200, 503):
                r.success()
            else:
                r.failure(f"readiness {r.status_code}")


# ── Shared response handler ───────────────────────────────────────────────────

def _handle_outbound_response(resp) -> None:  # noqa: ANN001
    sc = resp.status_code
    if sc in (200, 201, 202):
        resp.success()
    elif sc == 401:
        resp.failure("401 — producer rejected VP (enrollment may have expired)")
    elif sc == 403:
        resp.failure("403 — trust policy denied")
    elif sc == 503:
        resp.failure("503 — producer unreachable or no endpoints available")
    elif sc == 502:
        resp.failure(f"502 — upstream auth failure or descriptor invalid")
    else:
        resp.failure(f"{sc}: {resp.text[:200]}")


# ── Lifecycle hooks ───────────────────────────────────────────────────────────

@events.test_start.add_listener
def on_test_start(environment, **kwargs):  # noqa: ANN001, ANN003
    print(f"[locust] test starting — target={TARGET_SERVICE_ID}  payload={PAYLOAD_SIZE}B")
    print(f"[locust] outbound prefix: {_OUTBOUND}")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):  # noqa: ANN001, ANN003
    stats = environment.stats.total
    p95 = stats.get_response_time_percentile(0.95)
    p99 = stats.get_response_time_percentile(0.99)
    print(
        f"[locust] done — reqs={stats.num_requests}  "
        f"failures={stats.num_failures}  "
        f"avg={stats.avg_response_time:.1f}ms  "
        f"p95={p95:.1f}ms  p99={p99:.1f}ms"
    )
