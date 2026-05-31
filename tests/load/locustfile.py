"""
Locust load tests for the Connect sentinel protocol.

Experiments (§5.2 of the paper):
  (a) Phase A vs Phase B latency — P50 / P95 / P99
  (b) Throughput-vs-concurrency characterisation
  (c) Revocation propagation timing — measured by revocation_timing.py

Usage (from the consumer EC2 instance after sourcing .env):

  # Headless — Phase A benchmark (50 users, 5 min)
  locust -f locustfile.py PhaseAUser \
    --headless -u 50 -r 5 -t 300s \
    --host $PRODUCER_URL \
    --csv results/phase_a

  # Headless — Phase B benchmark (50 users, 5 min)
  locust -f locustfile.py PhaseBUser \
    --headless -u 50 -r 5 -t 300s \
    --host $PRODUCER_URL \
    --csv results/phase_b

  # Concurrency sweep — mixed workload (use run_load_tests.sh for automated sweep)
  locust -f locustfile.py ThroughputUser \
    --headless -u 100 -r 10 -t 120s \
    --host $PRODUCER_URL \
    --csv results/throughput_100u

  # Web UI (interactive)
  locust -f locustfile.py --host $PRODUCER_URL

Environment variables consumed:
  PRODUCER_URL      — base URL of the producer sentinel  (default: http://localhost:8080)
  DISCOVERY_URL     — base URL of discovery service      (default: http://localhost:8000)
  DISCOVERY_ADMIN_API_KEY — admin key to issue test credentials
  SSM_PREFIX        — SSM prefix for fetching VC JWT     (default: /connect-test)
  AWS_DEFAULT_REGION
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Optional

import httpx
from locust import HttpUser, between, events, task
from locust.runners import MasterRunner, WorkerRunner

logger = logging.getLogger(__name__)

DISCOVERY_URL = os.environ.get("DISCOVERY_URL", "http://localhost:8000")
DISCOVERY_ADMIN_API_KEY = os.environ.get("DISCOVERY_ADMIN_API_KEY", "")
SSM_PREFIX = os.environ.get("SSM_PREFIX", "/connect-test")
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

# Shared VC JWT — fetched once and reused across all users (Option A seeding).
_shared_vc_jwt: Optional[str] = None
# Shared session token — one warm-up Phase A call populates this for Phase B users.
_shared_session_token: Optional[str] = None


# ── Helpers ──────────────────────────────────────────────────────────────────

def _fetch_vc_jwt_from_ssm() -> Optional[str]:
    """Try to retrieve the pre-seeded VC JWT from AWS SSM Parameter Store."""
    try:
        import boto3
        ssm = boto3.client("ssm", region_name=AWS_REGION)
        resp = ssm.get_parameter(
            Name=f"{SSM_PREFIX}/load_test/vc_jwt",
            WithDecryption=True,
        )
        return resp["Parameter"]["Value"]
    except Exception as exc:
        logger.warning("Could not fetch VC JWT from SSM: %s", exc)
        return None


def _fetch_vc_jwt_from_discovery() -> Optional[str]:
    """Fallback: issue a fresh credential via the Discovery admin API."""
    try:
        resp = httpx.post(
            f"{DISCOVERY_URL}/api/v1/credentials/issue",
            headers={"X-API-Key": DISCOVERY_ADMIN_API_KEY},
            json={
                "subject_id": "load-test-consumer",
                "credential_type": "ServiceAccessCredential",
                "claims": {},
            },
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("credential")
    except Exception as exc:
        logger.warning("Could not issue VC from Discovery: %s", exc)
        return None


def _get_vc_jwt() -> Optional[str]:
    """Return the shared VC JWT, fetching it if necessary."""
    global _shared_vc_jwt
    if _shared_vc_jwt:
        return _shared_vc_jwt
    _shared_vc_jwt = _fetch_vc_jwt_from_ssm()
    if not _shared_vc_jwt:
        logger.info("SSM fetch failed, trying Discovery API directly...")
        _shared_vc_jwt = _fetch_vc_jwt_from_discovery()
    return _shared_vc_jwt


def _make_phase_a_headers(vc_jwt: str) -> dict[str, str]:
    """Headers for a Phase A (full VC verification) request."""
    nonce = str(uuid.uuid4())
    return {
        "X-Sentinel-VC": vc_jwt,
        "X-Request-ID": nonce,
        "X-Nonce": nonce,
        "X-Timestamp": str(int(time.time())),
        "Content-Type": "application/json",
    }


def _make_phase_b_headers(session_token: str) -> dict[str, str]:
    """Headers for a Phase B (session token fast-path) request."""
    return {
        "Authorization": f"Bearer {session_token}",
        "Content-Type": "application/json",
    }


# ── Test users ────────────────────────────────────────────────────────────────

class PhaseAUser(HttpUser):
    """
    Experiment (a) — Phase A latency.

    Each task performs a full Phase A pipeline:
      1. Consumer presents VC JWT to producer sentinel.
      2. Sentinel verifies credential on-chain + checks trust policy.
      3. Sentinel forwards request to mock-backend and returns PERMIT.

    Measures the full cryptographic verification + policy evaluation cost.
    """

    wait_time = between(0.1, 0.5)   # small think-time to avoid queue saturation

    def on_start(self) -> None:
        self.vc_jwt = _get_vc_jwt()
        if not self.vc_jwt:
            logger.error(
                "No VC JWT available. Set DISCOVERY_ADMIN_API_KEY or seed via hub.sh."
            )

    @task
    def phase_a_request(self) -> None:
        if not self.vc_jwt:
            return

        headers = _make_phase_a_headers(self.vc_jwt)
        with self.client.post(
            "/api/v1/request",
            headers=headers,
            json={"target": "/api/data", "method": "GET"},
            name="Phase A — full VC verification",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                decision = resp.json().get("decision", "")
                if decision == "PERMIT":
                    resp.success()
                else:
                    resp.failure(f"Expected PERMIT, got decision={decision!r}")
            elif resp.status_code == 429:
                resp.failure("Rate limited (429)")
            else:
                resp.failure(f"Unexpected status {resp.status_code}: {resp.text[:200]}")


class PhaseBUser(HttpUser):
    """
    Experiment (a) — Phase B latency (session token fast-path).

    on_start performs ONE Phase A call to obtain a session token.
    Subsequent tasks use only the session token — no VC re-verification.

    This models a service that has already gone through Phase A and is
    now in the SD-JWT fast-path (SESSION_TOKEN_TTL window).
    """

    wait_time = between(0.05, 0.2)  # faster since Phase B is much cheaper

    def on_start(self) -> None:
        self.vc_jwt = _get_vc_jwt()
        self.session_token: Optional[str] = None

        if not self.vc_jwt:
            logger.error("No VC JWT available for Phase A warm-up.")
            return

        # Warm-up: one Phase A call to get a session token.
        headers = _make_phase_a_headers(self.vc_jwt)
        resp = self.client.post(
            "/api/v1/request",
            headers=headers,
            json={"target": "/api/data", "method": "GET"},
            name="Phase B warm-up (Phase A)",
        )
        if resp.status_code == 200:
            # The session token may be returned in the response body or
            # in a Set-Cookie / X-Session-Token header depending on impl.
            body = resp.json()
            self.session_token = (
                body.get("session_token")
                or resp.headers.get("X-Session-Token")
                or resp.cookies.get("sentinel_session")
            )
            if not self.session_token:
                logger.warning(
                    "Phase A warm-up succeeded but no session token found in "
                    "response. Phase B tasks will fall back to Phase A headers."
                )
        else:
            logger.error(
                "Phase A warm-up failed with status %s: %s",
                resp.status_code, resp.text[:200],
            )

    @task
    def phase_b_request(self) -> None:
        if self.session_token:
            headers = _make_phase_b_headers(self.session_token)
        elif self.vc_jwt:
            # Fallback to Phase A headers if session token not available.
            headers = _make_phase_a_headers(self.vc_jwt)
        else:
            return

        with self.client.post(
            "/api/v1/request",
            headers=headers,
            json={"target": "/api/data", "method": "GET"},
            name="Phase B — session token fast-path",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            elif resp.status_code == 401:
                # Session expired — refresh with Phase A.
                self.session_token = None
                resp.failure("Session expired (401), will refresh on next iteration")
            else:
                resp.failure(f"Status {resp.status_code}: {resp.text[:200]}")


class ThroughputUser(HttpUser):
    """
    Experiment (b) — Throughput-vs-concurrency characterisation.

    Mixed workload: 70% Phase B (session fast-path), 30% Phase A (fresh VC).
    Run with increasing concurrency levels (10 → 200 users) to find the
    saturation point and the throughput ceiling of a single sentinel instance.

    Results: plot requests/second vs. user count; note where P95 > 500 ms.
    """

    wait_time = between(0.0, 0.1)

    def on_start(self) -> None:
        self.vc_jwt = _get_vc_jwt()
        self.session_token: Optional[str] = None

        if self.vc_jwt:
            headers = _make_phase_a_headers(self.vc_jwt)
            resp = self.client.post(
                "/api/v1/request",
                headers=headers,
                json={"target": "/api/ping", "method": "GET"},
                name="ThroughputUser warm-up",
            )
            if resp.status_code == 200:
                body = resp.json()
                self.session_token = (
                    body.get("session_token")
                    or resp.headers.get("X-Session-Token")
                )

    @task(7)
    def phase_b(self) -> None:
        if self.session_token:
            headers = _make_phase_b_headers(self.session_token)
        elif self.vc_jwt:
            headers = _make_phase_a_headers(self.vc_jwt)
        else:
            return

        with self.client.post(
            "/api/v1/request",
            headers=headers,
            json={"target": "/api/data", "method": "GET"},
            name="Throughput — Phase B (70%)",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            elif resp.status_code == 401:
                self.session_token = None
                resp.failure("401 — session expired")
            else:
                resp.failure(f"Status {resp.status_code}")

    @task(3)
    def phase_a(self) -> None:
        if not self.vc_jwt:
            return

        with self.client.post(
            "/api/v1/request",
            headers=_make_phase_a_headers(self.vc_jwt),
            json={"target": "/api/data", "method": "GET"},
            name="Throughput — Phase A (30%)",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                body = resp.json()
                new_token = (
                    body.get("session_token")
                    or resp.headers.get("X-Session-Token")
                )
                if new_token:
                    self.session_token = new_token
                resp.success()
            else:
                resp.failure(f"Status {resp.status_code}")


# ── Lifecycle hooks ───────────────────────────────────────────────────────────

@events.init.add_listener
def on_init(environment, **_kwargs):
    """Pre-fetch the VC JWT before the first user spawns."""
    if not isinstance(environment.runner, (WorkerRunner,)):
        logger.info("Pre-fetching VC JWT for load tests...")
        jwt = _get_vc_jwt()
        if jwt:
            logger.info("✓ VC JWT ready (%d chars)", len(jwt))
        else:
            logger.warning(
                "No VC JWT found. Set DISCOVERY_ADMIN_API_KEY or ensure "
                "hub.sh ran seed step 10 successfully."
            )


@events.quitting.add_listener
def on_quitting(environment, **_kwargs):
    """Print a brief P50/P95/P99 summary at exit."""
    if hasattr(environment, "runner") and environment.runner is not None:
        stats = environment.runner.stats
        for name, entry in stats.entries.items():
            if entry.num_requests == 0:
                continue
            p50 = entry.get_response_time_percentile(0.50)
            p95 = entry.get_response_time_percentile(0.95)
            p99 = entry.get_response_time_percentile(0.99)
            rps = entry.current_rps
            print(
                f"[{name[1]}] n={entry.num_requests}  "
                f"p50={p50}ms  p95={p95}ms  p99={p99}ms  "
                f"rps={rps:.1f}  failures={entry.num_failures}"
            )
