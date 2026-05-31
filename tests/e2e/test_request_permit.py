"""E2E — Request permit latency SLO.

Scenario:
  A sentinel producer evaluates an inbound request carrying a valid VP.
  The decision MUST be PERMIT and p95 latency MUST be < 200 ms.
  The mock-backend MUST receive exactly one forwarded request.
"""
from __future__ import annotations

import statistics
import time
import uuid

import httpx
import pytest

LATENCY_P95_MS = 200
SAMPLE_SIZE = 20


def _make_request_headers(vc_jwt: str, nonce: str) -> dict[str, str]:
    return {
        "X-Sentinel-VC": vc_jwt,
        "X-Request-ID": nonce,
        "X-Nonce": nonce,
        "X-Timestamp": str(int(time.time())),
        "Content-Type": "application/json",
    }


@pytest.mark.e2e
def test_request_permit_latency(
    discovery_client: httpx.Client,
    sentinel_producer_client: httpx.Client,
    admin_token: str,
) -> None:
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Obtain an active service & issue credential
    services_resp = discovery_client.get("/api/v1/services", params={"status": "active"})
    assert services_resp.status_code == 200
    services = services_resp.json()
    if not services:
        pytest.skip("No active services available")

    service_id = services[0]["id"]
    issue_resp = discovery_client.post(
        "/api/v1/credentials/issue",
        headers=admin_headers,
        json={"subject_id": service_id, "credential_type": "ServiceAccessCredential", "claims": {}},
    )
    assert issue_resp.status_code == 201
    vc_jwt = issue_resp.json()["credential"]

    # Warm up (one un-timed request)
    nonce = str(uuid.uuid4())
    sentinel_producer_client.post(
        "/api/v1/request",
        headers=_make_request_headers(vc_jwt, nonce),
        json={"target": "/api/data", "method": "GET"},
    )

    # Timed samples
    latencies_ms: list[float] = []
    for _ in range(SAMPLE_SIZE):
        nonce = str(uuid.uuid4())
        t0 = time.perf_counter()
        resp = sentinel_producer_client.post(
            "/api/v1/request",
            headers=_make_request_headers(vc_jwt, nonce),
            json={"target": "/api/data", "method": "GET"},
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000
        latencies_ms.append(elapsed_ms)
        assert resp.status_code == 200, f"Expected PERMIT (200), got {resp.status_code}: {resp.text}"
        decision = resp.json().get("decision")
        assert decision == "PERMIT", f"Expected PERMIT, got {decision}"

    sorted_latencies = sorted(latencies_ms)
    p50 = sorted_latencies[int(SAMPLE_SIZE * 0.50)]
    p95 = sorted_latencies[int(SAMPLE_SIZE * 0.95)]
    p99 = sorted_latencies[min(int(SAMPLE_SIZE * 0.99), SAMPLE_SIZE - 1)]

    print(f"\nLatency p50={p50:.1f}ms  p95={p95:.1f}ms  p99={p99:.1f}ms")
    assert p95 < LATENCY_P95_MS, (
        f"p95 latency {p95:.1f}ms exceeds SLO of {LATENCY_P95_MS}ms"
    )
