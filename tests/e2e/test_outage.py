"""E2E — Outage handling: fail-closed and discovery outage behaviour.

Scenario A (RPC outage): When the chain RPC becomes unreachable, after the
  status-list TTL expires the sentinel MUST fail-closed (DENY) rather than
  silently permitting.

Scenario B (Discovery outage): When the discovery service is unreachable, the
  sentinel producer MUST reject inbound requests rather than fall through to
  the backend.
"""
from __future__ import annotations

import subprocess
import time
import uuid

import httpx
import pytest

COMPOSE_FILE = "tests/e2e/docker-compose.e2e.yml"
# Allow a short window for cached/in-flight decisions to flush
FAIL_CLOSED_TIMEOUT_S = 30


def _send_request(client: httpx.Client, vc_jwt: str) -> tuple[int, str]:
    nonce = str(uuid.uuid4())
    resp = client.post(
        "/api/v1/request",
        headers={
            "X-Sentinel-VC": vc_jwt,
            "X-Request-ID": nonce,
            "X-Nonce": nonce,
            "X-Timestamp": str(int(time.time())),
        },
        json={"target": "/api/data", "method": "GET"},
        timeout=5,
    )
    decision = resp.json().get("decision", "UNKNOWN") if resp.status_code == 200 else f"HTTP_{resp.status_code}"
    return resp.status_code, decision


def _pause_service(service: str) -> None:
    subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, "pause", service],
        check=True,
    )


def _unpause_service(service: str) -> None:
    subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, "unpause", service],
        check=True,
    )


@pytest.mark.e2e
@pytest.mark.timeout(90)
def test_rpc_outage_fail_closed(
    discovery_client: httpx.Client,
    sentinel_producer_client: httpx.Client,
    admin_token: str,
) -> None:
    """After chain RPC goes down, sentinel must fail-closed within FAIL_CLOSED_TIMEOUT_S."""
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    services_resp = discovery_client.get("/api/v1/services", params={"status": "active"})
    services = services_resp.json()
    if not services:
        pytest.skip("No active services")

    service_id = services[0]["id"]
    issue_resp = discovery_client.post(
        "/api/v1/credentials/issue",
        headers=admin_headers,
        json={"subject_id": service_id, "credential_type": "ServiceAccessCredential", "claims": {}},
    )
    vc_jwt = issue_resp.json()["credential"]

    # Baseline: confirm PERMIT
    status, decision = _send_request(sentinel_producer_client, vc_jwt)
    assert decision == "PERMIT", f"Baseline not PERMIT: {decision}"

    # Pause the hardhat node (simulates RPC outage)
    _pause_service("hardhat-node")
    try:
        deadline = time.monotonic() + FAIL_CLOSED_TIMEOUT_S
        last_decision = "PERMIT"
        while time.monotonic() < deadline:
            try:
                _, last_decision = _send_request(sentinel_producer_client, vc_jwt)
                if last_decision != "PERMIT":
                    break
            except Exception:
                break
            time.sleep(1)

        assert last_decision != "PERMIT", (
            f"Sentinel did not fail-closed within {FAIL_CLOSED_TIMEOUT_S}s of RPC outage"
        )
    finally:
        _unpause_service("hardhat-node")


@pytest.mark.e2e
def test_discovery_outage_producer_rejects(
    discovery_client: httpx.Client,
    sentinel_producer_client: httpx.Client,
    admin_token: str,
) -> None:
    """When discovery is paused, producer must reject new requests."""
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    services_resp = discovery_client.get("/api/v1/services", params={"status": "active"})
    services = services_resp.json()
    if not services:
        pytest.skip("No active services")

    service_id = services[0]["id"]
    issue_resp = discovery_client.post(
        "/api/v1/credentials/issue",
        headers=admin_headers,
        json={"subject_id": service_id, "credential_type": "ServiceAccessCredential", "claims": {}},
    )
    # Use a fresh credential issued just before the outage
    vc_jwt = issue_resp.json()["credential"]

    _pause_service("discovery")
    try:
        # Allow cache to expire (2s conservative)
        time.sleep(2)

        # With discovery down, request should be rejected
        status, decision = _send_request(sentinel_producer_client, vc_jwt)
        assert decision != "PERMIT", (
            f"Expected non-PERMIT when discovery is down, got {decision} (status={status})"
        )
    finally:
        _unpause_service("discovery")
