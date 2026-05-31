"""E2E — Replay attack prevention.

Scenario:
  1. First request with a unique nonce → PERMIT.
  2. Replay the exact same nonce/proof → MUST return 403 PROOF_ALREADY_SEEN.
"""
from __future__ import annotations

import time
import uuid

import httpx
import pytest


def _build_headers(vc_jwt: str, nonce: str) -> dict[str, str]:
    return {
        "X-Sentinel-VC": vc_jwt,
        "X-Request-ID": nonce,
        "X-Nonce": nonce,
        "X-Timestamp": str(int(time.time())),
        "Content-Type": "application/json",
    }


@pytest.mark.e2e
def test_replay_rejected(
    discovery_client: httpx.Client,
    sentinel_producer_client: httpx.Client,
    admin_token: str,
) -> None:
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Obtain active service + credential
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

    # Unique nonce for this test
    nonce = str(uuid.uuid4())
    headers = _build_headers(vc_jwt, nonce)
    payload = {"target": "/api/data", "method": "GET"}

    # 1. First request → PERMIT
    first_resp = sentinel_producer_client.post(
        "/api/v1/request", headers=headers, json=payload
    )
    assert first_resp.status_code == 200, f"First request failed: {first_resp.text}"
    assert first_resp.json().get("decision") == "PERMIT"

    # 2. Replay the same request → DENY with 403 + PROOF_ALREADY_SEEN error code
    replay_resp = sentinel_producer_client.post(
        "/api/v1/request", headers=headers, json=payload
    )
    assert replay_resp.status_code == 403, (
        f"Expected 403 on replay, got {replay_resp.status_code}: {replay_resp.text}"
    )
    body = replay_resp.json()
    assert body.get("error_code") == "PROOF_ALREADY_SEEN", (
        f"Expected error_code=PROOF_ALREADY_SEEN, got: {body}"
    )


@pytest.mark.e2e
def test_different_nonces_both_permitted(
    discovery_client: httpx.Client,
    sentinel_producer_client: httpx.Client,
    admin_token: str,
) -> None:
    """Two requests with different nonces must both be permitted."""
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    services_resp = discovery_client.get("/api/v1/services", params={"status": "active"})
    services = services_resp.json()
    if not services:
        pytest.skip("No active services available")

    service_id = services[0]["id"]
    issue_resp = discovery_client.post(
        "/api/v1/credentials/issue",
        headers=admin_headers,
        json={"subject_id": service_id, "credential_type": "ServiceAccessCredential", "claims": {}},
    )
    vc_jwt = issue_resp.json()["credential"]

    for _ in range(2):
        nonce = str(uuid.uuid4())
        resp = sentinel_producer_client.post(
            "/api/v1/request",
            headers=_build_headers(vc_jwt, nonce),
            json={"target": "/api/data", "method": "GET"},
        )
        assert resp.status_code == 200
        assert resp.json().get("decision") == "PERMIT"
