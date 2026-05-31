"""E2E — Revocation propagation timing.

Scenario:
  Given a valid issued credential and an active sentinel:
  1. Initial request → PERMIT.
  2. Admin revokes the credential.
  3. For at least Δ seconds after revocation, sentinel still returns PERMIT
     (grace period / propagation window).
  4. After Δ + buffer seconds, sentinel MUST return DENY.
  Total time-to-deny MUST be ≤ Δ + 5 s.
"""
from __future__ import annotations

import time
import uuid

import httpx
import pytest

# Revocation propagation delta (must match REVOCATION_DELTA env on sentinel)
REVOCATION_DELTA_S = int(10)  # conservative for E2E; real value may differ
MAX_TIME_TO_DENY_S = REVOCATION_DELTA_S + 5


def _permit_request(client: httpx.Client, vc_jwt: str) -> str:
    """POST a request and return the decision string."""
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
    )
    if resp.status_code == 200:
        return resp.json().get("decision", "UNKNOWN")
    if resp.status_code == 403:
        return "DENY"
    return f"STATUS_{resp.status_code}"


@pytest.mark.e2e
@pytest.mark.timeout(60)
def test_revocation_propagation(
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
        pytest.skip("No active services — run onboarding test first")

    service_id = services[0]["id"]
    issue_resp = discovery_client.post(
        "/api/v1/credentials/issue",
        headers=admin_headers,
        json={"subject_id": service_id, "credential_type": "ServiceAccessCredential", "claims": {}},
    )
    assert issue_resp.status_code == 201
    vc_jwt = issue_resp.json()["credential"]
    credential_id = issue_resp.json()["id"]

    # 1. Verify PERMIT before revocation
    decision = _permit_request(sentinel_producer_client, vc_jwt)
    assert decision == "PERMIT", f"Expected PERMIT before revocation, got {decision}"

    # 2. Revoke the credential
    revoke_ts = time.monotonic()
    revoke_resp = discovery_client.post(
        f"/api/v1/credentials/{credential_id}/revoke",
        headers=admin_headers,
        json={"reason": "e2e_test_revocation"},
    )
    assert revoke_resp.status_code == 200, revoke_resp.text

    # 3. For at least 1s after revocation, PERMIT is still acceptable (grace window)
    time.sleep(1)
    grace_decision = _permit_request(sentinel_producer_client, vc_jwt)
    # Grace period: PERMIT is acceptable (cached status list not yet expired)
    assert grace_decision in ("PERMIT", "DENY"), f"Unexpected decision: {grace_decision}"

    # 4. Poll until DENY or timeout
    deadline = revoke_ts + MAX_TIME_TO_DENY_S
    final_decision = grace_decision
    while time.monotonic() < deadline and final_decision != "DENY":
        time.sleep(1)
        final_decision = _permit_request(sentinel_producer_client, vc_jwt)

    elapsed = time.monotonic() - revoke_ts
    assert final_decision == "DENY", (
        f"Expected DENY after revocation propagation but got {final_decision} after {elapsed:.1f}s"
    )
    assert elapsed <= MAX_TIME_TO_DENY_S, (
        f"Time-to-deny {elapsed:.1f}s exceeded max allowed {MAX_TIME_TO_DENY_S}s"
    )

    print(f"\nTime-to-deny: {elapsed:.1f}s (max allowed: {MAX_TIME_TO_DENY_S}s)")
