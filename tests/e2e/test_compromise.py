"""E2E — Issuer compromise containment test.

Scenario: An issuer's key is compromised. The admin disables the issuer
on-chain. The sentinel MUST deny ALL credentials from that issuer within
30 seconds (time_to_containment ≤ 30s).
"""
from __future__ import annotations

import time
import uuid

import httpx
import pytest

CONTAINMENT_DEADLINE_S = 30


def _send_request(client: httpx.Client, vc_jwt: str) -> str:
    """Return decision string or HTTP_xxx on error."""
    nonce = str(uuid.uuid4())
    try:
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
        if resp.status_code == 200:
            return resp.json().get("decision", "UNKNOWN")
        return f"HTTP_{resp.status_code}"
    except Exception as exc:
        return f"ERROR_{exc!s:.30}"


@pytest.mark.e2e
@pytest.mark.timeout(90)
def test_issuer_compromise_containment(
    discovery_client: httpx.Client,
    sentinel_producer_client: httpx.Client,
    admin_token: str,
    deploy_contracts: dict,
    hardhat,
) -> None:
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Obtain active service + credential
    services_resp = discovery_client.get("/api/v1/services", params={"status": "active"})
    assert services_resp.status_code == 200
    services = services_resp.json()
    if not services:
        pytest.skip("No active services")

    service_id = services[0]["id"]
    issue_resp = discovery_client.post(
        "/api/v1/credentials/issue",
        headers=admin_headers,
        json={"subject_id": service_id, "credential_type": "ServiceAccessCredential", "claims": {}},
    )
    assert issue_resp.status_code == 201
    vc_jwt = issue_resp.json()["credential"]
    issuer_did = issue_resp.json().get("issuer_did")

    # 2. Confirm credential is initially PERMIT
    decision = _send_request(sentinel_producer_client, vc_jwt)
    assert decision == "PERMIT", f"Expected initial PERMIT, got {decision}"

    # 3. Disable issuer on-chain via admin API (which calls the smart contract)
    disable_resp = discovery_client.post(
        f"/api/v1/admin/issuers/{issuer_did}/disable",
        headers=admin_headers,
        json={"reason": "e2e_compromise_test"},
    )
    assert disable_resp.status_code == 200, disable_resp.text

    disable_ts = time.monotonic()

    # 4. Poll until DENY or containment deadline
    final_decision = "PERMIT"
    while time.monotonic() - disable_ts < CONTAINMENT_DEADLINE_S:
        final_decision = _send_request(sentinel_producer_client, vc_jwt)
        if final_decision != "PERMIT":
            break
        time.sleep(1)

    elapsed = time.monotonic() - disable_ts

    assert final_decision != "PERMIT", (
        f"Sentinel still returning PERMIT {elapsed:.1f}s after issuer disabled on-chain"
    )
    assert elapsed <= CONTAINMENT_DEADLINE_S, (
        f"Time-to-containment {elapsed:.1f}s exceeded {CONTAINMENT_DEADLINE_S}s SLO"
    )

    print(f"\nTime-to-containment: {elapsed:.1f}s (SLO: {CONTAINMENT_DEADLINE_S}s) ✓")

    # 5. Audit log should contain the compromise/disable event
    audit_resp = discovery_client.get(
        "/api/v1/audit",
        headers=admin_headers,
        params={"action": "issuer.disabled", "target_id": issuer_did},
    )
    assert audit_resp.status_code == 200
    events = audit_resp.json().get("events", [])
    assert any(e.get("action") == "issuer.disabled" for e in events), (
        "Expected 'issuer.disabled' event in audit log"
    )
