"""E2E — Service onboarding end-to-end flow.

Scenario: A new service provider enrolls, gets approved, bootstraps their
sentinel node, and appears healthy both in Discovery and on-chain.
Total time budget: < 60 s.
"""
from __future__ import annotations

import time

import httpx
import pytest


@pytest.mark.e2e
@pytest.mark.timeout(60)
def test_full_onboarding_flow(
    discovery_client: httpx.Client,
    admin_token: str,
    hardhat,
    deploy_contracts: dict,
) -> None:
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Enroll a new service provider
    enroll_resp = discovery_client.post(
        "/api/v1/enrollment",
        json={
            "service_name": "e2e-test-service",
            "service_url": "https://e2e.example.com",
            "contact_email": "ops@e2e.example.com",
            "did_document": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:example:e2e-test-service",
                "verificationMethod": [],
            },
        },
    )
    assert enroll_resp.status_code == 201, enroll_resp.text
    enrollment_id = enroll_resp.json()["id"]

    # 2. Admin approves enrollment
    approve_resp = discovery_client.post(
        f"/api/v1/admin/enrollment/{enrollment_id}/approve",
        headers=admin_headers,
    )
    assert approve_resp.status_code == 200, approve_resp.text

    # 3. Bootstrap the service (retrieve credentials)
    bootstrap_resp = discovery_client.post(
        f"/api/v1/enrollment/{enrollment_id}/bootstrap",
    )
    assert bootstrap_resp.status_code == 200, bootstrap_resp.text
    service_id = bootstrap_resp.json()["service_id"]
    assert service_id

    # 4. Service should appear healthy in Discovery
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        health_resp = discovery_client.get(f"/api/v1/services/{service_id}")
        if health_resp.status_code == 200 and health_resp.json().get("status") == "active":
            break
        time.sleep(1)
    else:
        pytest.fail(f"Service {service_id} not active after 30s: {health_resp.text}")

    # 5. Verify it appears in /api/v1/services list
    list_resp = discovery_client.get("/api/v1/services")
    assert list_resp.status_code == 200
    service_ids = [s["id"] for s in list_resp.json()]
    assert service_id in service_ids

    # 6. Verify on-chain registration (IssuerRegistered event)
    registry_addr = deploy_contracts.get("IssuerRegistry")
    if registry_addr:
        logs = hardhat.eth.get_logs(
            {"address": registry_addr, "fromBlock": "earliest"}
        )
        assert len(logs) >= 1, "Expected at least one IssuerRegistered event on-chain"

    # 7. Audit log should contain enrollment events
    audit_resp = discovery_client.get(
        "/api/v1/audit",
        headers=admin_headers,
        params={"action": "enrollment.approved", "target_id": service_id},
    )
    assert audit_resp.status_code == 200
    events = audit_resp.json().get("events", [])
    assert any(e.get("action") == "enrollment.approved" for e in events)
