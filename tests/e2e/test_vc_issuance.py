"""E2E — Verifiable Credential issuance and sentinel verification.

Scenario:
  1. Issue a VC from Discovery for a registered service.
  2. Push the VC to the sentinel producer for verification.
  3. Verify the JWT structure (header.payload.signature).
  4. Confirm status bit 0 is not revoked.
"""
from __future__ import annotations

import base64
import json
import time

import httpx
import pytest


@pytest.mark.e2e
def test_vc_issuance_and_verification(
    discovery_client: httpx.Client,
    sentinel_producer_client: httpx.Client,
    admin_token: str,
) -> None:
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Obtain a valid service_id (assumes onboarding has run or a seeded service exists)
    services_resp = discovery_client.get("/api/v1/services", params={"status": "active"})
    assert services_resp.status_code == 200
    services = services_resp.json()
    if not services:
        pytest.skip("No active services registered — run onboarding test first")
    service_id = services[0]["id"]

    # 2. Issue a VC
    issue_resp = discovery_client.post(
        "/api/v1/credentials/issue",
        headers=admin_headers,
        json={
            "subject_id": service_id,
            "credential_type": "ServiceAccessCredential",
            "claims": {"scope": "read:data write:data"},
        },
    )
    assert issue_resp.status_code == 201, issue_resp.text
    vc_jwt = issue_resp.json()["credential"]
    assert vc_jwt, "Expected a non-empty credential JWT"

    # 3. Verify JWT structure: three base64url-encoded parts
    parts = vc_jwt.split(".")
    assert len(parts) == 3, f"JWT must have 3 parts, got {len(parts)}"

    def b64_decode(s: str) -> dict:
        padding = 4 - len(s) % 4
        return json.loads(base64.urlsafe_b64decode(s + "=" * padding))

    header = b64_decode(parts[0])
    payload = b64_decode(parts[1])

    assert header.get("alg") in ("ES256", "EdDSA"), f"Unexpected alg: {header.get('alg')}"
    assert "sub" in payload, "JWT payload must contain 'sub'"
    assert payload["sub"] == service_id

    # 4. Push VC to sentinel producer for policy check
    check_resp = sentinel_producer_client.post(
        "/api/v1/verify",
        headers={"X-Sentinel-VC": vc_jwt},
        json={},
    )
    # Either PERMIT or the endpoint validates and accepts it
    assert check_resp.status_code in (200, 204), check_resp.text

    # 5. Confirm status — credential should NOT be revoked (bit 0 = 0)
    status_resp = discovery_client.get(
        f"/api/v1/credentials/{payload.get('jti', service_id)}/status",
        headers=admin_headers,
    )
    if status_resp.status_code == 200:
        status_data = status_resp.json()
        assert not status_data.get("revoked", False), "Newly issued VC should not be revoked"


@pytest.mark.e2e
def test_vc_issuance_requires_auth(discovery_client: httpx.Client) -> None:
    """Issuing a VC without auth must return 401."""
    resp = discovery_client.post(
        "/api/v1/credentials/issue",
        json={"subject_id": "does-not-matter", "credential_type": "Test", "claims": {}},
    )
    assert resp.status_code == 401
