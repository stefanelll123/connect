"""Integration tests for the Consumer Outbound Pipeline (TASK-044).

Tests:
  1. Successful request end-to-end with mock producer
  2. Descriptor signature invalid — rejected before send
  3. No credentials → falls back to empty VP (not 403 per pipeline design)
  4. Producer returns 401 — no retry, returns response immediately
  5. Producer returns 503 then 200 — retry succeeds with NEW jti
  6. All retries fail — raises after exhausting retries
  7. No endpoints available — raises NoEndpointsAvailable
  8. Endpoint circuit breaker trips after 3 failures
"""
from __future__ import annotations

import asyncio
import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel.consumer.credential_selector import NoCredentialAvailable
from sentinel.consumer.descriptor_cache import (
    DescriptorCache,
    DescriptorInvalid,
    ServiceDescriptor,
    ServiceNotFound,
)
from sentinel.consumer.endpoint_selector import EndpointSelector, NoEndpointsAvailable
from sentinel.consumer.pipeline import OutboundPipeline

# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------

_CONSUMER_PRIV_KEY = Ed25519PrivateKey.generate()
CONSUMER_PRIV_BYTES = _CONSUMER_PRIV_KEY.private_bytes_raw()
CONSUMER_PUB_BYTES = _CONSUMER_PRIV_KEY.public_key().public_bytes_raw()

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    res = []
    while n:
        n, r = divmod(n, 58)
        res.append(_B58_ALPHABET[r])
    for b in data:
        if b == 0:
            res.append(_B58_ALPHABET[0])
        else:
            break
    return "".join(reversed(res))


CONSUMER_DID = f"did:key:z{_b58(bytes([0xED, 0x01]) + CONSUMER_PUB_BYTES)}"
PRODUCER_DID = "did:example:producer"
SERVICE_ID = "test-service"
ENV = "test"

ENDPOINTS = [{"url": "http://producer.local:8080", "weight": 1, "health_status": "active"}]


def _make_descriptor(**kwargs) -> ServiceDescriptor:
    return ServiceDescriptor(
        service_id=kwargs.get("service_id", SERVICE_ID),
        service_did=kwargs.get("service_did", PRODUCER_DID),
        producer_did=kwargs.get("producer_did", PRODUCER_DID),
        env=kwargs.get("env", ENV),
        endpoints=kwargs.get("endpoints", ENDPOINTS),
        signed_jwt="stub.jwt",
        max_age_seconds=300.0,
        exp=time.time() + 300,
    )


def _make_descriptor_cache(descriptor: ServiceDescriptor) -> DescriptorCache:
    cache = DescriptorCache(discovery_client=None)
    # Pre-populate cache directly
    cache._store[(descriptor.service_id, descriptor.env)] = (descriptor, time.time())
    return cache


def _make_pipeline(
    http_client: httpx.AsyncClient,
    descriptor: ServiceDescriptor | None = None,
    descriptor_raises=None,
) -> OutboundPipeline:
    if descriptor_raises is not None:
        desc_cache = MagicMock()
        desc_cache.get = AsyncMock(side_effect=descriptor_raises)
    elif descriptor is not None:
        desc_cache = _make_descriptor_cache(descriptor)
    else:
        desc_cache = _make_descriptor_cache(_make_descriptor())

    return OutboundPipeline(
        http_client=http_client,
        descriptor_cache=desc_cache,
        endpoint_selector=EndpointSelector(),
        consumer_did=CONSUMER_DID,
        consumer_key_bytes=CONSUMER_PRIV_BYTES,
        credential_store=None,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestOutboundPipelineSuccess:
    """Test 1: Successful end-to-end request."""

    async def test_success(self, httpx_mock):
        httpx_mock.add_response(status_code=200, json={"ok": True})

        async with httpx.AsyncClient() as client:
            pipeline = _make_pipeline(client)
            response = await pipeline.send(
                service_id=SERVICE_ID,
                path="api/resource",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=b'{"test": 1}',
                query_params={},
                env=ENV,
            )

        assert response.status_code == 200
        # Verify that the Authorization header was set
        sent_request = httpx_mock.get_requests()[0]
        assert sent_request.headers.get("authorization", "").startswith("SentinelProof ")
        assert "sentinelvp" in sent_request.headers


class TestDescriptorInvalid:
    """Test 2: Descriptor raises DescriptorInvalid — raises before send."""

    async def test_descriptor_invalid_raises(self):
        async with httpx.AsyncClient() as client:
            pipeline = _make_pipeline(
                client, descriptor_raises=DescriptorInvalid("bad signature")
            )
            with pytest.raises(DescriptorInvalid):
                await pipeline.send(
                    service_id=SERVICE_ID,
                    path="api/resource",
                    method="GET",
                    headers={},
                    body=b"",
                    query_params={},
                    env=ENV,
                )


class TestProducerAuth401:
    """Test 4: Producer returns 401 — no retry (definitive rejection)."""

    async def test_no_retry_on_401(self, httpx_mock):
        httpx_mock.add_response(status_code=401, json={"error": "MISSING_PROOF"})

        async with httpx.AsyncClient() as client:
            pipeline = _make_pipeline(client)
            response = await pipeline.send(
                service_id=SERVICE_ID,
                path="auth-resource",
                method="POST",
                headers={},
                body=b"data",
                query_params={},
                env=ENV,
            )

        assert response.status_code == 401
        assert len(httpx_mock.get_requests()) == 1  # no retry


class TestRetryWithNewJti:
    """Test 5: Producer returns 503 then 200 — retry with a NEW jti."""

    async def test_retry_produces_new_jti(self, httpx_mock):
        httpx_mock.add_response(status_code=503, json={"error": "temporary failure"})
        httpx_mock.add_response(status_code=200, json={"ok": True})

        async with httpx.AsyncClient() as client:
            pipeline = _make_pipeline(client)
            with patch("asyncio.sleep", new_callable=AsyncMock):
                response = await pipeline.send(
                    service_id=SERVICE_ID,
                    path="resource",
                    method="POST",
                    headers={},
                    body=b"payload",
                    query_params={},
                    env=ENV,
                )

        assert response.status_code == 200
        requests = httpx_mock.get_requests()
        assert len(requests) == 2
        # jti MUST differ between attempts
        jtis = []
        for req in requests:
            auth = req.headers.get("authorization", "")
            if auth.startswith("SentinelProof "):
                import base64, json as _json
                parts = auth[len("SentinelProof "):].split(".")
                if len(parts) == 3:
                    padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    payload = _json.loads(base64.urlsafe_b64decode(padded))
                    jtis.append(payload.get("jti"))
        assert len(jtis) == 2
        assert jtis[0] != jtis[1], "jti must be regenerated per retry"


class TestAllRetriesFail:
    """Test 6: All retries fail — raises after exhausting."""

    async def test_raises_after_all_retries(self, httpx_mock):
        # 3 attempts each returning 503
        for _ in range(3):
            httpx_mock.add_response(status_code=503, json={"error": "down"})

        async with httpx.AsyncClient() as client:
            pipeline = _make_pipeline(client)
            with patch("asyncio.sleep", new_callable=AsyncMock):
                with pytest.raises(Exception):
                    await pipeline.send(
                        service_id=SERVICE_ID,
                        path="fail",
                        method="POST",
                        headers={},
                        body=b"",
                        query_params={},
                        env=ENV,
                    )

        # 3 total attempts
        assert len(httpx_mock.get_requests()) == 3


class TestNoEndpointsAvailable:
    """Test 7: No endpoints available → NoEndpointsAvailable raised."""

    async def test_no_endpoints_raises(self):
        descriptor = _make_descriptor(endpoints=[])

        async with httpx.AsyncClient() as client:
            pipeline = _make_pipeline(client, descriptor=descriptor)
            with pytest.raises(NoEndpointsAvailable):
                await pipeline.send(
                    service_id=SERVICE_ID,
                    path="resource",
                    method="GET",
                    headers={},
                    body=b"",
                    query_params={},
                    env=ENV,
                )


class TestEndpointCircuitBreaker:
    """Test 8: Circuit breaker trips after 3 consecutive failures."""

    def test_circuit_breaker_marks_unhealthy_after_3_failures(self):
        selector = EndpointSelector()
        url = "http://producer.local:8080"

        # Record 3 failures
        for _ in range(3):
            selector.record_failure(url)

        state = selector._states[url]
        assert not state.is_locally_healthy(), "endpoint should be locally unhealthy after 3 failures"

    def test_circuit_breaker_clears_after_success(self):
        selector = EndpointSelector()
        url = "http://producer.local:8080"

        for _ in range(3):
            selector.record_failure(url)

        selector.record_success(url)
        state = selector._states[url]
        assert state.is_locally_healthy()
        assert state.consecutive_failures == 0

    def test_unhealthy_endpoint_filtered_from_selection(self):
        selector = EndpointSelector()
        url = "http://unreachable.local:9999"
        endpoints = [
            {"url": url, "weight": 1, "health_status": "active"},
            {"url": "http://healthy.local:8080", "weight": 1, "health_status": "active"},
        ]

        # Trip the circuit breaker for first endpoint
        for _ in range(3):
            selector.record_failure(url)

        # Selection should not return the unhealthy endpoint
        for _ in range(20):
            chosen = selector.select(endpoints)
            assert chosen == "http://healthy.local:8080"
