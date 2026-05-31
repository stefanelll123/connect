"""TASK-040 unit tests: Discovery Client."""
from __future__ import annotations

import asyncio
import base64
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_jwt(exp_offset: int = 3600) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) + exp_offset, "sub": "sentinel-id"}).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


def _make_http_response(status_code: int, body: dict | None = None, headers: dict | None = None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = json.dumps(body or {})
    resp.headers = MagicMock()
    resp.headers.get = MagicMock(return_value=headers.get("ETag", "") if headers else "")
    resp.json = MagicMock(return_value=body or {})
    resp.request = MagicMock()
    return resp


# ---------------------------------------------------------------------------
# TokenManager
# ---------------------------------------------------------------------------

class TestTokenManager:
    def test_get_returns_none_before_set(self):
        from sentinel.clients.auth_token import TokenManager
        tm = TokenManager()
        assert tm.get() is None

    def test_set_and_get(self):
        from sentinel.clients.auth_token import TokenManager
        tm = TokenManager()
        jwt = _make_jwt(3600)
        tm.set(jwt)
        assert tm.get() == jwt

    def test_expired_token_returns_none(self):
        from sentinel.clients.auth_token import TokenManager
        tm = TokenManager()
        expired = _make_jwt(-100)  # already expired
        tm.set(expired)
        assert tm.get() is None

    def test_needs_renewal_when_expiring_soon(self):
        from sentinel.clients.auth_token import TokenManager
        tm = TokenManager()
        soon = _make_jwt(100)  # expires in 100s, buffer is 300s → needs renewal
        tm.set(soon)
        assert tm.needs_renewal() is True

    def test_no_renewal_needed_for_fresh_token(self):
        from sentinel.clients.auth_token import TokenManager
        tm = TokenManager()
        fresh = _make_jwt(7200)
        tm.set(fresh)
        assert tm.needs_renewal() is False


# ---------------------------------------------------------------------------
# RetryWithBackoff
# ---------------------------------------------------------------------------

class TestRetryWithBackoff:
    @pytest.mark.asyncio
    async def test_succeeds_on_first_attempt(self):
        from sentinel.clients.ds_client import RetryWithBackoff
        import httpx

        retry = RetryWithBackoff(max_attempts=3)
        call_count = 0

        async def flaky():
            nonlocal call_count
            call_count += 1
            return "ok"

        result = await retry.run(flaky)
        assert result == "ok"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retries_on_http_error(self):
        from sentinel.clients.ds_client import RetryWithBackoff
        import httpx

        retry = RetryWithBackoff(max_attempts=3, base_delay=0.0)
        call_count = 0

        async def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.ConnectError("refused")
            return "ok"

        result = await retry.run(flaky)
        assert result == "ok"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_raises_after_max_attempts(self):
        from sentinel.clients.ds_client import RetryWithBackoff
        import httpx

        retry = RetryWithBackoff(max_attempts=2, base_delay=0.0)

        async def always_fail():
            raise httpx.ConnectError("down")

        with pytest.raises(httpx.ConnectError):
            await retry.run(always_fail)


# ---------------------------------------------------------------------------
# CircuitBreaker
# ---------------------------------------------------------------------------

class TestCircuitBreaker:
    def test_starts_closed(self):
        from sentinel.clients.ds_client import CircuitBreaker
        cb = CircuitBreaker()
        assert cb.state == CircuitBreaker.CLOSED
        assert cb.allow_request() is True

    def test_opens_after_fail_max(self):
        from sentinel.clients.ds_client import CircuitBreaker
        cb = CircuitBreaker(fail_max=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitBreaker.OPEN
        assert cb.allow_request() is False

    def test_closes_after_success(self):
        from sentinel.clients.ds_client import CircuitBreaker
        cb = CircuitBreaker(fail_max=2)
        cb.record_failure()
        cb.record_failure()
        assert cb.is_open()
        cb._state = CircuitBreaker.HALF_OPEN  # simulate timeout
        cb.record_success()
        assert cb.state == CircuitBreaker.CLOSED

    def test_transitions_to_half_open_after_timeout(self):
        from sentinel.clients.ds_client import CircuitBreaker
        cb = CircuitBreaker(fail_max=1, reset_timeout=0.01)
        cb.record_failure()
        assert cb.is_open()
        import time
        time.sleep(0.02)
        assert cb.state == CircuitBreaker.HALF_OPEN


# ---------------------------------------------------------------------------
# DiscoveryClient
# ---------------------------------------------------------------------------

class TestDiscoveryClientOnboard:
    @pytest.mark.asyncio
    async def test_onboard_success(self):
        from sentinel.clients.ds_client import DiscoveryClient

        mock_http = AsyncMock()
        auth_token = _make_jwt(86400)

        phase1_resp = _make_http_response(200, {"challenge_nonce": "nonce123", "jti": "jti-abc"})
        phase2_resp = _make_http_response(201, {
            "sentinel_id": "s-001",
            "access_token": auth_token,
            "discovery_endpoints": {"config": "/config"},
            "chain_addresses": {},
            "credentials": [],
            "etag": "etag-v1",
        })
        mock_http.post = AsyncMock(side_effect=[phase1_resp, phase2_resp])

        client = DiscoveryClient("http://ds:8000", http_client=mock_http)
        bundle = await client.onboard("enroll-token-abc")

        assert bundle.sentinel_id == "s-001"
        assert bundle.auth_token == auth_token
        assert client.sentinel_id == "s-001"

    @pytest.mark.asyncio
    async def test_onboard_409_falls_back_to_config(self):
        from sentinel.clients.ds_client import DiscoveryClient

        mock_http = AsyncMock()
        conflict_resp = _make_http_response(409, {"detail": "ENROLLMENT_ALREADY_CONSUMED"})
        config_resp = _make_http_response(304, None)
        mock_http.post = AsyncMock(return_value=conflict_resp)
        mock_http.get = AsyncMock(return_value=config_resp)

        client = DiscoveryClient("http://ds:8000", sentinel_id="s-001", http_client=mock_http)
        bundle = await client.onboard("old-token")
        assert bundle.sentinel_id == "s-001"


class TestDiscoveryClientSync:
    @pytest.mark.asyncio
    async def test_sync_config_304_returns_false(self):
        from sentinel.clients.ds_client import DiscoveryClient

        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=_make_http_response(304))
        client = DiscoveryClient("http://ds:8000", sentinel_id="s-001", http_client=mock_http)
        result = await client.sync_config()
        assert result is False

    @pytest.mark.asyncio
    async def test_sync_config_200_returns_true(self):
        from sentinel.clients.ds_client import DiscoveryClient

        mock_http = AsyncMock()
        config_resp = _make_http_response(200, {"bundle": {}}, {"ETag": "new-etag"})
        mock_http.get = AsyncMock(return_value=config_resp)
        client = DiscoveryClient("http://ds:8000", sentinel_id="s-001", http_client=mock_http)
        result = await client.sync_config()
        assert result is True

    @pytest.mark.asyncio
    async def test_sync_credentials_counts_valid(self):
        from sentinel.clients.ds_client import DiscoveryClient

        mock_http = AsyncMock()
        cred_jwt = _make_jwt(3600)
        creds_resp = _make_http_response(200, {"credentials": [cred_jwt]})
        mock_http.get = AsyncMock(return_value=creds_resp)
        client = DiscoveryClient("http://ds:8000", sentinel_id="s-001", http_client=mock_http)
        count = await client.sync_credentials()
        assert count == 1

    @pytest.mark.asyncio
    async def test_sync_credentials_skips_expired(self):
        from sentinel.clients.ds_client import DiscoveryClient

        mock_http = AsyncMock()
        expired_jwt = _make_jwt(-100)
        creds_resp = _make_http_response(200, {"credentials": [expired_jwt]})
        mock_http.get = AsyncMock(return_value=creds_resp)
        client = DiscoveryClient("http://ds:8000", sentinel_id="s-001", http_client=mock_http)
        count = await client.sync_credentials()
        assert count == 0


class TestDiscoveryClientHeartbeat:
    @pytest.mark.asyncio
    async def test_heartbeat_increments_missed_on_error(self):
        from sentinel.clients.ds_client import DiscoveryClient
        import httpx

        mock_http = AsyncMock()
        mock_http.post = AsyncMock(side_effect=httpx.ConnectError("down"))
        client = DiscoveryClient("http://ds:8000", sentinel_id="s-001", http_client=mock_http)
        # disable retries to keep test fast
        client._retry.max_attempts = 1
        client._circuit._state = "closed"
        client._circuit.fail_max = 100  # don't open circuit mid-test

        # 6 failed heartbeats should trigger CRITICAL
        with patch("sentinel.clients.ds_client.logger") as mock_log:
            for _ in range(6):
                await client.send_heartbeat("inst-1", "1.0.0", {})
            assert any(
                call[0][0] == "Discovery unreachable: %d consecutive missed heartbeats"
                for call in mock_log.critical.call_args_list
            )

    @pytest.mark.asyncio
    async def test_heartbeat_resets_missed_on_success(self):
        from sentinel.clients.ds_client import DiscoveryClient

        mock_http = AsyncMock()
        ok_resp = _make_http_response(200)
        mock_http.post = AsyncMock(return_value=ok_resp)
        client = DiscoveryClient("http://ds:8000", sentinel_id="s-001", http_client=mock_http)
        client._missed_heartbeats = 3
        await client.send_heartbeat("inst-1", "1.0.0", {})
        assert client._missed_heartbeats == 0
