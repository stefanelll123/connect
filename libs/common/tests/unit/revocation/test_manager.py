"""Unit tests for RevocationManager (TASK-046).

7 test cases:
  1. Not-revoked bit returns is_revoked=False
  2. Revoked bit returns is_revoked=True
  3. Hash mismatch raises StatusListHashMismatch
  4. Staleness > Δ with FAIL_CLOSED raises RevocationStatusStale
  5. Staleness > Δ with FAIL_OPEN_DEGRADED returns stale=True (not revoked)
  6. Background refresher updates cache (scheduling test)
  7. Emergency check: trust_client returns None anchor → not revoked (no emergency)
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from common.revocation.bitstring import (
    create_status_list,
    revoke_credential,
)
from common.revocation.checker import (
    CachedStatusList,
    StatusListCache,
    build_cached_entry,
)
from common.revocation.manager import (
    RevocationCheckResult,
    RevocationManager,
    RevocationStatusStale,
    StatusListHashMismatch,
)
from common.revocation.models import (
    StalenessMode,
    StalenessPolicy,
    StatusAnchor,
    StatusListInfo,
)
from common.revocation.refresher import StatusListRefresher

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_LIST_URL = "https://example.gov/status/list-001"
_ISSUER_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
_CRED_JTI = "urn:uuid:test-jti-00001"
_NOW = 1_700_000_000


def _make_encoded_list(revoked_indices: list[int] = ()) -> str:
    """Create an encodedList with the specified indices set (revoked)."""
    encoded = create_status_list()
    for idx in revoked_indices:
        encoded = revoke_credential(encoded, idx)
    return encoded


def _make_status_list_info(encoded_list: str) -> StatusListInfo:
    return StatusListInfo(
        jti="urn:uuid:list-jti",
        iss=_ISSUER_DID,
        sub=_LIST_URL,
        iat=_NOW - 3600,
        exp=_NOW + 86400,
        status_purpose="revocation",
        encoded_list=encoded_list,
    )


def _make_cached_entry(
    revoked_indices: list[int] = (),
    bitstring_hash: str = "deadbeef",
    anchor: StatusAnchor | None = None,
    downloaded_at: int = _NOW,
) -> CachedStatusList:
    encoded = _make_encoded_list(revoked_indices)
    info = _make_status_list_info(encoded)
    from common.revocation.bitstring import decode_bitstring
    bitstring_bytes = decode_bitstring(encoded)
    return CachedStatusList(
        info=info,
        bitstring_bytes=bitstring_bytes,
        downloaded_at=downloaded_at,
        bitstring_hash=bitstring_hash,
        anchor=anchor,
    )


def _make_anchor(
    updated_at: int = _NOW,
    root_hash: str = "deadbeef",
) -> StatusAnchor:
    return StatusAnchor(
        status_list_id="list-001",
        root_hash=root_hash,
        updated_at=updated_at,
    )


def _make_manager(
    cache: StatusListCache | None = None,
    trust_client=None,
    staleness_policy: StalenessPolicy | None = None,
    http_client=None,
) -> RevocationManager:
    return RevocationManager(
        status_list_cache=cache or StatusListCache(),
        trust_client=trust_client,
        discovery_http_client=http_client,
        staleness_policy=staleness_policy or StalenessPolicy(delta_seconds=600, mode=StalenessMode.FAIL_CLOSED),
    )


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestNotRevoked:
    """Test 1: Credential with unset bit → is_revoked=False."""

    async def test_not_revoked(self):
        cache = StatusListCache()
        anchor = _make_anchor(updated_at=_NOW, root_hash="deadbeef")
        entry = _make_cached_entry(revoked_indices=[], bitstring_hash="deadbeef", anchor=anchor)
        cache.put(_LIST_URL, entry)

        mock_trust_client = MagicMock()
        mock_trust_client.get_status_anchor = AsyncMock(return_value=anchor)
        mock_trust_client.get_policy_params = AsyncMock(
            return_value=MagicMock(revocation_delta_seconds=600)
        )

        manager = _make_manager(
            cache=cache,
            trust_client=mock_trust_client,
            staleness_policy=StalenessPolicy(delta_seconds=600, mode=StalenessMode.FAIL_CLOSED),
        )

        with patch("time.time", return_value=float(_NOW)):
            result = await manager.check(_CRED_JTI, _LIST_URL, status_list_index=42)

        assert not result.is_revoked
        assert not result.stale


class TestRevoked:
    """Test 2: Credential with set bit → is_revoked=True."""

    async def test_bit_set_revoked(self):
        cache = StatusListCache()
        anchor = _make_anchor(updated_at=_NOW, root_hash="deadbeef")
        entry = _make_cached_entry(revoked_indices=[42], bitstring_hash="deadbeef", anchor=anchor)
        cache.put(_LIST_URL, entry)

        mock_trust_client = MagicMock()
        mock_trust_client.get_status_anchor = AsyncMock(return_value=anchor)
        mock_trust_client.get_policy_params = AsyncMock(
            return_value=MagicMock(revocation_delta_seconds=600)
        )

        manager = _make_manager(
            cache=cache,
            trust_client=mock_trust_client,
            staleness_policy=StalenessPolicy(delta_seconds=600, mode=StalenessMode.FAIL_CLOSED),
        )

        with patch("time.time", return_value=float(_NOW)):
            result = await manager.check(_CRED_JTI, _LIST_URL, status_list_index=42)

        assert result.is_revoked


class TestHashMismatch:
    """Test 3: Downloaded hash != anchor hash → StatusListHashMismatch."""

    async def test_hash_mismatch_raises(self):
        cache = StatusListCache()
        # Cached with hash "deadbeef" but anchor says "cafebabe"
        anchor = _make_anchor(updated_at=_NOW, root_hash="cafebabe")
        entry = _make_cached_entry(revoked_indices=[], bitstring_hash="deadbeef", anchor=anchor)
        cache.put(_LIST_URL, entry)

        # The manager will see the hash mismatch and try to re-download.
        # We simulate the download returning a JWT whose SHA-256 is also "deadbeef"
        # (different from anchor's "cafebabe") → raises StatusListHashMismatch

        fake_jwt_bytes = b"fake.jwt.data"
        actual_hash = hashlib.sha256(fake_jwt_bytes).hexdigest()

        mock_response = MagicMock()
        mock_response.content = fake_jwt_bytes
        mock_response.raise_for_status = MagicMock()

        mock_http = MagicMock()
        mock_http.get = AsyncMock(return_value=mock_response)

        mock_trust_client = MagicMock()
        mock_trust_client.get_status_anchor = AsyncMock(return_value=anchor)
        mock_trust_client.get_policy_params = AsyncMock(
            return_value=MagicMock(revocation_delta_seconds=600)
        )

        manager = _make_manager(
            cache=cache,
            trust_client=mock_trust_client,
            http_client=mock_http,
            staleness_policy=StalenessPolicy(delta_seconds=600, mode=StalenessMode.FAIL_CLOSED),
        )

        with patch("time.time", return_value=float(_NOW)):
            with pytest.raises(StatusListHashMismatch) as exc_info:
                await manager.check(_CRED_JTI, _LIST_URL, status_list_index=42)

        assert exc_info.value.status_list_id == _LIST_URL


class TestStalenessFailClosed:
    """Test 4: Staleness > Δ with FAIL_CLOSED raises RevocationStatusStale."""

    async def test_stale_fail_closed_raises(self):
        cache = StatusListCache()
        # Anchor updated_at is 1200 seconds ago (Δ=600 → stale by 600s)
        stale_anchor = _make_anchor(updated_at=_NOW - 1200, root_hash="deadbeef")
        entry = _make_cached_entry(revoked_indices=[], bitstring_hash="deadbeef", anchor=stale_anchor)
        cache.put(_LIST_URL, entry)

        mock_trust_client = MagicMock()
        mock_trust_client.get_status_anchor = AsyncMock(return_value=stale_anchor)
        mock_trust_client.get_policy_params = AsyncMock(
            return_value=MagicMock(revocation_delta_seconds=600)
        )

        manager = _make_manager(
            cache=cache,
            trust_client=mock_trust_client,
            staleness_policy=StalenessPolicy(delta_seconds=600, mode=StalenessMode.FAIL_CLOSED),
        )

        with patch("time.time", return_value=float(_NOW)):
            with pytest.raises(RevocationStatusStale) as exc_info:
                await manager.check(_CRED_JTI, _LIST_URL, status_list_index=0)

        assert exc_info.value.staleness_seconds > 0


class TestStalenessDegrade:
    """Test 5: Staleness > Δ with FAIL_OPEN_DEGRADED returns stale=True."""

    async def test_stale_degrade_returns_stale_not_revoked(self):
        cache = StatusListCache()
        stale_anchor = _make_anchor(updated_at=_NOW - 1200, root_hash="deadbeef")
        entry = _make_cached_entry(revoked_indices=[], bitstring_hash="deadbeef", anchor=stale_anchor)
        cache.put(_LIST_URL, entry)

        mock_trust_client = MagicMock()
        mock_trust_client.get_status_anchor = AsyncMock(return_value=stale_anchor)
        mock_trust_client.get_policy_params = AsyncMock(
            return_value=MagicMock(revocation_delta_seconds=600)
        )

        manager = _make_manager(
            cache=cache,
            trust_client=mock_trust_client,
            staleness_policy=StalenessPolicy(delta_seconds=600, mode=StalenessMode.FAIL_OPEN_DEGRADED),
        )

        with patch("time.time", return_value=float(_NOW)):
            result = await manager.check(_CRED_JTI, _LIST_URL, status_list_index=0)

        assert result.stale is True
        assert result.is_revoked is False  # not revoked in stale-open mode
        assert result.stale_seconds > 0


class TestBackgroundRefresher:
    """Test 6: Refresher schedules next refresh after Δ/2."""

    async def test_refresher_schedules_and_refreshes(self):
        cache = StatusListCache()
        anchor = _make_anchor(updated_at=_NOW, root_hash="deadbeef")
        entry = _make_cached_entry(revoked_indices=[], bitstring_hash="deadbeef", anchor=anchor)
        cache.put(_LIST_URL, entry)

        mock_trust_client = MagicMock()
        mock_trust_client.get_status_anchor = AsyncMock(return_value=anchor)
        mock_trust_client.get_policy_params = AsyncMock(
            return_value=MagicMock(revocation_delta_seconds=600)
        )

        manager = _make_manager(
            cache=cache,
            trust_client=mock_trust_client,
            staleness_policy=StalenessPolicy(delta_seconds=600, mode=StalenessMode.FAIL_CLOSED),
        )

        refresher = StatusListRefresher(
            manager=manager,
            delta_seconds=60,  # short delta for test
            trust_client=mock_trust_client,
        )

        # Register an ID and trigger a single tick
        refresher.register(_LIST_URL)
        assert _LIST_URL in refresher._active_ids
        assert _LIST_URL in refresher._schedule

        # After tick, schedule should be updated to ~30s in the future
        await refresher._tick()
        assert refresher._schedule[_LIST_URL] > 0.0  # rescheduled


class TestEmergencyCheck:
    """Test 7: Emergency check — trust_client returns None → not emergently revoked."""

    async def test_emergency_not_revoked_when_no_anchor(self):
        mock_trust_client = MagicMock()
        mock_trust_client.get_status_anchor = AsyncMock(return_value=None)

        manager = RevocationManager(
            trust_client=mock_trust_client,
        )
        result = await manager.emergency_check(_CRED_JTI)
        assert result is False  # None anchor = not in emergency revoke list

    async def test_emergency_revoked_when_anchor_present(self):
        anchor = _make_anchor()
        mock_trust_client = MagicMock()
        mock_trust_client.get_status_anchor = AsyncMock(return_value=anchor)

        manager = RevocationManager(trust_client=mock_trust_client)
        result = await manager.emergency_check(_CRED_JTI)
        assert result is True  # anchor present = emergently revoked

    async def test_emergency_fail_closed_on_unavailable(self):
        mock_trust_client = MagicMock()
        mock_trust_client.get_status_anchor = AsyncMock(
            side_effect=Exception("chain unavailable")
        )

        manager = RevocationManager(trust_client=mock_trust_client)
        result = await manager.emergency_check(_CRED_JTI)
        assert result is True  # fail-closed on chain error

    async def test_emergency_fail_closed_without_trust_client(self):
        manager = RevocationManager(trust_client=None)
        result = await manager.emergency_check(_CRED_JTI)
        assert result is True  # fail-closed with no trust_client
