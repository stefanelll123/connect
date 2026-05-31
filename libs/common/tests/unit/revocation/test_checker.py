"""Unit tests for common.revocation.checker."""

from __future__ import annotations

import hashlib

import pytest

from common.revocation.bitstring import create_status_list, revoke_credential
from common.revocation.checker import (
    CachedStatusList,
    StatusListCache,
    build_cached_entry,
    check_credential_status,
    hash_jti,
)
from common.revocation.models import (
    CredentialStatusEntry,
    StalenessMode,
    StalenessPolicy,
    StatusAnchor,
    StatusCheckResult,
    StatusListInfo,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

_LIST_URL = "https://example.gov/status/list-001"
_JTI = "urn:uuid:test-jti-0001"
_ISSUER_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
_NOW = 1_700_000_000


def _make_status_entry(index: int = 42, url: str = _LIST_URL) -> CredentialStatusEntry:
    return CredentialStatusEntry(
        id=f"{url}#{index}",
        type="BitstringStatusListEntry",
        statusListIndex=str(index),
        statusListCredential=url,
        statusPurpose="revocation",
    )


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


def _make_cached(
    encoded_list: str,
    downloaded_at: int = _NOW,
    bitstring_hash: str = "aabbcc",
    anchor: StatusAnchor | None = None,
) -> CachedStatusList:
    from common.revocation.bitstring import decode_bitstring

    info = _make_status_list_info(encoded_list)
    return CachedStatusList(
        info=info,
        bitstring_bytes=decode_bitstring(encoded_list),
        downloaded_at=downloaded_at,
        bitstring_hash=bitstring_hash,
        anchor=anchor,
    )


_FRESH_POLICY = StalenessPolicy(delta_seconds=600, mode=StalenessMode.FAIL_CLOSED)
_FAIL_OPEN_POLICY = StalenessPolicy(delta_seconds=600, mode=StalenessMode.FAIL_OPEN_DEGRADED)
_ALLOW_POLICY = StalenessPolicy(delta_seconds=600, mode=StalenessMode.ALLOW_WITH_WARNING)


# ---------------------------------------------------------------------------
# TestHashJti
# ---------------------------------------------------------------------------


class TestHashJti:
    def test_known_value(self) -> None:
        jti = "urn:uuid:test"
        expected = hashlib.sha256(jti.encode()).hexdigest()
        assert hash_jti(jti) == expected

    def test_is_hex_string(self) -> None:
        result = hash_jti("some-jti")
        int(result, 16)  # should not raise

    def test_deterministic(self) -> None:
        assert hash_jti("x") == hash_jti("x")

    def test_different_jtis_produce_different_hashes(self) -> None:
        assert hash_jti("a") != hash_jti("b")


# ---------------------------------------------------------------------------
# TestStatusListCache
# ---------------------------------------------------------------------------


class TestStatusListCache:
    def test_get_missing_returns_none(self) -> None:
        cache = StatusListCache()
        assert cache.get("https://not-there") is None

    def test_put_and_get(self) -> None:
        cache = StatusListCache()
        entry = _make_cached(create_status_list())
        cache.put(_LIST_URL, entry)
        assert cache.get(_LIST_URL) is entry

    def test_put_replaces_existing(self) -> None:
        cache = StatusListCache()
        entry1 = _make_cached(create_status_list(), downloaded_at=100)
        entry2 = _make_cached(create_status_list(), downloaded_at=200)
        cache.put(_LIST_URL, entry1)
        cache.put(_LIST_URL, entry2)
        assert cache.get(_LIST_URL) is entry2

    def test_invalidate_removes_entry(self) -> None:
        cache = StatusListCache()
        cache.put(_LIST_URL, _make_cached(create_status_list()))
        cache.invalidate(_LIST_URL)
        assert cache.get(_LIST_URL) is None

    def test_invalidate_missing_is_noop(self) -> None:
        cache = StatusListCache()
        cache.invalidate("https://not-there")  # should not raise

    def test_size(self) -> None:
        cache = StatusListCache()
        assert cache.size() == 0
        cache.put(_LIST_URL, _make_cached(create_status_list()))
        assert cache.size() == 1


# ---------------------------------------------------------------------------
# TestCheckCredentialStatus
# ---------------------------------------------------------------------------


class TestCheckCredentialStatus:
    # --- Happy path ---

    def test_not_revoked(self) -> None:
        cache = StatusListCache()
        encoded = create_status_list()
        cache.put(_LIST_URL, _make_cached(encoded, downloaded_at=_NOW))
        entry = _make_status_entry(42)
        result = check_credential_status(
            entry, cache=cache, policy=_FRESH_POLICY, now=_NOW
        )
        assert result == StatusCheckResult.NOT_REVOKED

    def test_revoked(self) -> None:
        cache = StatusListCache()
        encoded = revoke_credential(create_status_list(), 42)
        cache.put(_LIST_URL, _make_cached(encoded, downloaded_at=_NOW))
        entry = _make_status_entry(42)
        result = check_credential_status(
            entry, cache=cache, policy=_FRESH_POLICY, now=_NOW
        )
        assert result == StatusCheckResult.REVOKED

    # --- Emergency revocation ---

    def test_emergency_revoked(self) -> None:
        cache = StatusListCache()
        encoded = create_status_list()  # bit NOT set in list
        cache.put(_LIST_URL, _make_cached(encoded, downloaded_at=_NOW))
        entry = _make_status_entry(42)
        jti_hash = hash_jti(_JTI)
        result = check_credential_status(
            entry,
            cache=cache,
            policy=_FRESH_POLICY,
            credential_jti=_JTI,
            emergency_revoked=frozenset([jti_hash]),
            now=_NOW,
        )
        assert result == StatusCheckResult.EMERGENCY_REVOKED

    def test_no_emergency_revoke_when_jti_not_matching(self) -> None:
        cache = StatusListCache()
        encoded = create_status_list()
        cache.put(_LIST_URL, _make_cached(encoded, downloaded_at=_NOW))
        entry = _make_status_entry(42)
        other_hash = hash_jti("other-jti")
        result = check_credential_status(
            entry,
            cache=cache,
            policy=_FRESH_POLICY,
            credential_jti=_JTI,
            emergency_revoked=frozenset([other_hash]),
            now=_NOW,
        )
        assert result == StatusCheckResult.NOT_REVOKED

    def test_no_emergency_check_when_jti_none(self) -> None:
        cache = StatusListCache()
        encoded = create_status_list()
        cache.put(_LIST_URL, _make_cached(encoded, downloaded_at=_NOW))
        entry = _make_status_entry(42)
        # Provide emergency_revoked set but no jti — should not emergency-revoke
        result = check_credential_status(
            entry,
            cache=cache,
            policy=_FRESH_POLICY,
            credential_jti=None,
            emergency_revoked=frozenset([hash_jti("any")]),
            now=_NOW,
        )
        assert result == StatusCheckResult.NOT_REVOKED

    # --- Cache miss ---

    def test_cache_miss_fail_closed(self) -> None:
        cache = StatusListCache()
        entry = _make_status_entry(42)
        result = check_credential_status(
            entry, cache=cache, policy=_FRESH_POLICY, now=_NOW
        )
        assert result == StatusCheckResult.STALE_FAIL_CLOSED

    def test_cache_miss_fail_open_degraded(self) -> None:
        cache = StatusListCache()
        entry = _make_status_entry(42)
        result = check_credential_status(
            entry, cache=cache, policy=_FAIL_OPEN_POLICY, now=_NOW
        )
        assert result == StatusCheckResult.LIST_UNAVAILABLE

    def test_cache_miss_allow_with_warning(self) -> None:
        cache = StatusListCache()
        entry = _make_status_entry(42)
        result = check_credential_status(
            entry, cache=cache, policy=_ALLOW_POLICY, now=_NOW
        )
        assert result == StatusCheckResult.LIST_UNAVAILABLE

    # --- Staleness ---

    def test_stale_fail_closed_rejects(self) -> None:
        cache = StatusListCache()
        encoded = create_status_list()
        # downloaded 601 seconds before now → stale
        cache.put(_LIST_URL, _make_cached(encoded, downloaded_at=_NOW - 601))
        entry = _make_status_entry(42)
        result = check_credential_status(
            entry, cache=cache, policy=_FRESH_POLICY, now=_NOW
        )
        assert result == StatusCheckResult.STALE_FAIL_CLOSED

    def test_stale_fail_open_degraded_continues(self) -> None:
        cache = StatusListCache()
        encoded = create_status_list()
        cache.put(_LIST_URL, _make_cached(encoded, downloaded_at=_NOW - 601))
        entry = _make_status_entry(42)
        result = check_credential_status(
            entry, cache=cache, policy=_FAIL_OPEN_POLICY, now=_NOW
        )
        # Continues with stale data — bit is 0 → NOT_REVOKED
        assert result == StatusCheckResult.NOT_REVOKED

    def test_stale_allow_with_warning_continues(self) -> None:
        cache = StatusListCache()
        encoded = revoke_credential(create_status_list(), 42)
        cache.put(_LIST_URL, _make_cached(encoded, downloaded_at=_NOW - 601))
        entry = _make_status_entry(42)
        result = check_credential_status(
            entry, cache=cache, policy=_ALLOW_POLICY, now=_NOW
        )
        # Continues with stale data — bit is 1 → REVOKED
        assert result == StatusCheckResult.REVOKED

    def test_just_within_delta_not_stale(self) -> None:
        cache = StatusListCache()
        encoded = create_status_list()
        # downloaded exactly delta_seconds ago — not yet stale (age == delta is ok)
        cache.put(_LIST_URL, _make_cached(encoded, downloaded_at=_NOW - 600))
        entry = _make_status_entry(42)
        result = check_credential_status(
            entry, cache=cache, policy=_FRESH_POLICY, now=_NOW
        )
        assert result == StatusCheckResult.NOT_REVOKED

    # --- Anchor verification ---

    def test_hash_mismatch(self) -> None:
        cache = StatusListCache()
        encoded = create_status_list()
        cache.put(_LIST_URL, _make_cached(encoded, downloaded_at=_NOW, bitstring_hash="aabbcc"))
        entry = _make_status_entry(42)
        anchor = StatusAnchor(
            status_list_id="0x1234",
            root_hash="different-hash",
            updated_at=_NOW,
        )
        result = check_credential_status(
            entry,
            cache=cache,
            policy=_FRESH_POLICY,
            expected_anchor=anchor,
            now=_NOW,
        )
        assert result == StatusCheckResult.HASH_MISMATCH

    def test_hash_match_continues(self) -> None:
        cache = StatusListCache()
        encoded = create_status_list()
        cache.put(_LIST_URL, _make_cached(encoded, downloaded_at=_NOW, bitstring_hash="aabbcc"))
        entry = _make_status_entry(42)
        anchor = StatusAnchor(
            status_list_id="0x1234",
            root_hash="aabbcc",  # matches
            updated_at=_NOW,
        )
        result = check_credential_status(
            entry,
            cache=cache,
            policy=_FRESH_POLICY,
            expected_anchor=anchor,
            now=_NOW,
        )
        assert result == StatusCheckResult.NOT_REVOKED

    # --- Index bounds ---

    def test_index_out_of_range(self) -> None:
        cache = StatusListCache()
        encoded = create_status_list()
        cache.put(_LIST_URL, _make_cached(encoded, downloaded_at=_NOW))
        # Index beyond 131_072 bits
        entry = _make_status_entry(index=200_000)
        result = check_credential_status(
            entry, cache=cache, policy=_FRESH_POLICY, now=_NOW
        )
        assert result == StatusCheckResult.INDEX_OUT_OF_RANGE


# ---------------------------------------------------------------------------
# TestBuildCachedEntry
# ---------------------------------------------------------------------------


class TestBuildCachedEntry:
    def test_bitstring_hash_is_hex_sha256(self) -> None:
        from common.revocation.bitstring import decode_bitstring
        encoded = create_status_list()
        bitstring_bytes = decode_bitstring(encoded)
        expected = hashlib.sha256(bitstring_bytes).hexdigest()
        info = _make_status_list_info(encoded)
        entry = build_cached_entry(info, raw_jwt_bytes=b"irrelevant")
        assert entry.bitstring_hash == expected

    def test_bitstring_bytes_decoded(self) -> None:
        from common.revocation.bitstring import decode_bitstring

        encoded = create_status_list()
        info = _make_status_list_info(encoded)
        entry = build_cached_entry(info, raw_jwt_bytes=b"jwt")
        assert entry.bitstring_bytes == decode_bitstring(encoded)

    def test_downloaded_at_uses_now_override(self) -> None:
        info = _make_status_list_info(create_status_list())
        entry = build_cached_entry(info, raw_jwt_bytes=b"jwt", now=_NOW)
        assert entry.downloaded_at == _NOW

    def test_anchor_stored(self) -> None:
        anchor = StatusAnchor(
            status_list_id="0x1234", root_hash="abc", updated_at=_NOW
        )
        info = _make_status_list_info(create_status_list())
        entry = build_cached_entry(info, raw_jwt_bytes=b"jwt", anchor=anchor, now=_NOW)
        assert entry.anchor is anchor

    def test_no_anchor_by_default(self) -> None:
        info = _make_status_list_info(create_status_list())
        entry = build_cached_entry(info, raw_jwt_bytes=b"jwt", now=_NOW)
        assert entry.anchor is None
