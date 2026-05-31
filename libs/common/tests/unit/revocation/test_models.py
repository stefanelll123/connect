"""Unit tests for common.revocation.models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from common.revocation.models import (
    CredentialStatusEntry,
    StatusAnchor,
    StatusCheckResult,
    StatusListInfo,
    StalenessMode,
    StalenessPolicy,
    default_policy_for_env,
)
from common.revocation.bitstring import create_status_list

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

_VALID_STATUS_ENTRY: dict = {
    "id": "https://example.gov/status/list-001#42",
    "type": "BitstringStatusListEntry",
    "statusListIndex": "42",
    "statusListCredential": "https://example.gov/status/list-001",
    "statusPurpose": "revocation",
}

_VALID_JWT_CLAIMS: dict = {
    "jti": "urn:uuid:abc123",
    "iss": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "sub": "https://example.gov/status/list-001",
    "iat": 1_700_000_000,
    "exp": 1_700_086_400,
    "vc": {
        "credentialSubject": {
            "statusPurpose": "revocation",
            "encodedList": create_status_list(),
        }
    },
}


# ---------------------------------------------------------------------------
# TestCredentialStatusEntry
# ---------------------------------------------------------------------------


class TestCredentialStatusEntry:
    def test_valid_entry(self) -> None:
        entry = CredentialStatusEntry(**_VALID_STATUS_ENTRY)
        assert entry.statusListIndex == "42"
        assert entry.statusListCredential == "https://example.gov/status/list-001"

    def test_index_property(self) -> None:
        entry = CredentialStatusEntry(**_VALID_STATUS_ENTRY)
        assert entry.index == 42

    def test_default_type(self) -> None:
        data = dict(_VALID_STATUS_ENTRY)
        del data["type"]
        entry = CredentialStatusEntry(**data)
        assert entry.type == "BitstringStatusListEntry"

    def test_default_status_purpose(self) -> None:
        data = dict(_VALID_STATUS_ENTRY)
        del data["statusPurpose"]
        entry = CredentialStatusEntry(**data)
        assert entry.statusPurpose == "revocation"

    def test_invalid_non_numeric_index(self) -> None:
        data = dict(_VALID_STATUS_ENTRY)
        data["statusListIndex"] = "abc"
        with pytest.raises(ValidationError):
            CredentialStatusEntry(**data)

    def test_invalid_negative_index(self) -> None:
        data = dict(_VALID_STATUS_ENTRY)
        data["statusListIndex"] = "-1"
        with pytest.raises(ValidationError):
            CredentialStatusEntry(**data)

    def test_invalid_type(self) -> None:
        data = dict(_VALID_STATUS_ENTRY)
        data["type"] = "SomethingElse"
        with pytest.raises(ValidationError):
            CredentialStatusEntry(**data)

    def test_invalid_status_purpose(self) -> None:
        data = dict(_VALID_STATUS_ENTRY)
        data["statusPurpose"] = "expiry"
        with pytest.raises(ValidationError):
            CredentialStatusEntry(**data)

    def test_frozen_cannot_reassign(self) -> None:
        entry = CredentialStatusEntry(**_VALID_STATUS_ENTRY)
        with pytest.raises(Exception):
            entry.statusListIndex = "99"  # type: ignore[misc]

    def test_suspension_purpose(self) -> None:
        data = dict(_VALID_STATUS_ENTRY)
        data["statusPurpose"] = "suspension"
        entry = CredentialStatusEntry(**data)
        assert entry.statusPurpose == "suspension"


# ---------------------------------------------------------------------------
# TestStatusListInfo
# ---------------------------------------------------------------------------


class TestStatusListInfo:
    def test_from_jwt_claims(self) -> None:
        info = StatusListInfo.from_jwt_claims(_VALID_JWT_CLAIMS)
        assert info.jti == "urn:uuid:abc123"
        assert info.iss.startswith("did:")
        assert info.status_purpose == "revocation"

    def test_from_jwt_claims_encoded_list(self) -> None:
        info = StatusListInfo.from_jwt_claims(_VALID_JWT_CLAIMS)
        assert isinstance(info.encoded_list, str)
        assert len(info.encoded_list) > 0

    def test_frozen_cannot_reassign(self) -> None:
        info = StatusListInfo.from_jwt_claims(_VALID_JWT_CLAIMS)
        with pytest.raises(Exception):
            info.jti = "new-jti"  # type: ignore[misc]

    def test_iss_must_be_did(self) -> None:
        claims = dict(_VALID_JWT_CLAIMS)
        claims["iss"] = "https://example.com/not-a-did"
        with pytest.raises(ValidationError):
            StatusListInfo.from_jwt_claims(claims)


# ---------------------------------------------------------------------------
# TestStalenessMode
# ---------------------------------------------------------------------------


class TestStalenessMode:
    def test_enum_values(self) -> None:
        assert StalenessMode.FAIL_CLOSED == "FAIL_CLOSED"
        assert StalenessMode.FAIL_OPEN_DEGRADED == "FAIL_OPEN_DEGRADED"
        assert StalenessMode.ALLOW_WITH_WARNING == "ALLOW_WITH_WARNING"


# ---------------------------------------------------------------------------
# TestStalenessPolicy
# ---------------------------------------------------------------------------


class TestStalenessPolicy:
    def test_default_values(self) -> None:
        policy = StalenessPolicy()
        assert policy.delta_seconds == 600
        assert policy.mode == StalenessMode.FAIL_CLOSED

    def test_custom_delta(self) -> None:
        policy = StalenessPolicy(delta_seconds=300)
        assert policy.delta_seconds == 300

    def test_frozen(self) -> None:
        policy = StalenessPolicy()
        with pytest.raises((AttributeError, TypeError)):
            policy.delta_seconds = 999  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TestDefaultPolicyForEnv
# ---------------------------------------------------------------------------


class TestDefaultPolicyForEnv:
    def test_prod(self) -> None:
        p = default_policy_for_env("prod")
        assert p.delta_seconds == 600
        assert p.mode == StalenessMode.FAIL_CLOSED

    def test_test_env(self) -> None:
        p = default_policy_for_env("test")
        assert p.delta_seconds == 1800
        assert p.mode == StalenessMode.FAIL_OPEN_DEGRADED

    def test_dev(self) -> None:
        p = default_policy_for_env("dev")
        assert p.delta_seconds == 3600
        assert p.mode == StalenessMode.ALLOW_WITH_WARNING

    def test_unknown_defaults_to_prod(self) -> None:
        p = default_policy_for_env("staging")
        assert p == default_policy_for_env("prod")


# ---------------------------------------------------------------------------
# TestStatusAnchor
# ---------------------------------------------------------------------------


class TestStatusAnchor:
    def test_creation(self) -> None:
        anchor = StatusAnchor(
            status_list_id="0xdeadbeef",
            root_hash="abcd1234",
            updated_at=1_700_000_000,
            issuer_id="0xcafebabe",
        )
        assert anchor.status_list_id == "0xdeadbeef"
        assert anchor.root_hash == "abcd1234"
        assert anchor.updated_at == 1_700_000_000

    def test_frozen(self) -> None:
        anchor = StatusAnchor(
            status_list_id="x",
            root_hash="y",
            updated_at=1,
        )
        with pytest.raises((AttributeError, TypeError)):
            anchor.root_hash = "z"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TestStatusCheckResult
# ---------------------------------------------------------------------------


class TestStatusCheckResult:
    def test_all_enum_values_exist(self) -> None:
        expected = {
            "NOT_REVOKED",
            "REVOKED",
            "EMERGENCY_REVOKED",
            "STALE_FAIL_CLOSED",
            "HASH_MISMATCH",
            "INDEX_OUT_OF_RANGE",
            "LIST_UNAVAILABLE",
        }
        actual = {e.value for e in StatusCheckResult}
        assert expected == actual

    def test_is_string_enum(self) -> None:
        assert isinstance(StatusCheckResult.REVOKED, str)
