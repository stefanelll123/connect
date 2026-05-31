"""Unit tests for SentinelIdentityCredential.

Covers:
* Valid credential construction (PRODUCER and CONSUMER roles).
* Field validation: DID patterns, service_id pattern, env literals, role literals.
* Lifetime constraints: exp > nbf, max 365 days.
* Cross-field invariant: JWT sub == vc.credentialSubject.id.
* vc.type must include both required type strings.
* JSON Schema export.
* Frozen model (immutability).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from pydantic_core import ValidationError as CoreValidationError

from common.vc_schemas.sentinel_identity import (
    SentinelIdentityCredential,
    SentinelIdentitySubject,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_NOW = 1_741_910_400          # fixed timestamp for determinism
_YEAR = 365 * 24 * 3600
_ISSUER = "did:key:z6MkIssuerDiscoveryService"
_SUBJECT = "did:key:z6MkSentinelProducerDID"
_JTI = "urn:uuid:11111111-2222-3333-4444-555555555555"


def _make_status(**overrides: object) -> dict:
    base: dict = {
        "id": "https://discovery.example.gov/status/list-001#1",
        "type": "BitstringStatusListEntry",
        "statusListIndex": "1",
        "statusListCredential": "https://discovery.example.gov/status/list-001",
        "statusPurpose": "revocation",
    }
    base.update(overrides)
    return base


def _make_subject(**overrides: object) -> dict:
    base: dict = {
        "id": _SUBJECT,
        "role": "PRODUCER",
        "service_id": "citizen-data-service",
        "env": "prod",
    }
    base.update(overrides)
    return base


def _make_vc(**overrides: object) -> dict:
    base: dict = {
        "iss": _ISSUER,
        "sub": _SUBJECT,
        "nbf": _NOW,
        "exp": _NOW + _YEAR,
        "jti": _JTI,
        "vc": {
            "type": ["VerifiableCredential", "SentinelIdentityCredential"],
            "credentialSubject": _make_subject(),
            "credentialStatus": _make_status(),
        },
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# SentinelIdentitySubject
# ---------------------------------------------------------------------------

class TestSentinelIdentitySubject:
    def test_valid_producer(self) -> None:
        subj = SentinelIdentitySubject(**_make_subject())
        assert subj.role == "PRODUCER"
        assert subj.env == "prod"

    def test_valid_consumer(self) -> None:
        subj = SentinelIdentitySubject(**_make_subject(role="CONSUMER"))
        assert subj.role == "CONSUMER"

    def test_instance_count_hint_optional(self) -> None:
        subj = SentinelIdentitySubject(**_make_subject())
        assert subj.instance_count_hint is None

    def test_instance_count_hint_valid(self) -> None:
        subj = SentinelIdentitySubject(**_make_subject(instance_count_hint=3))
        assert subj.instance_count_hint == 3

    def test_instance_count_hint_minimum_one(self) -> None:
        with pytest.raises(ValidationError):
            SentinelIdentitySubject(**_make_subject(instance_count_hint=0))

    def test_invalid_did_pattern(self) -> None:
        with pytest.raises(ValidationError, match="pattern"):
            SentinelIdentitySubject(**_make_subject(id="not-a-did"))

    def test_invalid_did_empty(self) -> None:
        with pytest.raises(ValidationError):
            SentinelIdentitySubject(**_make_subject(id=""))

    def test_invalid_service_id_uppercase(self) -> None:
        with pytest.raises(ValidationError):
            SentinelIdentitySubject(**_make_subject(service_id="Invalid-Service"))

    def test_invalid_service_id_too_long(self) -> None:
        with pytest.raises(ValidationError):
            SentinelIdentitySubject(**_make_subject(service_id="a" * 129))

    def test_service_id_allows_hyphens_and_underscores(self) -> None:
        subj = SentinelIdentitySubject(**_make_subject(service_id="my-citizen_data"))
        assert subj.service_id == "my-citizen_data"

    def test_invalid_env(self) -> None:
        with pytest.raises(ValidationError):
            SentinelIdentitySubject(**_make_subject(env="staging"))

    def test_invalid_role(self) -> None:
        with pytest.raises(ValidationError):
            SentinelIdentitySubject(**_make_subject(role="ADMIN"))

    def test_all_envs_accepted(self) -> None:
        for env in ("dev", "test", "prod"):
            subj = SentinelIdentitySubject(**_make_subject(env=env))
            assert subj.env == env


# ---------------------------------------------------------------------------
# SentinelIdentityCredential
# ---------------------------------------------------------------------------

class TestSentinelIdentityCredential:
    def test_valid_credential(self) -> None:
        vc = SentinelIdentityCredential(**_make_vc())
        assert vc.iss == _ISSUER
        assert vc.sub == _SUBJECT
        assert vc.vc.credentialSubject.role == "PRODUCER"

    def test_exp_must_be_after_nbf(self) -> None:
        with pytest.raises(ValidationError, match="exp must be greater than nbf"):
            SentinelIdentityCredential(**_make_vc(exp=_NOW - 1))

    def test_exp_equal_to_nbf_rejected(self) -> None:
        with pytest.raises(ValidationError, match="exp must be greater than nbf"):
            SentinelIdentityCredential(**_make_vc(exp=_NOW))

    def test_max_lifetime_exactly_at_limit(self) -> None:
        # exactly 365 days — must succeed
        vc = SentinelIdentityCredential(**_make_vc(exp=_NOW + _YEAR))
        assert vc.exp - vc.nbf == _YEAR

    def test_max_lifetime_exceeded_by_one_second(self) -> None:
        with pytest.raises(ValidationError, match="365 days"):
            SentinelIdentityCredential(**_make_vc(exp=_NOW + _YEAR + 1))

    def test_sub_must_match_credential_subject_id(self) -> None:
        vc_data = _make_vc()
        vc_data["sub"] = "did:key:z6MkDifferentDID"
        with pytest.raises(ValidationError, match="sub.*credentialSubject.id"):
            SentinelIdentityCredential(**vc_data)

    def test_invalid_jti_pattern(self) -> None:
        with pytest.raises(ValidationError):
            SentinelIdentityCredential(**_make_vc(jti="not-a-urn"))

    def test_invalid_jti_missing_prefix(self) -> None:
        with pytest.raises(ValidationError):
            SentinelIdentityCredential(**_make_vc(jti="uuid:11111111-2222-3333-4444-555555555555"))

    def test_vc_type_must_include_credential_type(self) -> None:
        vc_data = _make_vc()
        vc_data["vc"]["type"] = ["VerifiableCredential"]  # type: ignore[index]
        with pytest.raises(ValidationError, match="SentinelIdentityCredential"):
            SentinelIdentityCredential(**vc_data)

    def test_vc_type_must_include_base_type(self) -> None:
        vc_data = _make_vc()
        vc_data["vc"]["type"] = ["SentinelIdentityCredential"]  # type: ignore[index]
        with pytest.raises(ValidationError, match="VerifiableCredential"):
            SentinelIdentityCredential(**vc_data)

    def test_extra_vc_types_are_allowed(self) -> None:
        vc_data = _make_vc()
        vc_data["vc"]["type"] = [  # type: ignore[index]
            "VerifiableCredential",
            "SentinelIdentityCredential",
            "CustomExtension",
        ]
        vc = SentinelIdentityCredential(**vc_data)
        assert "CustomExtension" in vc.vc.type

    def test_json_schema_export(self) -> None:
        schema = SentinelIdentityCredential.model_json_schema()
        assert "properties" in schema
        assert "iss" in schema["properties"]
        assert "vc" in schema["properties"]

    def test_model_is_frozen(self) -> None:
        vc = SentinelIdentityCredential(**_make_vc())
        with pytest.raises((AttributeError, TypeError, ValidationError, CoreValidationError)):
            vc.iss = "did:key:z6MkOther"  # type: ignore[misc]

    def test_consumer_credential_valid(self) -> None:
        vc_data = _make_vc()
        vc_data["vc"]["credentialSubject"] = _make_subject(  # type: ignore[index]
            role="CONSUMER",
            service_id="frontend-aggregator",
        )
        vc_data["vc"]["credentialSubject"]["id"] = _SUBJECT  # type: ignore[index]
        vc = SentinelIdentityCredential(**vc_data)
        assert vc.vc.credentialSubject.role == "CONSUMER"
