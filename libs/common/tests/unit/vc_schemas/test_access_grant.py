"""Unit tests for AccessGrantCredential and ScopeEntry.

Covers:
* ScopeEntry: valid entries, wildcard enforcement, method validation.
* AccessGrantSubject: scope count limits, rate-limit constraints, aud DID pattern.
* AccessGrantCredential: prod 30-day lifetime, sub/aud cross-field invariants,
  credentialStatus mandatory, JSON Schema export.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from pydantic_core import ValidationError as CoreValidationError

from common.vc_schemas.access_grant import (
    AccessGrantCredential,
    AccessGrantSubject,
    ScopeEntry,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_NOW = 1_741_910_400
_30D = 30 * 24 * 3600
_ISSUER = "did:key:z6MkProducerAuthorityDID"
_CONSUMER = "did:key:z6MkConsumerSentinelDID"
_PRODUCER = "did:key:z6MkProducerServiceDID"
_JTI = "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _make_status(**overrides: object) -> dict:
    base: dict = {
        "id": "https://discovery.example.gov/status/list-002#42",
        "type": "BitstringStatusListEntry",
        "statusListIndex": "42",
        "statusListCredential": "https://discovery.example.gov/status/list-002",
        "statusPurpose": "revocation",
    }
    base.update(overrides)
    return base


def _make_scope(**overrides: object) -> dict:
    base: dict = {
        "service_id": "citizen-data-service",
        "path_glob": "/api/v1/citizens/*",
        "methods": ["GET"],
    }
    base.update(overrides)
    return base


def _make_subject(**overrides: object) -> dict:
    base: dict = {
        "id": _CONSUMER,
        "aud": _PRODUCER,
        "env": "prod",
        "scope": [_make_scope()],
    }
    base.update(overrides)
    return base


def _make_vc(**overrides: object) -> dict:
    base: dict = {
        "iss": _ISSUER,
        "sub": _CONSUMER,
        "aud": _PRODUCER,
        "nbf": _NOW,
        "exp": _NOW + _30D,
        "jti": _JTI,
        "vc": {
            "type": ["VerifiableCredential", "AccessGrantCredential"],
            "credentialSubject": _make_subject(),
            "credentialStatus": _make_status(),
        },
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# ScopeEntry
# ---------------------------------------------------------------------------

class TestScopeEntry:
    def test_valid_scope(self) -> None:
        scope = ScopeEntry(**_make_scope())
        assert scope.service_id == "citizen-data-service"
        assert "GET" in scope.methods

    def test_multiple_methods(self) -> None:
        scope = ScopeEntry(**_make_scope(methods=["GET", "POST"]))
        assert len(scope.methods) == 2

    def test_all_http_methods_accepted(self) -> None:
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            scope = ScopeEntry(**_make_scope(methods=[method]))
            assert method in scope.methods

    def test_empty_methods_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScopeEntry(**_make_scope(methods=[]))

    def test_invalid_method_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScopeEntry(**_make_scope(methods=["CONNECT"]))

    def test_head_method_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScopeEntry(**_make_scope(methods=["HEAD"]))

    def test_double_wildcard_requires_approval(self) -> None:
        with pytest.raises(ValidationError, match="approval_reference"):
            ScopeEntry(**_make_scope(path_glob="/api/**"))

    def test_double_wildcard_with_approval_accepted(self) -> None:
        scope = ScopeEntry(**_make_scope(path_glob="/api/**", approval_reference="SEC-ADMIN-2024-001"))
        assert scope.approval_reference == "SEC-ADMIN-2024-001"

    def test_single_wildcard_no_approval_needed(self) -> None:
        scope = ScopeEntry(**_make_scope(path_glob="/api/v1/citizens/*"))
        assert scope.approval_reference is None

    def test_path_glob_too_long(self) -> None:
        with pytest.raises(ValidationError):
            ScopeEntry(**_make_scope(path_glob="/" + "a" * 256))

    def test_path_glob_exactly_256_accepted(self) -> None:
        glob = "/" + "a" * 255  # total length = 256
        scope = ScopeEntry(**_make_scope(path_glob=glob))
        assert len(scope.path_glob) == 256

    def test_invalid_service_id_uppercase(self) -> None:
        with pytest.raises(ValidationError):
            ScopeEntry(**_make_scope(service_id="Invalid-Service"))

    def test_invalid_service_id_with_spaces(self) -> None:
        with pytest.raises(ValidationError):
            ScopeEntry(**_make_scope(service_id="my service"))

    def test_attributes_optional(self) -> None:
        scope = ScopeEntry(**_make_scope())
        assert scope.attributes is None

    def test_attributes_accepted(self) -> None:
        scope = ScopeEntry(**_make_scope(attributes=["role:admin", "org:gov"]))
        assert scope.attributes is not None
        assert len(scope.attributes) == 2

    def test_too_many_attributes(self) -> None:
        with pytest.raises(ValidationError):
            ScopeEntry(**_make_scope(attributes=["x"] * 21))

    def test_model_frozen(self) -> None:
        scope = ScopeEntry(**_make_scope())
        with pytest.raises((AttributeError, TypeError, ValidationError, CoreValidationError)):
            scope.service_id = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# AccessGrantSubject
# ---------------------------------------------------------------------------

class TestAccessGrantSubject:
    def test_valid_subject(self) -> None:
        subj = AccessGrantSubject(**_make_subject())
        assert subj.id == _CONSUMER
        assert subj.aud == _PRODUCER

    def test_empty_scope_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AccessGrantSubject(**_make_subject(scope=[]))

    def test_too_many_scopes(self) -> None:
        with pytest.raises(ValidationError):
            AccessGrantSubject(**_make_subject(scope=[_make_scope()] * 51))

    def test_exactly_50_scopes_accepted(self) -> None:
        subj = AccessGrantSubject(**_make_subject(scope=[_make_scope()] * 50))
        assert len(subj.scope) == 50

    def test_rate_limit_zero_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AccessGrantSubject(**_make_subject(max_requests_per_minute=0))

    def test_rate_limit_above_maximum_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AccessGrantSubject(**_make_subject(max_requests_per_minute=10001))

    def test_rate_limit_at_maximum_accepted(self) -> None:
        subj = AccessGrantSubject(**_make_subject(max_requests_per_minute=10000))
        assert subj.max_requests_per_minute == 10000

    def test_rate_limit_optional(self) -> None:
        subj = AccessGrantSubject(**_make_subject())
        assert subj.max_requests_per_minute is None

    def test_aud_must_be_did(self) -> None:
        with pytest.raises(ValidationError):
            AccessGrantSubject(**_make_subject(aud="not-a-did"))

    def test_id_must_be_did(self) -> None:
        with pytest.raises(ValidationError):
            AccessGrantSubject(**_make_subject(id="not-a-did"))


# ---------------------------------------------------------------------------
# AccessGrantCredential
# ---------------------------------------------------------------------------

class TestAccessGrantCredential:
    def test_valid_credential(self) -> None:
        vc = AccessGrantCredential(**_make_vc())
        assert vc.sub == _CONSUMER
        assert vc.aud == _PRODUCER

    def test_exp_must_be_after_nbf(self) -> None:
        with pytest.raises(ValidationError):
            AccessGrantCredential(**_make_vc(exp=_NOW))

    def test_prod_max_30_days_exceeded(self) -> None:
        with pytest.raises(ValidationError, match="30-day"):
            AccessGrantCredential(**_make_vc(exp=_NOW + _30D + 1))

    def test_prod_max_30_days_exactly_at_limit(self) -> None:
        vc = AccessGrantCredential(**_make_vc(exp=_NOW + _30D))
        assert vc.exp - vc.nbf == _30D

    def test_non_prod_can_exceed_30_days(self) -> None:
        vc_data = _make_vc(exp=_NOW + _30D * 2)
        vc_data["vc"]["credentialSubject"] = _make_subject(env="test")  # type: ignore[index]
        vc = AccessGrantCredential(**vc_data)
        assert vc.vc.credentialSubject.env == "test"

    def test_dev_can_exceed_30_days(self) -> None:
        vc_data = _make_vc(exp=_NOW + _30D * 10)
        vc_data["vc"]["credentialSubject"] = _make_subject(env="dev")  # type: ignore[index]
        vc = AccessGrantCredential(**vc_data)
        assert vc.vc.credentialSubject.env == "dev"

    def test_sub_must_match_credential_subject_id(self) -> None:
        vc_data = _make_vc()
        vc_data["sub"] = "did:key:z6MkOtherConsumer"
        with pytest.raises(ValidationError, match="sub.*credentialSubject.id"):
            AccessGrantCredential(**vc_data)

    def test_aud_must_match_credential_subject_aud(self) -> None:
        vc_data = _make_vc()
        vc_data["aud"] = "did:key:z6MkOtherProducer"
        with pytest.raises(ValidationError, match="aud.*credentialSubject.aud"):
            AccessGrantCredential(**vc_data)

    def test_credential_status_required(self) -> None:
        vc_data = _make_vc()
        vc_data["vc"]["credentialStatus"] = None  # type: ignore[index]
        with pytest.raises(ValidationError):
            AccessGrantCredential(**vc_data)

    def test_credential_status_missing_field_rejected(self) -> None:
        vc_data = _make_vc()
        del vc_data["vc"]["credentialStatus"]  # type: ignore[attr-defined]
        with pytest.raises(ValidationError):
            AccessGrantCredential(**vc_data)

    def test_vc_type_must_include_access_grant(self) -> None:
        vc_data = _make_vc()
        vc_data["vc"]["type"] = ["VerifiableCredential"]  # type: ignore[index]
        with pytest.raises(ValidationError, match="AccessGrantCredential"):
            AccessGrantCredential(**vc_data)

    def test_env_stored_in_credential_subject(self) -> None:
        vc = AccessGrantCredential(**_make_vc())
        assert vc.vc.credentialSubject.env == "prod"

    def test_json_schema_export(self) -> None:
        schema = AccessGrantCredential.model_json_schema()
        assert "properties" in schema or "$defs" in schema

    def test_model_is_frozen(self) -> None:
        vc = AccessGrantCredential(**_make_vc())
        with pytest.raises((AttributeError, TypeError, ValidationError, CoreValidationError)):
            vc.iss = "did:key:z6MkOther"  # type: ignore[misc]
