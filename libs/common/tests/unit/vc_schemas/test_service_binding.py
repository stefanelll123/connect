"""Unit tests for ServiceBindingCredential.

Covers:
* Valid credential construction.
* Endpoint pattern validation (length, count).
* Prod max-lifetime constraint (90 days).
* Non-prod environments may exceed 90 days.
* JWT sub must match credentialSubject.sentinel_did.
* credentialStatus is optional.
* JSON Schema export.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from pydantic_core import ValidationError as CoreValidationError

from common.vc_schemas.service_binding import (
    ServiceBindingCredential,
    ServiceBindingSubject,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_NOW = 1_741_910_400
_90D = 90 * 24 * 3600
_ISSUER = "did:key:z6MkServiceOwnerDID"
_SUBJECT = "did:key:z6MkSentinelDID"
_JTI = "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _make_subject(**overrides: object) -> dict:
    base: dict = {
        "sentinel_did": _SUBJECT,
        "service_id": "my-service",
        "env": "prod",
    }
    base.update(overrides)
    return base


def _make_vc(**overrides: object) -> dict:
    base: dict = {
        "iss": _ISSUER,
        "sub": _SUBJECT,
        "nbf": _NOW,
        "exp": _NOW + _90D,
        "jti": _JTI,
        "vc": {
            "type": ["VerifiableCredential", "ServiceBindingCredential"],
            "credentialSubject": _make_subject(),
            "credentialStatus": None,
        },
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# ServiceBindingSubject
# ---------------------------------------------------------------------------

class TestServiceBindingSubject:
    def test_valid_subject(self) -> None:
        subj = ServiceBindingSubject(**_make_subject())
        assert subj.sentinel_did == _SUBJECT
        assert subj.env == "prod"

    def test_endpoint_patterns_accepted(self) -> None:
        subj = ServiceBindingSubject(
            **_make_subject(valid_endpoint_patterns=["https://service.example.gov/api/*"])
        )
        assert subj.valid_endpoint_patterns is not None
        assert len(subj.valid_endpoint_patterns) == 1

    def test_endpoint_patterns_none_by_default(self) -> None:
        subj = ServiceBindingSubject(**_make_subject())
        assert subj.valid_endpoint_patterns is None

    def test_endpoint_pattern_max_length_512(self) -> None:
        with pytest.raises(ValidationError):
            ServiceBindingSubject(**_make_subject(valid_endpoint_patterns=["x" * 513]))

    def test_endpoint_pattern_exactly_512_accepted(self) -> None:
        # 512 chars is on the boundary — must pass
        subj = ServiceBindingSubject(**_make_subject(valid_endpoint_patterns=["x" * 512]))
        assert subj.valid_endpoint_patterns is not None

    def test_too_many_endpoint_patterns(self) -> None:
        with pytest.raises(ValidationError):
            ServiceBindingSubject(**_make_subject(valid_endpoint_patterns=["p"] * 21))

    def test_exactly_20_endpoint_patterns_accepted(self) -> None:
        subj = ServiceBindingSubject(**_make_subject(valid_endpoint_patterns=["p"] * 20))
        assert len(subj.valid_endpoint_patterns) == 20  # type: ignore[arg-type]

    def test_invalid_did_pattern(self) -> None:
        with pytest.raises(ValidationError):
            ServiceBindingSubject(**_make_subject(sentinel_did="not-a-did"))

    def test_invalid_env(self) -> None:
        with pytest.raises(ValidationError):
            ServiceBindingSubject(**_make_subject(env="uat"))

    def test_all_envs_accepted(self) -> None:
        for env in ("dev", "test", "prod"):
            subj = ServiceBindingSubject(**_make_subject(env=env))
            assert subj.env == env


# ---------------------------------------------------------------------------
# ServiceBindingCredential
# ---------------------------------------------------------------------------

class TestServiceBindingCredential:
    def test_valid_credential(self) -> None:
        vc = ServiceBindingCredential(**_make_vc())
        assert vc.sub == _SUBJECT
        assert vc.vc.credentialSubject.service_id == "my-service"

    def test_exp_must_be_after_nbf(self) -> None:
        with pytest.raises(ValidationError):
            ServiceBindingCredential(**_make_vc(exp=_NOW - 1))

    def test_exp_equal_nbf_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ServiceBindingCredential(**_make_vc(exp=_NOW))

    def test_prod_max_lifetime_exceeded_by_one_second(self) -> None:
        with pytest.raises(ValidationError, match="90-day"):
            ServiceBindingCredential(**_make_vc(exp=_NOW + _90D + 1))

    def test_prod_max_lifetime_exactly_at_limit(self) -> None:
        # exactly 90 days — must succeed
        vc = ServiceBindingCredential(**_make_vc(exp=_NOW + _90D))
        assert vc.exp - vc.nbf == _90D

    def test_non_prod_can_exceed_90_days(self) -> None:
        vc_data = _make_vc(exp=_NOW + _90D * 2)
        vc_data["vc"]["credentialSubject"] = _make_subject(env="dev")  # type: ignore[index]
        vc = ServiceBindingCredential(**vc_data)
        assert vc.vc.credentialSubject.env == "dev"

    def test_test_env_can_exceed_90_days(self) -> None:
        vc_data = _make_vc(exp=_NOW + _90D + 1)
        vc_data["vc"]["credentialSubject"] = _make_subject(env="test")  # type: ignore[index]
        vc = ServiceBindingCredential(**vc_data)
        assert vc.vc.credentialSubject.env == "test"

    def test_sub_must_match_sentinel_did(self) -> None:
        vc_data = _make_vc()
        vc_data["sub"] = "did:key:z6MkOtherDID"
        with pytest.raises(ValidationError, match="sub.*sentinel_did"):
            ServiceBindingCredential(**vc_data)

    def test_vc_type_must_include_service_binding(self) -> None:
        vc_data = _make_vc()
        vc_data["vc"]["type"] = ["VerifiableCredential"]  # type: ignore[index]
        with pytest.raises(ValidationError, match="ServiceBindingCredential"):
            ServiceBindingCredential(**vc_data)

    def test_credential_status_optional(self) -> None:
        vc_data = _make_vc()
        vc_data["vc"]["credentialStatus"] = None  # type: ignore[index]
        vc = ServiceBindingCredential(**vc_data)
        assert vc.vc.credentialStatus is None

    def test_credential_status_when_provided(self) -> None:
        vc_data = _make_vc()
        vc_data["vc"]["credentialStatus"] = {  # type: ignore[index]
            "id": "https://discovery.example.gov/status/list-001#5",
            "type": "BitstringStatusListEntry",
            "statusListIndex": "5",
            "statusListCredential": "https://discovery.example.gov/status/list-001",
            "statusPurpose": "revocation",
        }
        vc = ServiceBindingCredential(**vc_data)
        assert vc.vc.credentialStatus is not None
        assert vc.vc.credentialStatus.statusListIndex == "5"

    def test_json_schema_export(self) -> None:
        schema = ServiceBindingCredential.model_json_schema()
        assert "properties" in schema

    def test_model_is_frozen(self) -> None:
        vc = ServiceBindingCredential(**_make_vc())
        with pytest.raises((AttributeError, TypeError, ValidationError, CoreValidationError)):
            vc.iss = "did:key:z6MkOther"  # type: ignore[misc]
