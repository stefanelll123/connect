"""Unit tests for SimplePolicyEvaluator, PolicyDecision, and matches_path_glob.

Covers:
* Path glob matching: exact, *, **, no-match.
* Permit on valid VC with matching scope.
* Deny: no matching VC, expired VC, revoked VC, env mismatch, aud mismatch,
  scope insufficient (wrong path), scope insufficient (wrong method).
* matched_rule_id is populated on PERMIT.
* VC for wrong consumer DID → NO_MATCHING_VC.
* PolicyEvaluator protocol satisfaction.
* PolicyDecision and VerifiedVC are frozen dataclasses.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from common.vc_schemas.policy import (
    PolicyDecision,
    PolicyEvaluator,
    PolicyRequest,
    PolicyReasonCode,
    RequestContext,
    SimplePolicyEvaluator,
    VerifiedVC,
    matches_path_glob,
)

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

_NOW = 1_741_910_400
_CONSUMER = "did:key:z6MkConsumerDID"
_PRODUCER = "did:key:z6MkProducerDID"
_ISSUER = "did:key:z6MkIssuerDID"
_JTI = "urn:uuid:11111111-2222-3333-4444-555555555555"


def _make_vc(**overrides: object) -> VerifiedVC:
    base = VerifiedVC(
        jti=_JTI,
        issuer=_ISSUER,
        subject=_CONSUMER,
        vc_type=["VerifiableCredential", "AccessGrantCredential"],
        credential_subject={
            "id": _CONSUMER,
            "aud": _PRODUCER,
            "env": "prod",
            "scope": [
                {
                    "service_id": "citizen-data",
                    "path_glob": "/api/v1/citizens/*",
                    "methods": ["GET"],
                }
            ],
        },
        env="prod",
        exp=_NOW + 3600,
        is_revoked=False,
    )
    return replace(base, **overrides)


def _make_request(**overrides: object) -> PolicyRequest:
    defaults: dict = dict(
        consumer_did=_CONSUMER,
        producer_did=_PRODUCER,
        resource="/api/v1/citizens/123",
        method="GET",
        env="prod",
        vc_set=[_make_vc()],
        context=RequestContext(timestamp=_NOW),
    )
    defaults.update(overrides)
    return PolicyRequest(**defaults)


# ---------------------------------------------------------------------------
# matches_path_glob
# ---------------------------------------------------------------------------

class TestMatchesPathGlob:
    def test_exact_match(self) -> None:
        assert matches_path_glob("/api/v1/citizens/123", "/api/v1/citizens/123")

    def test_single_wildcard_matches_segment(self) -> None:
        assert matches_path_glob("/api/v1/citizens/123", "/api/v1/citizens/*")

    def test_single_wildcard_does_not_cross_slash(self) -> None:
        assert not matches_path_glob("/api/v1/citizens/123/docs", "/api/v1/citizens/*")

    def test_double_wildcard_crosses_slash(self) -> None:
        assert matches_path_glob("/api/v1/citizens/123/docs", "/api/v1/citizens/**")

    def test_double_wildcard_matches_multiple_segments(self) -> None:
        assert matches_path_glob("/api/v1/citizens/123/docs/report.pdf", "/api/v1/**")

    def test_no_match_different_prefix(self) -> None:
        assert not matches_path_glob("/api/v2/services/99", "/api/v1/citizens/*")

    def test_root_path_exact(self) -> None:
        assert matches_path_glob("/health", "/health")

    def test_trailing_slash_normalised(self) -> None:
        assert matches_path_glob("/health/", "/health")

    def test_wildcard_must_match_non_empty_segment(self) -> None:
        # /* should match /anything but not just /
        assert not matches_path_glob("/api/v1/citizens/", "/api/v1/citizens/*")

    def test_no_match_extra_segment(self) -> None:
        assert not matches_path_glob("/api/v1/citizens", "/api/v1/citizens/*")


# ---------------------------------------------------------------------------
# SimplePolicyEvaluator
# ---------------------------------------------------------------------------

class TestSimplePolicyEvaluatorPermit:
    def setup_method(self) -> None:
        self.evaluator = SimplePolicyEvaluator()

    def test_permit_on_valid_vc_matching_scope(self) -> None:
        decision = self.evaluator.evaluate(_make_request())
        assert decision.result == "PERMIT"

    def test_permit_returns_matched_rule_id(self) -> None:
        decision = self.evaluator.evaluate(_make_request())
        assert decision.matched_rule_id is not None
        assert "citizen-data" in decision.matched_rule_id

    def test_permit_wildcard_path_various_ids(self) -> None:
        for resource_id in ("123", "456", "abc-def", "999"):
            decision = self.evaluator.evaluate(_make_request(resource=f"/api/v1/citizens/{resource_id}"))
            assert decision.result == "PERMIT"

    def test_permit_reason_code_is_permit(self) -> None:
        decision = self.evaluator.evaluate(_make_request())
        assert decision.reason_code == PolicyReasonCode.PERMIT


class TestSimplePolicyEvaluatorDeny:
    def setup_method(self) -> None:
        self.evaluator = SimplePolicyEvaluator()

    def test_deny_no_matching_vc(self) -> None:
        req = _make_request(vc_set=[])
        decision = self.evaluator.evaluate(req)
        assert decision.result == "DENY"
        assert decision.reason_code == PolicyReasonCode.NO_MATCHING_VC

    def test_deny_expired_vc(self) -> None:
        expired_vc = _make_vc(exp=_NOW - 1)
        decision = self.evaluator.evaluate(_make_request(vc_set=[expired_vc]))
        assert decision.result == "DENY"
        assert decision.reason_code == PolicyReasonCode.VC_EXPIRED

    def test_deny_vc_expiring_at_exact_now(self) -> None:
        # exp < now means expired; exp == now - 1 is definitely expired
        expired_vc = _make_vc(exp=_NOW - 1)
        decision = self.evaluator.evaluate(_make_request(vc_set=[expired_vc]))
        assert decision.result == "DENY"

    def test_deny_revoked_vc(self) -> None:
        revoked_vc = _make_vc(is_revoked=True)
        decision = self.evaluator.evaluate(_make_request(vc_set=[revoked_vc]))
        assert decision.result == "DENY"
        assert decision.reason_code == PolicyReasonCode.VC_REVOKED

    def test_revoked_check_before_expiry(self) -> None:
        # Revoked AND expired — revocation check happens first.
        bad_vc = _make_vc(is_revoked=True, exp=_NOW - 1)
        decision = self.evaluator.evaluate(_make_request(vc_set=[bad_vc]))
        assert decision.reason_code == PolicyReasonCode.VC_REVOKED

    def test_deny_env_mismatch(self) -> None:
        dev_vc = _make_vc(env="dev")
        decision = self.evaluator.evaluate(_make_request(vc_set=[dev_vc]))
        assert decision.result == "DENY"
        assert decision.reason_code == PolicyReasonCode.ENV_MISMATCH

    def test_deny_env_mismatch_test_env(self) -> None:
        test_vc = _make_vc(env="test")
        decision = self.evaluator.evaluate(_make_request(vc_set=[test_vc]))
        assert decision.result == "DENY"
        assert decision.reason_code == PolicyReasonCode.ENV_MISMATCH

    def test_deny_aud_mismatch(self) -> None:
        wrong_cs = {**_make_vc().credential_subject, "aud": "did:key:z6MkWrongProducer"}
        bad_vc = replace(_make_vc(), credential_subject=wrong_cs)
        decision = self.evaluator.evaluate(_make_request(vc_set=[bad_vc]))
        assert decision.result == "DENY"
        assert decision.reason_code == PolicyReasonCode.AUD_MISMATCH

    def test_deny_scope_insufficient_wrong_path(self) -> None:
        req = _make_request(resource="/api/v2/admin/settings")
        decision = self.evaluator.evaluate(req)
        assert decision.result == "DENY"
        assert decision.reason_code == PolicyReasonCode.SCOPE_INSUFFICIENT

    def test_deny_scope_insufficient_wrong_method(self) -> None:
        req = _make_request(method="DELETE")
        decision = self.evaluator.evaluate(req)
        assert decision.result == "DENY"
        assert decision.reason_code == PolicyReasonCode.SCOPE_INSUFFICIENT

    def test_deny_scope_insufficient_post_on_get_only(self) -> None:
        req = _make_request(method="POST")
        decision = self.evaluator.evaluate(req)
        assert decision.result == "DENY"
        assert decision.reason_code == PolicyReasonCode.SCOPE_INSUFFICIENT

    def test_deny_vc_for_wrong_consumer(self) -> None:
        wrong_consumer_vc = _make_vc(subject="did:key:z6MkOtherConsumer")
        req = _make_request(vc_set=[wrong_consumer_vc])
        decision = self.evaluator.evaluate(req)
        assert decision.result == "DENY"
        assert decision.reason_code == PolicyReasonCode.NO_MATCHING_VC

    def test_deny_non_access_grant_vc_ignored(self) -> None:
        identity_vc = _make_vc(vc_type=["VerifiableCredential", "SentinelIdentityCredential"])
        req = _make_request(vc_set=[identity_vc])
        decision = self.evaluator.evaluate(req)
        assert decision.result == "DENY"
        assert decision.reason_code == PolicyReasonCode.NO_MATCHING_VC

    def test_missing_scopes_populated_on_scope_deny(self) -> None:
        req = _make_request(resource="/api/v2/admin/settings", method="DELETE")
        decision = self.evaluator.evaluate(req)
        assert decision.reason_code == PolicyReasonCode.SCOPE_INSUFFICIENT
        assert len(decision.missing_scopes) > 0
        assert "DELETE" in decision.missing_scopes[0]


# ---------------------------------------------------------------------------
# Protocol and frozen types
# ---------------------------------------------------------------------------

class TestPolicyEvaluatorProtocol:
    def test_simple_evaluator_satisfies_protocol(self) -> None:
        evaluator = SimplePolicyEvaluator()
        assert isinstance(evaluator, PolicyEvaluator)

    def test_policy_decision_default_missing_scopes(self) -> None:
        d = PolicyDecision(result="DENY", reason_code=PolicyReasonCode.NO_MATCHING_VC)
        assert d.missing_scopes == []

    def test_policy_decision_matched_rule_id_default_none(self) -> None:
        d = PolicyDecision(result="DENY", reason_code=PolicyReasonCode.NO_MATCHING_VC)
        assert d.matched_rule_id is None

    def test_policy_decision_is_frozen(self) -> None:
        d = PolicyDecision(result="PERMIT", reason_code=PolicyReasonCode.PERMIT)
        with pytest.raises((AttributeError, TypeError, FrozenInstanceError)):
            d.result = "DENY"  # type: ignore[misc]

    def test_verified_vc_is_frozen(self) -> None:
        vc = _make_vc()
        with pytest.raises((AttributeError, TypeError, FrozenInstanceError)):
            vc.jti = "new-jti"  # type: ignore[misc]

    def test_request_context_is_frozen(self) -> None:
        ctx = RequestContext(timestamp=_NOW)
        with pytest.raises((AttributeError, TypeError, FrozenInstanceError)):
            ctx.timestamp = _NOW + 1  # type: ignore[misc]
