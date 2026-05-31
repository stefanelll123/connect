"""Unit tests for the Policy Engine (TASK-047).

Tests:
  1.  Exact path match + all scopes present → permit
  2.  Glob path match + scopes present → permit
  3.  Exact path match + missing scope → deny with missing_scopes populated
  4.  Method mismatch skips rule → falls through to default deny
  5.  Env mismatch skips rule
  6.  required_issuer match → permit
  7.  required_issuer mismatch → deny
  8.  No matching rule → default deny (reason=no_matching_rule)
  9.  Deny-all rule fires → deny (reason=rule_matched)
  10. Hot reload replaces active policy atomically
  11. Rollback restores previous policy
  12. Empty policy YAML load rejected with ValueError
  + Glob priority ordering (deny_admin at priority 5 fires before allow at 10)
"""
from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Optional

import pytest

from common.policy_engine.engine import PolicyEngine
from common.policy_engine.evaluator import PolicyEvaluator
from common.policy_engine.loader import load_policy_yaml
from common.policy_engine.models import PolicyDecision, PolicyDecisionType

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_sample() -> str:
    return (_FIXTURES_DIR / "sample_policy.yaml").read_text()


@dataclasses.dataclass
class _FakeVC:
    issuer_did: str
    credential_type: str
    claims: dict  # represents credentialSubject


def _vc(
    *,
    issuer: str = "did:key:z6MkTestIssuer",
    ctype: str = "SentinelAccessCredential",
    scopes: list = None,
) -> _FakeVC:
    return _FakeVC(
        issuer_did=issuer,
        credential_type=ctype,
        claims={"scopes": scopes or []},
    )


SAMPLE_RULES = load_policy_yaml(_load_sample())
EVALUATOR = PolicyEvaluator()


def _eval(
    resource: str,
    method: str = "GET",
    env: str = "prod",
    service_id: str = "service-a",
    vcs: list = None,
    rules=None,
) -> PolicyDecision:
    return EVALUATOR.evaluate(
        resource=resource,
        method=method,
        env=env,
        consumer_did="did:key:z6MkConsumer",
        vcs=vcs or [],
        service_id=service_id,
        rules=rules if rules is not None else SAMPLE_RULES,
    )


# ---------------------------------------------------------------------------
# Test 1: Exact path match + all scopes present → permit
# ---------------------------------------------------------------------------

class TestExactPathPermit:
    def test_exact_match_all_scopes_present(self):
        decision = _eval(
            resource="/api/v1/data",
            method="GET",
            vcs=[_vc(scopes=["data:read"])],
        )
        assert decision.permit is True
        assert decision.rule_id == "allow_read_data_v1"
        assert decision.reason == "rule_matched"
        assert decision.missing_scopes == []


# ---------------------------------------------------------------------------
# Test 2: Glob path match + scopes present → permit
# ---------------------------------------------------------------------------

class TestGlobPathPermit:
    def test_glob_match_scopes_present(self):
        decision = _eval(
            resource="/api/v1/orders",
            method="POST",
            vcs=[_vc(scopes=["data:write"])],
        )
        assert decision.permit is True
        assert decision.rule_id == "allow_write_api_glob"
        assert decision.reason == "rule_matched"


# ---------------------------------------------------------------------------
# Test 3: Exact path match + missing scope → deny, missing_scopes populated
# ---------------------------------------------------------------------------

class TestMissingScope:
    def test_missing_scope_deny_best_structural_match(self):
        # No default-deny catch-all — so when scope check fails, reason=no_matching_rule
        # and missing_scopes is populated from the best structural match.
        rules_no_default = load_policy_yaml("""
version: '1'
rules:
  - id: allow_read_only
    service_id: 'service-a'
    path_glob: '/api/v1/data'
    method: GET
    env: prod
    required_scopes: ['data:read']
    decision: permit
    priority: 10
""")
        decision = _eval(
            resource="/api/v1/data",
            method="GET",
            vcs=[],  # no VCs → no scopes
            rules=rules_no_default,
        )
        assert decision.permit is False
        # best structural match is allow_read_only (matched path/method/env/service_id)
        assert decision.rule_id == "allow_read_only"
        assert "data:read" in decision.missing_scopes
        assert decision.reason == "no_matching_rule"

    def test_missing_scope_with_default_deny_fires(self):
        # With full sample policy: default_deny (no required scopes) fires for
        # requests that fail the allow_read_data_v1 scope check.
        decision = _eval(
            resource="/api/v1/data",
            method="GET",
            vcs=[],  # no VCs → no scopes
        )
        assert decision.permit is False
        assert decision.rule_id == "default_deny"
        assert decision.reason == "rule_matched"


# ---------------------------------------------------------------------------
# Test 4: Method mismatch skips rule → falls through to default deny
# ---------------------------------------------------------------------------

class TestMethodMismatch:
    def test_method_mismatch_skips_rule(self):
        # allow_read_data_v1 requires GET, we send DELETE
        decision = _eval(
            resource="/api/v1/data",
            method="DELETE",
            vcs=[_vc(scopes=["data:read"])],
        )
        assert decision.permit is False
        assert decision.rule_id == "default_deny"  # default_deny fires
        assert decision.reason == "rule_matched"


# ---------------------------------------------------------------------------
# Test 5: Env mismatch skips rule
# ---------------------------------------------------------------------------

class TestEnvMismatch:
    def test_env_mismatch_skips_rule(self):
        # allow_read_data_v1 requires env=prod; we're in staging
        decision = _eval(
            resource="/api/v1/data",
            method="GET",
            env="staging",
            vcs=[_vc(scopes=["data:read"])],
        )
        assert decision.permit is False
        # only default_deny (env=*) matches
        assert decision.rule_id == "default_deny"
        assert decision.reason == "rule_matched"


# ---------------------------------------------------------------------------
# Test 6: required_issuer match → permit
# ---------------------------------------------------------------------------

class TestRequiredIssuerMatch:
    def test_issuer_required_and_present_permit(self):
        issuer_rules = load_policy_yaml("""
version: '1'
rules:
  - id: issuer_rule
    service_id: '*'
    path_glob: '**'
    method: '*'
    env: '*'
    required_scopes: ['read']
    required_issuer: 'did:key:z6MkTrusted'
    decision: permit
    priority: 1
""")
        decision = EVALUATOR.evaluate(
            resource="/api/resource",
            method="GET",
            env="prod",
            consumer_did="did:key:z6MkCons",
            vcs=[_vc(issuer="did:key:z6MkTrusted", scopes=["read"])],
            service_id="*",
            rules=issuer_rules,
        )
        assert decision.permit is True
        assert decision.rule_id == "issuer_rule"


# ---------------------------------------------------------------------------
# Test 7: required_issuer mismatch → deny
# ---------------------------------------------------------------------------

class TestRequiredIssuerMismatch:
    def test_issuer_required_but_wrong_deny(self):
        issuer_rules = load_policy_yaml("""
version: '1'
rules:
  - id: issuer_rule
    service_id: '*'
    path_glob: '**'
    method: '*'
    env: '*'
    required_scopes: ['read']
    required_issuer: 'did:key:z6MkTrusted'
    decision: permit
    priority: 1
""")
        decision = EVALUATOR.evaluate(
            resource="/api/resource",
            method="GET",
            env="prod",
            consumer_did="did:key:z6MkCons",
            vcs=[_vc(issuer="did:key:z6MkUntrusted", scopes=["read"])],
            service_id="*",
            rules=issuer_rules,
        )
        assert decision.permit is False
        assert decision.rule_id == "issuer_rule"
        assert decision.missing_scopes == []


# ---------------------------------------------------------------------------
# Test 8: No matching rule → default deny (reason=no_matching_rule)
# ---------------------------------------------------------------------------

class TestNoMatchingRule:
    def test_empty_ruleset_deny(self):
        # An empty ruleset has no rules at all — no structural match
        empty_rules = load_policy_yaml("""
version: '1'
rules:
  - id: very_specific_rule
    service_id: 'only-this-service'
    path_glob: '/only/this/path'
    method: 'POST'
    env: 'prod'
    required_scopes: ['special']
    decision: permit
    priority: 1
""")
        decision = EVALUATOR.evaluate(
            resource="/other/path",
            method="GET",
            env="prod",
            consumer_did="did:key:z6MkCons",
            vcs=[_vc(scopes=["special"])],
            service_id="only-this-service",
            rules=empty_rules,
        )
        assert decision.permit is False
        assert decision.rule_id is None
        assert decision.reason == "no_matching_rule"


# ---------------------------------------------------------------------------
# Test 9: Deny-all rule → deny (reason=rule_matched with decision=deny)
# ---------------------------------------------------------------------------

class TestDenyAllRule:
    def test_deny_all_default_fires(self):
        # default_deny in sample policy (priority 9999) catches all unmatched
        # Provide scopes to pass allow_read but request wrong path
        decision = _eval(
            resource="/completely/different/path",
            method="DELETE",
            vcs=[_vc(scopes=["data:read", "data:write"])],
        )
        assert decision.permit is False
        assert decision.rule_id == "default_deny"
        assert decision.reason == "rule_matched"


# ---------------------------------------------------------------------------
# Test 10: Hot reload replaces active policy atomically
# ---------------------------------------------------------------------------

class TestHotReload:
    async def test_reload_swaps_active_policy(self):
        engine = PolicyEngine()
        # At startup: DENY_ALL
        d1 = await engine.evaluate(
            resource="/api/data", method="GET", env="prod",
            consumer_did="did:key:z", vcs=[_vc(scopes=["data:read"])],
            service_id="service-a",
        )
        assert d1.permit is False  # DENY_ALL is active

        # Load permissive policy
        permit_yaml = """
version: '2'
rules:
  - id: allow_all
    service_id: '*'
    path_glob: '**'
    method: '*'
    env: '*'
    required_scopes: []
    decision: permit
    priority: 1
"""
        await engine.reload(permit_yaml, bundle_version="v2")
        d2 = await engine.evaluate(
            resource="/api/data", method="GET", env="prod",
            consumer_did="did:key:z", vcs=[],
            service_id="service-a",
        )
        assert d2.permit is True
        assert engine.active_version == "v2"


# ---------------------------------------------------------------------------
# Test 11: Rollback restores previous policy
# ---------------------------------------------------------------------------

class TestRollback:
    async def test_rollback_restores_previous_policy(self):
        engine = PolicyEngine()

        deny_yaml = """
version: 'deny-v1'
rules:
  - id: deny_all
    service_id: '*'
    path_glob: '**'
    method: '*'
    env: '*'
    required_scopes: []
    decision: deny
    priority: 1
"""
        permit_yaml = """
version: 'permit-v1'
rules:
  - id: allow_all
    service_id: '*'
    path_glob: '**'
    method: '*'
    env: '*'
    required_scopes: []
    decision: permit
    priority: 1
"""
        await engine.reload(deny_yaml, "deny-v1")
        await engine.reload(permit_yaml, "permit-v1")

        # After second reload: permit
        d1 = await engine.evaluate("/r", "GET", "prod", "did:key:z", [])
        assert d1.permit is True

        # Rollback: restore deny-v1
        await engine.rollback()
        d2 = await engine.evaluate("/r", "GET", "prod", "did:key:z", [])
        assert d2.permit is False


# ---------------------------------------------------------------------------
# Test 12: Empty policy YAML → ValueError
# ---------------------------------------------------------------------------

class TestEmptyPolicyRejected:
    def test_empty_string_rejected(self):
        with pytest.raises(ValueError, match="[Ee]mpty"):
            load_policy_yaml("")

    def test_whitespace_only_rejected(self):
        with pytest.raises(ValueError, match="[Ee]mpty"):
            load_policy_yaml("   \n  ")

    def test_no_rules_key_rejected(self):
        with pytest.raises(ValueError):
            load_policy_yaml("version: '1'\n")

    def test_empty_rules_list_rejected(self):
        with pytest.raises(ValueError):
            load_policy_yaml("version: '1'\nrules: []\n")


# ---------------------------------------------------------------------------
# Bonus: Glob priority ordering (deny_admin fires before later permit rules)
# ---------------------------------------------------------------------------

class TestGlobPriorityOrdering:
    def test_deny_admin_fires_before_allow(self):
        # /admin/ path should hit deny_admin (priority 5) before allow_read (priority 10)
        decision = _eval(
            resource="/admin/users",
            method="GET",
            vcs=[_vc(scopes=["data:read"])],
        )
        assert decision.permit is False
        assert decision.rule_id == "deny_admin"

    def test_lower_priority_fires_first(self):
        # Verify sort order: priority 5 < priority 10 < priority 20 < 9999
        priorities = [r.priority for r in SAMPLE_RULES]
        assert priorities == sorted(priorities)
