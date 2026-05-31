"""Policy evaluator — first-match ABAC semantics (TASK-047).

Evaluation steps for each rule (in priority order):
  1. Match service_id_pattern, path_pattern (fnmatch), method_pattern, env_pattern.
  2. Check required_scopes ⊆ context.scopes  (AND / set containment).
  3. Check required_issuer in context.issuer_dids  (if set).
  4. Check required_credential_type in context.credential_types  (if set).
  5. First fully-matching rule → return decision.
  6. No match → default deny.

``missing_scopes`` in the result is populated from the *best structural match* —
the first rule that matched structurally but failed scope/issuer/type checks.
This is used only for internal audit logging; it is never returned to the caller.
"""
from __future__ import annotations

import fnmatch
import logging
from typing import List, Optional

from common.policy_engine.models import PolicyDecision, PolicyDecisionType, PolicyRule

logger = logging.getLogger(__name__)


def _match(pattern: str, value: str) -> bool:
    """Case-sensitive fnmatch; '*' matches everything."""
    if pattern == "*":
        return True
    return fnmatch.fnmatch(value, pattern)


class _RequestContext:
    """Extracted context built from verified VCs."""

    def __init__(
        self,
        resource: str,
        method: str,
        env: str,
        consumer_did: str,
        vcs: list,
    ) -> None:
        self.resource = resource
        self.method = method.upper()
        self.env = env
        self.consumer_did = consumer_did

        scopes: set = set()
        issuer_dids: set = set()
        credential_types: set = set()

        for vc in vcs:
            # Support both VerifiedCredential dataclasses and plain dicts.
            if hasattr(vc, "issuer_did"):
                issuer_dids.add(vc.issuer_did)
            elif isinstance(vc, dict):
                iss = vc.get("issuer_did") or vc.get("issuer", "")
                if iss:
                    issuer_dids.add(str(iss))

            if hasattr(vc, "credential_type"):
                t = vc.credential_type
                if t:
                    credential_types.add(str(t))
            elif isinstance(vc, dict):
                t = vc.get("credential_type", "")
                if t:
                    credential_types.add(str(t))

            # Extract scopes from credentialSubject.scopes (VerifiedCredential.claims)
            if hasattr(vc, "claims"):
                cs = vc.claims
            elif isinstance(vc, dict):
                cs = vc.get("claims", {}) or {}
            else:
                cs = {}

            raw_scopes = cs.get("scopes", []) if isinstance(cs, dict) else []
            if raw_scopes:
                for s in raw_scopes:
                    if s:
                        scopes.add(str(s))

        self.scopes: frozenset = frozenset(scopes)
        self.issuer_dids: frozenset = frozenset(issuer_dids)
        self.credential_types: frozenset = frozenset(credential_types)


class PolicyEvaluator:
    """Stateless ABAC evaluator; thread-safe (all state passed in)."""

    def evaluate(
        self,
        resource: str,
        method: str,
        env: str,
        consumer_did: str,
        vcs: list,
        service_id: str = "*",
        rules: Optional[List[PolicyRule]] = None,
    ) -> PolicyDecision:
        """Evaluate the request against pre-sorted rules.

        Returns:
            PolicyDecision with permit=True iff a permit rule fully matches.
        """
        if rules is None:
            rules = []

        ctx = _RequestContext(resource, method, env, consumer_did, vcs)

        # Track the best structural match (for audit explain output)
        best_rule_id: Optional[str] = None
        best_missing_scopes: Optional[List[str]] = None
        best_extra_context: dict = {}

        for rule in rules:
            # ── structural matching ──────────────────────────────────────
            if not _match(rule.service_id_pattern, service_id):
                continue
            if not _match(rule.path_pattern, resource):
                continue
            if rule.method_pattern != "*" and rule.method_pattern != ctx.method:
                continue
            if not _match(rule.env_pattern, env):
                continue

            # ── requirement checks ───────────────────────────────────────
            missing = sorted(rule.required_scopes - ctx.scopes)
            if missing:
                if best_rule_id is None:
                    best_rule_id = rule.id
                    best_missing_scopes = missing
                    best_extra_context = {
                        "required_issuer_expected": rule.required_issuer,
                        "actual_issuers": sorted(ctx.issuer_dids),
                    }
                continue  # partial match — don't deny immediately

            if rule.required_issuer and rule.required_issuer not in ctx.issuer_dids:
                if best_rule_id is None:
                    best_rule_id = rule.id
                    best_missing_scopes = []
                    best_extra_context = {
                        "required_issuer_expected": rule.required_issuer,
                        "actual_issuers": sorted(ctx.issuer_dids),
                    }
                continue

            if rule.required_credential_type and rule.required_credential_type not in ctx.credential_types:
                if best_rule_id is None:
                    best_rule_id = rule.id
                    best_missing_scopes = []
                    best_extra_context = {
                        "required_credential_type": rule.required_credential_type,
                        "actual_types": sorted(ctx.credential_types),
                    }
                continue

            # ── first full match → return decision ───────────────────────
            return PolicyDecision(
                permit=(rule.decision == PolicyDecisionType.permit),
                rule_id=rule.id,
                missing_scopes=[],
                extra_context={
                    "consumer_did": consumer_did,
                    "scopes_presented": sorted(ctx.scopes),
                    "issuer_dids": sorted(ctx.issuer_dids),
                },
                reason="rule_matched",
            )

        # No rule matched (or all structural matches failed requirements)
        return PolicyDecision(
            permit=False,
            rule_id=best_rule_id,
            missing_scopes=best_missing_scopes or [],
            extra_context={
                "consumer_did": consumer_did,
                "scopes_presented": sorted(ctx.scopes),
                **best_extra_context,
            },
            reason="no_matching_rule",
        )
