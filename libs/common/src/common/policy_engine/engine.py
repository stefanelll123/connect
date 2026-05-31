"""PolicyEngine — hot-reload, rollback, and default deny-all (TASK-047).

At startup the engine is seeded with a built-in DENY_ALL policy.  The first
``reload()`` call after the config bundle is verified replaces it atomically.
``rollback()`` restores the last known-good policy.

The asyncio.Lock is held *only* during the pointer swap (< 1 µs); evaluation
reads the rules reference under the lock and then releases it before running.
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from common.policy_engine.evaluator import PolicyEvaluator
from common.policy_engine.loader import compute_policy_fingerprint, load_policy_yaml
from common.policy_engine.models import PolicyDecision, PolicyRule

logger = logging.getLogger(__name__)

# ── Built-in deny-all policy (applied before first bundle sync) ──────────────
_DENY_ALL_YAML = """\
version: 'built-in'
issued_by: 'built-in'
issued_at: '1970-01-01T00:00:00Z'
rules:
  - id: default_deny
    service_id: '*'
    path_glob: '**'
    method: '*'
    env: '*'
    required_scopes: []
    decision: deny
    priority: 9999
"""

_DENY_ALL_RULES: List[PolicyRule] = load_policy_yaml(_DENY_ALL_YAML)


class PolicyEngine:
    """ABAC policy engine with atomic hot reload and rollback.

    Usage::

        engine = PolicyEngine()
        await engine.reload(policy_yaml, bundle_version="v3")
        decision = await engine.evaluate(
            resource="/api/data",
            method="GET",
            env="prod",
            consumer_did="did:key:z...",
            vcs=verified_vcs,
            service_id="my-service",
        )
        if not decision.permit:
            return 403  # do NOT include decision.rule_id in the response
    """

    def __init__(self) -> None:
        self._active_rules: List[PolicyRule] = _DENY_ALL_RULES
        self._last_valid_rules: List[PolicyRule] = _DENY_ALL_RULES
        self._active_version: str = "deny_all"
        self._lock = asyncio.Lock()
        self._evaluator = PolicyEvaluator()
        logger.warning(
            "event=no_policy_loaded using=deny_all "
            "reason='awaiting first config bundle sync'"
        )

    async def reload(self, new_policy_yaml: str, bundle_version: str = "") -> bool:
        """Atomically swap in a new policy parsed from verified YAML.

        Args:
            new_policy_yaml:  YAML string extracted from a JWS-verified bundle.
            bundle_version:   Opaque version string for audit logging.

        Returns:
            True on success.

        Raises:
            ValueError: if policy YAML is empty or fails validation.
        """
        new_rules = load_policy_yaml(new_policy_yaml)
        fingerprint = compute_policy_fingerprint(new_policy_yaml)

        async with self._lock:
            self._last_valid_rules = self._active_rules
            self._active_rules = new_rules
            self._active_version = bundle_version

        logger.info(
            "event=policy_loaded version=%s rule_count=%d fingerprint=%.16s",
            bundle_version,
            len(new_rules),
            fingerprint,
        )
        return True

    async def rollback(self) -> None:
        """Restore the previous known-good policy atomically."""
        async with self._lock:
            self._active_rules, self._last_valid_rules = (
                self._last_valid_rules,
                self._active_rules,
            )
        logger.warning(
            "event=policy_rolled_back previous_version=%s",
            self._active_version,
        )

    async def evaluate(
        self,
        resource: str,
        method: str,
        env: str,
        consumer_did: str,
        vcs: list,
        service_id: str = "*",
    ) -> PolicyDecision:
        """Evaluate without holding the lock during the actual rule scan."""
        async with self._lock:
            rules = self._active_rules  # copy reference
        return self._evaluator.evaluate(
            resource=resource,
            method=method,
            env=env,
            consumer_did=consumer_did,
            vcs=vcs,
            service_id=service_id,
            rules=rules,
        )

    @property
    def active_version(self) -> str:
        return self._active_version

    @property
    def rule_count(self) -> int:
        return len(self._active_rules)
