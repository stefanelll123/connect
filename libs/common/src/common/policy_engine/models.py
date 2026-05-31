"""Policy engine data models (TASK-047)."""
from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Optional


class PolicyDecisionType(str, Enum):
    permit = "permit"
    deny = "deny"


@dataclasses.dataclass(frozen=True)
class PolicyRule:
    """A single ABAC policy rule parsed from YAML."""
    id: str
    service_id_pattern: str    # exact match or fnmatch glob, '*' = any
    path_pattern: str          # fnmatch glob, '**' = any path
    method_pattern: str        # HTTP verb or '*'
    env_pattern: str           # environment name or '*'
    required_scopes: frozenset  # type: ignore[type-arg]  # all must be present (AND)
    required_issuer: Optional[str]
    required_credential_type: Optional[str]
    decision: PolicyDecisionType
    priority: int              # lower = evaluated first


@dataclasses.dataclass
class PolicyDecision:
    """Result of a policy evaluation."""
    permit: bool
    rule_id: Optional[str]
    missing_scopes: list  # type: ignore[type-arg]  # populated for best-match rule only
    extra_context: dict   # type: ignore[type-arg]  # audit only — never returned to caller
    reason: str           # "rule_matched" | "no_matching_rule"
