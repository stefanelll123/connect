"""Policy YAML loader and fingerprint computation (TASK-047).

Policies must be parsed with ``yaml.safe_load`` to prevent YAML deserialization
attacks (CWE-502).  Policy MUST only be loaded from a cryptographically verified
config bundle — no unsigned loading.
"""
from __future__ import annotations

import hashlib
import logging
from typing import List

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:  # pragma: no cover
    _YAML_AVAILABLE = False
    yaml = None  # type: ignore[assignment]

from common.policy_engine.models import PolicyDecisionType, PolicyRule

logger = logging.getLogger(__name__)

_MAX_RULES = 500


def load_policy_yaml(yaml_str: str) -> List[PolicyRule]:
    """Parse, validate and sort a YAML policy string into ``PolicyRule`` objects.

    Args:
        yaml_str: Raw YAML string (from a verified config bundle).

    Returns:
        List of ``PolicyRule`` instances sorted by priority (ascending).

    Raises:
        ValueError: if the policy is empty, malformed, or fails validation.
        ImportError: if PyYAML is not installed.
    """
    if not _YAML_AVAILABLE:
        raise ImportError("PyYAML is required for the policy engine: pip install pyyaml")

    if not yaml_str or not yaml_str.strip():
        raise ValueError("Empty policy YAML")

    data = yaml.safe_load(yaml_str)  # type: ignore[union-attr]
    if not isinstance(data, dict):
        raise ValueError("Policy YAML root must be a mapping")

    rules_data = data.get("rules") or []
    if not isinstance(rules_data, list) or not rules_data:
        raise ValueError("Policy must contain at least one rule under 'rules:'")

    if len(rules_data) > _MAX_RULES:
        raise ValueError(f"Policy has {len(rules_data)} rules; maximum is {_MAX_RULES}")

    rules: List[PolicyRule] = []
    seen_ids: set = set()

    for raw in rules_data:
        if not isinstance(raw, dict):
            raise ValueError(f"Each rule must be a dict, got: {type(raw).__name__}")

        rule_id = str(raw.get("id", "")).strip()
        if not rule_id:
            raise ValueError("Every rule must have a non-empty 'id' field")
        if rule_id in seen_ids:
            raise ValueError(f"Duplicate rule id: {rule_id!r}")
        seen_ids.add(rule_id)

        decision_str = str(raw.get("decision", "")).strip().lower()
        if decision_str not in ("permit", "deny"):
            raise ValueError(f"Rule {rule_id!r}: 'decision' must be 'permit' or 'deny'")

        raw_scopes = raw.get("required_scopes") or []
        if not isinstance(raw_scopes, list):
            raise ValueError(f"Rule {rule_id!r}: 'required_scopes' must be a list")
        for s in raw_scopes:
            if not isinstance(s, str) or not s.strip():
                raise ValueError(f"Rule {rule_id!r}: scopes must be non-empty strings")

        rules.append(
            PolicyRule(
                id=rule_id,
                service_id_pattern=str(raw.get("service_id", "*") or "*"),
                path_pattern=str(raw.get("path_glob", "**") or "**"),
                method_pattern=str(raw.get("method", "*") or "*").upper(),
                env_pattern=str(raw.get("env", "*") or "*"),
                required_scopes=frozenset(raw_scopes),
                required_issuer=raw.get("required_issuer") or None,
                required_credential_type=raw.get("required_credential_type") or None,
                decision=PolicyDecisionType(decision_str),
                priority=int(raw.get("priority", 100)),
            )
        )

    rules.sort(key=lambda r: r.priority)

    version = str(data.get("version", ""))
    logger.debug(
        "event=policy_yaml_parsed version=%s rule_count=%d",
        version,
        len(rules),
    )
    return rules


def compute_policy_fingerprint(yaml_str: str) -> str:
    """Return SHA-256 hex fingerprint of the policy YAML bytes."""
    return hashlib.sha256(yaml_str.encode()).hexdigest()
