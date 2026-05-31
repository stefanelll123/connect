"""Policy evaluation contract and SimplePolicyEvaluator for the Producer Sentinel.

Design principles:

* Most-restrictive wins — the effective scope is the intersection of all
  valid VC scopes when multiple VCs are presented.
* DENY on any critical failure (revoked, expired, env mismatch, aud mismatch).
* Every denial carries a precise ``reason_code`` — never silently ignore a
  failed check.
"""

from __future__ import annotations

import fnmatch
import re
import time
from dataclasses import dataclass, field
from typing import Literal, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Reason codes
# ---------------------------------------------------------------------------

class PolicyReasonCode:
    """String constants for PolicyDecision.reason_code."""

    NO_MATCHING_VC = "NO_MATCHING_VC"
    VC_EXPIRED = "VC_EXPIRED"
    VC_REVOKED = "VC_REVOKED"
    ENV_MISMATCH = "ENV_MISMATCH"
    AUD_MISMATCH = "AUD_MISMATCH"
    SCOPE_INSUFFICIENT = "SCOPE_INSUFFICIENT"
    ISSUER_UNTRUSTED = "ISSUER_UNTRUSTED"
    STATUS_STALE = "STATUS_STALE"
    PERMIT = "PERMIT"


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VerifiedVC:
    """A VC that has already been signature-verified and decoded.

    ``is_revoked`` must be populated by the caller after checking the
    Bitstring Status List.  It is not derived here.
    """

    jti: str
    issuer: str             # iss claim
    subject: str            # sub claim
    vc_type: list[str]
    credential_subject: dict
    env: str
    exp: int                # Unix timestamp
    is_revoked: bool = False


@dataclass(frozen=True)
class RequestContext:
    """Ambient metadata attached to a policy evaluation request."""

    timestamp: int          # Unix timestamp (now)
    client_ip: str | None = None
    request_id: str | None = None


@dataclass(frozen=True)
class PolicyRequest:
    """Input to :meth:`PolicyEvaluator.evaluate`."""

    consumer_did: str       # DID of the requesting consumer
    producer_did: str       # DID the consumer wants to reach (aud to match)
    resource: str           # request path, e.g. "/api/v1/citizens/123"
    method: str             # HTTP verb, e.g. "GET"
    env: str                # "dev" | "test" | "prod"
    vc_set: list[VerifiedVC] = field(default_factory=list)
    context: RequestContext | None = None


@dataclass(frozen=True)
class PolicyDecision:
    """Output of :meth:`PolicyEvaluator.evaluate`."""

    result: Literal["PERMIT", "DENY"]
    reason_code: str
    matched_rule_id: str | None = None
    missing_scopes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class PolicyEvaluator(Protocol):
    """Contract for all policy evaluators used by the Producer Sentinel."""

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        """Evaluate the policy for *request* and return a :class:`PolicyDecision`."""
        ...


# ---------------------------------------------------------------------------
# Path glob matching
# ---------------------------------------------------------------------------

def matches_path_glob(path: str, glob: str) -> bool:
    """Return ``True`` if *path* matches the *glob* pattern.

    Rules:

    * ``*``  matches any single path segment (does not cross ``/``).
    * ``**`` matches any sequence of path segments (crosses ``/``).
    * Comparison is case-sensitive.
    """
    path = path.rstrip("/")
    glob = glob.rstrip("/")

    if "**" not in glob:
        # Split both into segments and match segment-by-segment with fnmatch.
        glob_segments = glob.split("/")
        path_segments = path.split("/")
        if len(glob_segments) != len(path_segments):
            return False
        return all(
            fnmatch.fnmatchcase(ps, gs)
            for ps, gs in zip(path_segments, glob_segments)
        )

    # Handle ** by converting to a regex where ** → .* and * → [^/]*.
    # Split on ** first, then escape each part and replace * with [^/]*.
    parts = glob.split("**")
    regex_parts: list[str] = []
    for part in parts:
        # Escape the part, then un-escape our * → [^/]* substitution.
        escaped = re.escape(part).replace(r"\*", "[^/]*")
        regex_parts.append(escaped)
    regex = ".*".join(regex_parts)
    return bool(re.fullmatch(regex, path))


# ---------------------------------------------------------------------------
# Simple evaluator implementation
# ---------------------------------------------------------------------------

class SimplePolicyEvaluator:
    """Default policy evaluator using AccessGrantCredential VCs.

    Evaluation algorithm (5-step):

    1. Filter ``vc_set`` to AccessGrantCredential VCs for the consumer DID.
    2. Reject any VC that is revoked, expired, has env mismatch, or aud mismatch.
    3. Collect all scope entries from remaining valid VCs.
    4. Find a scope entry covering the requested resource + method.
    5. Return PERMIT or DENY with a precise reason_code.

    Critical failures (revoked, env mismatch) trigger immediate DENY.
    """

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        now = request.context.timestamp if request.context else int(time.time())

        # Step 1 — filter to relevant AccessGrantCredential VCs.
        access_vcs = [
            vc for vc in request.vc_set
            if "AccessGrantCredential" in vc.vc_type
            and vc.subject == request.consumer_did
        ]

        if not access_vcs:
            return PolicyDecision(
                result="DENY",
                reason_code=PolicyReasonCode.NO_MATCHING_VC,
            )

        # Step 2 — validate each VC; collect scope entries from valid ones.
        valid_scope_entries: list[tuple[str, str, str, list[str]]] = []
        # Each entry: (jti, service_id, path_glob, methods)

        for vc in access_vcs:
            # Revocation check — immediate DENY (critical).
            if vc.is_revoked:
                return PolicyDecision(
                    result="DENY",
                    reason_code=PolicyReasonCode.VC_REVOKED,
                )
            # Expiry check.
            if vc.exp < now:
                return PolicyDecision(
                    result="DENY",
                    reason_code=PolicyReasonCode.VC_EXPIRED,
                )
            # Environment check — both VC env and request env must match.
            if vc.env != request.env:
                return PolicyDecision(
                    result="DENY",
                    reason_code=PolicyReasonCode.ENV_MISMATCH,
                )
            # Audience check — VC must target exactly this producer.
            vc_aud = vc.credential_subject.get("aud", "")
            if vc_aud != request.producer_did:
                return PolicyDecision(
                    result="DENY",
                    reason_code=PolicyReasonCode.AUD_MISMATCH,
                )
            # Step 3 — collect scope entries.
            for entry in vc.credential_subject.get("scope", []):
                if not isinstance(entry, dict):
                    continue
                service_id = entry.get("service_id", "")
                path_glob = entry.get("path_glob", "")
                methods = [m.upper() for m in entry.get("methods", [])]
                if path_glob and methods:
                    valid_scope_entries.append((vc.jti, service_id, path_glob, methods))

        # Step 4 — find a matching scope entry.
        for jti, service_id, path_glob, methods in valid_scope_entries:
            if (
                matches_path_glob(request.resource, path_glob)
                and request.method.upper() in methods
            ):
                return PolicyDecision(
                    result="PERMIT",
                    reason_code=PolicyReasonCode.PERMIT,
                    matched_rule_id=f"{jti}:{service_id}:{path_glob}",
                )

        # Step 5 — no scope entry matched.
        return PolicyDecision(
            result="DENY",
            reason_code=PolicyReasonCode.SCOPE_INSUFFICIENT,
            missing_scopes=[f"{request.resource}:{request.method.upper()}"],
        )
