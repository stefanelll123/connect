"""PipelineContext — mutable state threaded through the 8-stage inbound pipeline (TASK-045)."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PipelineContext:
    """Mutable bag of state accumulated as each pipeline stage succeeds.

    The context is created at request ingestion (stage 0) and populated
    progressively by each stage.  It is never serialised externally — only
    used for intra-request state passing and final audit logging.
    """

    # ── Set at creation ────────────────────────────────────────────────
    request_id: str
    """UUID correlation id (from X-Correlation-ID or generated)."""

    method: str
    path: str
    service_id: str
    env: str

    # ── Populated after Stage 3 (ProofVerifier) ───────────────────────
    consumer_did: str = ""
    jti: str = ""
    proof_claims: Dict[str, Any] = field(default_factory=dict)

    # ── Populated after Stage 4 (VP / VC verification) ────────────────
    verified_vcs: List[Any] = field(default_factory=list)

    # ── Populated after Stage 5 (trust checks) ────────────────────────
    trust_checked: bool = False

    # ── Populated after Stage 6 (revocation) ──────────────────────────
    revocation_checked: bool = False
    stale_revocation: bool = False

    # ── Populated after Stage 7 (policy) ──────────────────────────────
    policy_rule_id: str = ""

    # ── Timing ────────────────────────────────────────────────────────
    started_at: float = field(default_factory=time.monotonic)
    stage_timings: Dict[str, float] = field(default_factory=dict)
    denied_at_stage: Optional[str] = None
    error_code: Optional[str] = None

    # ── Body bytes (set in Stage 1, used throughout) ──────────────────
    body: bytes = b""

    def record_stage(self, stage: str) -> None:
        """Record the elapsed time for *stage* from request start."""
        self.stage_timings[stage] = (time.monotonic() - self.started_at) * 1000

    def latency_ms(self) -> float:
        """Total pipeline latency in milliseconds."""
        return (time.monotonic() - self.started_at) * 1000

    def jti_hash(self) -> str:
        """First 16 hex chars of SHA-256(jti) — safe for audit logs."""
        import hashlib
        return hashlib.sha256(self.jti.encode()).hexdigest()[:16] if self.jti else ""

    def consumer_did_hash(self) -> str:
        """First 16 hex chars of SHA-256(consumer_did) — safe for audit logs."""
        import hashlib
        return hashlib.sha256(self.consumer_did.encode()).hexdigest()[:16] if self.consumer_did else ""
