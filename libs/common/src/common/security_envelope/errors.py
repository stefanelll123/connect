"""ProofError codes for the Sentinel request security envelope (TASK-043)."""
from __future__ import annotations

from enum import Enum


class ProofErrorCode(str, Enum):
    # 401 — authentication / integrity failures
    MISSING_PROOF = "MISSING_PROOF"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    PROOF_EXPIRED = "PROOF_EXPIRED"
    CLOCK_SKEW_EXCEEDED = "CLOCK_SKEW_EXCEEDED"
    BODY_HASH_MISMATCH = "BODY_HASH_MISMATCH"
    QUERY_HASH_MISMATCH = "QUERY_HASH_MISMATCH"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    MISSING_VP = "MISSING_VP"
    VP_INVALID = "VP_INVALID"
    VP_VC_INVALID = "VP_VC_INVALID"
    BODY_TOO_LARGE = "BODY_TOO_LARGE"
    # 403 — authorisation / policy failures
    AUD_MISMATCH = "AUD_MISMATCH"
    ENV_MISMATCH = "ENV_MISMATCH"


class ProofError(Exception):
    """Exception raised by the security envelope on any verification failure.

    Attributes:
        code:   Machine-readable ``ProofErrorCode``.
        detail: Human-readable debugging detail (NOT included in HTTP responses).
    """

    def __init__(self, code: ProofErrorCode, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail

    def is_4xx(self) -> bool:
        """True if this is a 401/403 class error."""
        return self.code not in ()

    @property
    def http_status(self) -> int:
        """HTTP status code appropriate for this error."""
        if self.code in (ProofErrorCode.AUD_MISMATCH, ProofErrorCode.ENV_MISMATCH):
            return 403
        if self.code == ProofErrorCode.BODY_TOO_LARGE:
            return 413
        return 401
