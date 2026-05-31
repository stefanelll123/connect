"""Error hierarchy for the VC/VP engine (TASK-041)."""
from __future__ import annotations

from enum import Enum


class VCErrorCode(str, Enum):
    VC_EXPIRED = "VC_EXPIRED"
    VC_NBF = "VC_NBF"
    ISSUER_UNTRUSTED = "ISSUER_UNTRUSTED"
    STATUS_REVOKED = "STATUS_REVOKED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    DID_UNRESOLVABLE = "DID_UNRESOLVABLE"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    PARSE_ERROR = "PARSE_ERROR"


class VPErrorCode(str, Enum):
    VP_INVALID = "VP_INVALID"
    VP_AUD_MISMATCH = "VP_AUD_MISMATCH"
    VP_NONCE_MISMATCH = "VP_NONCE_MISMATCH"
    VP_EXPIRED = "VP_EXPIRED"
    VC_ERROR = "VC_ERROR"


class VCError(Exception):
    """Raised when a Verifiable Credential fails validation."""

    def __init__(self, code: VCErrorCode, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else str(code))
        self.code = code
        self.detail = detail


class VPError(Exception):
    """Raised when a Verifiable Presentation fails validation."""

    def __init__(self, code: VPErrorCode, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else str(code))
        self.code = code
        self.detail = detail
