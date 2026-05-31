"""Security envelope public API (TASK-043)."""
from common.security_envelope.builder import (
    ProofClaimsBuilder,
    build_secure_headers,
    compute_body_hash,
    compute_query_hash,
    MAX_BODY_SIZE,
)
from common.security_envelope.errors import ProofError, ProofErrorCode
from common.security_envelope.replay_cache import ReplayCache
from common.security_envelope.verifier import ProofVerifier, VerificationContext

__all__ = [
    "ProofClaimsBuilder",
    "ProofVerifier",
    "ReplayCache",
    "VerificationContext",
    "ProofError",
    "ProofErrorCode",
    "build_secure_headers",
    "compute_body_hash",
    "compute_query_hash",
    "MAX_BODY_SIZE",
]
