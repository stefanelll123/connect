"""Request security envelope: ProofClaims builder/verifier and replay cache."""

from common.proof.models import ProofClaims, ReqBinding, DEFAULT_PROOF_TTL, MAX_PROOF_TTL
from common.proof.hash_utils import EMPTY_HASH, hash_bytes, hash_query, hash_body, body_hash_for_method, normalize_content_type
from common.proof.builder import build_proof, build_req_binding
from common.proof.verifier import ProofVerificationError, VerificationConfig, verify_proof
from common.proof.replay_cache import ReplayCache, InMemoryReplayCache, RedisReplayCache, make_cache_key

__all__ = [
    "ProofClaims",
    "ReqBinding",
    "DEFAULT_PROOF_TTL",
    "MAX_PROOF_TTL",
    "EMPTY_HASH",
    "hash_bytes",
    "hash_query",
    "hash_body",
    "body_hash_for_method",
    "normalize_content_type",
    "build_proof",
    "build_req_binding",
    "ProofVerificationError",
    "VerificationConfig",
    "verify_proof",
    "ReplayCache",
    "InMemoryReplayCache",
    "RedisReplayCache",
    "make_cache_key",
]
