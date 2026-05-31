"""Credential revocation: Bitstring Status List v1.0 + Δ-bounded freshness."""

from common.revocation.manager import (
    RevocationManager,
    RevocationCheckResult,
    RevocationStatusStale,
    StatusListHashMismatch,
)
from common.revocation.refresher import StatusListRefresher
from common.revocation.bitstring import (
    encode_bitstring,
    decode_bitstring,
    check_bit,
    set_bit,
    create_status_list,
    revoke_credential,
    MIN_BITSTRING_SIZE,
    MAX_BITSTRING_SIZE,
)
from common.revocation.models import (
    CredentialStatusEntry,
    StatusListInfo,
    StalenessMode,
    StalenessPolicy,
    StatusAnchor,
    StatusCheckResult,
    default_policy_for_env,
)
from common.revocation.checker import (
    CachedStatusList,
    StatusListCache,
    check_credential_status,
    build_cached_entry,
    hash_jti,
)

__all__ = [
    "RevocationManager",
    "RevocationCheckResult",
    "RevocationStatusStale",
    "StatusListHashMismatch",
    "StatusListRefresher",
    "encode_bitstring",
    "decode_bitstring",
    "check_bit",
    "set_bit",
    "create_status_list",
    "revoke_credential",
    "MIN_BITSTRING_SIZE",
    "MAX_BITSTRING_SIZE",
    "CredentialStatusEntry",
    "StatusListInfo",
    "StalenessMode",
    "StalenessPolicy",
    "StatusAnchor",
    "StatusCheckResult",
    "default_policy_for_env",
    "CachedStatusList",
    "StatusListCache",
    "check_credential_status",
    "build_cached_entry",
    "hash_jti",
]
