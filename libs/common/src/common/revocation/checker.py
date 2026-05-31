"""Credential status checker with in-process cache and staleness enforcement.

This module implements the 11-step status verification procedure described
in docs/protocols/revocation-mechanism.md §5.

The :class:`StatusListCache` maintains an in-process cache of downloaded
and verified status lists.  The :func:`check_credential_status` function
performs one full-status check against the cache, enforcing the Δ-bounded
freshness policy and detecting hash tampering.

For production deployments, status list refresh happens in a background
scheduler at ``Δ/2`` ± 10 % jitter.  That scheduler is not implemented
here — it is the responsibility of the Sentinel service layer.

Emergency revocation
--------------------
Emergency revocations are maintained as a set of hex-encoded SHA-256
hashes of credential ``jti`` values.  The set is checked on every
invocation of :func:`check_credential_status`.  In a real deployment this
set would be populated from on-chain ``StatusRegistry.emergencyRevoke``
events; here it is passed as an in-process ``frozenset``.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional

from common.revocation.bitstring import check_bit, decode_bitstring
from common.revocation.models import (
    CredentialStatusEntry,
    StalenessMode,
    StalenessPolicy,
    StatusAnchor,
    StatusCheckResult,
    StatusListInfo,
    default_policy_for_env,
)

__all__ = [
    "CachedStatusList",
    "StatusListCache",
    "check_credential_status",
    "hash_jti",
]

# ---------------------------------------------------------------------------
# Cache record
# ---------------------------------------------------------------------------


@dataclass
class CachedStatusList:
    """A single cached status list entry.

    Attributes:
        info: Parsed :class:`~common.revocation.models.StatusListInfo`.
        bitstring_bytes: Decompressed bitstring bytes.
        downloaded_at: Unix timestamp of when this entry was downloaded.
        bitstring_hash: Hex-encoded SHA-256 of the raw decompressed bitstring
            bytes (pre-gzip, pre-base64).  Matches ``current_hash`` stored by
            Discovery and the ``root_hash`` published to the StatusRegistry
            on-chain anchor.  Stable across routine JWT re-signs.
        anchor: On-chain anchor at time of download (may be ``None`` if
            on-chain verification is disabled/unavailable).
    """

    info: StatusListInfo
    bitstring_bytes: bytes
    downloaded_at: int
    bitstring_hash: str
    anchor: Optional[StatusAnchor] = None


class StatusListCache:
    """In-process cache of verified status lists keyed by URL.

    This cache stores the decoded bitstring and metadata.  It does not
    fetch status lists over HTTP — that is the caller's responsibility.
    Use :meth:`put` to insert/update entries and :meth:`get` to retrieve.

    Thread safety: basic — single-process use only.  For multi-instance
    deployments, back this with a shared Redis layer.
    """

    def __init__(self) -> None:
        self._store: dict[str, CachedStatusList] = {}

    def put(self, url: str, entry: CachedStatusList) -> None:
        """Insert or replace the cached entry for *url*."""
        self._store[url] = entry

    def get(self, url: str) -> Optional[CachedStatusList]:
        """Return the cached entry for *url*, or ``None`` if not present."""
        return self._store.get(url)

    def invalidate(self, url: str) -> None:
        """Remove the cached entry for *url*."""
        self._store.pop(url, None)

    def size(self) -> int:
        """Return the number of currently cached entries."""
        return len(self._store)


# ---------------------------------------------------------------------------
# Emergency revoke helper
# ---------------------------------------------------------------------------


def hash_jti(jti: str) -> str:
    """Return the hex SHA-256 hash of *jti*.

    Used as the key for emergency-revoke lookups.

    Args:
        jti: Credential ``jti`` claim (UUID string).

    Returns:
        Hex-encoded SHA-256 digest.
    """
    return hashlib.sha256(jti.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Main status check
# ---------------------------------------------------------------------------


def check_credential_status(
    entry: CredentialStatusEntry,
    *,
    cache: StatusListCache,
    policy: Optional[StalenessPolicy] = None,
    credential_jti: Optional[str] = None,
    emergency_revoked: frozenset[str] = frozenset(),
    expected_anchor: Optional[StatusAnchor] = None,
    now: Optional[int] = None,
) -> StatusCheckResult:
    """Perform a full credential status check (11-step procedure).

    Args:
        entry: The ``credentialStatus`` object from the VC being checked.
        cache: The :class:`StatusListCache` holding downloaded status lists.
        policy: Freshness / staleness policy.  Defaults to the ``"prod"``
            default (:data:`~common.revocation.models._ENV_DEFAULTS`).
        credential_jti: The ``jti`` of the VC being checked.  Required for
            emergency-revocation detection.
        emergency_revoked: Set of hex SHA-256 hashes of revoked ``jti``
            values (populated from on-chain events).
        expected_anchor: If provided, verify that the cached entry's
            ``bitstring_hash`` matches ``expected_anchor.root_hash``.
        now: Override the current timestamp (for testing).

    Returns:
        A :class:`~common.revocation.models.StatusCheckResult`.
    """
    if policy is None:
        policy = default_policy_for_env("prod")
    if now is None:
        now = int(time.time())

    # ------------------------------------------------------------------ 1
    # Emergency revocation check (bypass status list — check first)
    # ------------------------------------------------------------------ 1
    if credential_jti and emergency_revoked:
        jti_hash = hash_jti(credential_jti)
        if jti_hash in emergency_revoked:
            return StatusCheckResult.EMERGENCY_REVOKED

    # ------------------------------------------------------------------ 2
    # Retrieve status list from cache
    # ------------------------------------------------------------------ 2
    url = entry.statusListCredential
    cached = cache.get(url)

    if cached is None:
        # No cache entry → treat as unavailable
        if policy.mode == StalenessMode.FAIL_CLOSED:
            return StatusCheckResult.STALE_FAIL_CLOSED
        return StatusCheckResult.LIST_UNAVAILABLE

    # ------------------------------------------------------------------ 3
    # Staleness check: now - downloaded_at > Δ
    # ------------------------------------------------------------------ 3
    age = now - cached.downloaded_at
    if age > policy.delta_seconds:
        if policy.mode == StalenessMode.FAIL_CLOSED:
            return StatusCheckResult.STALE_FAIL_CLOSED
        # FAIL_OPEN_DEGRADED and ALLOW_WITH_WARNING continue with stale data
        # (the caller is responsible for logging a warning metric)

    # ------------------------------------------------------------------ 4
    # On-chain anchor hash verification
    # ------------------------------------------------------------------ 4
    if expected_anchor is not None:
        if cached.bitstring_hash != expected_anchor.root_hash:
            return StatusCheckResult.HASH_MISMATCH

    # ------------------------------------------------------------------ 5
    # Index bounds check
    # ------------------------------------------------------------------ 5
    index = entry.index
    if index < 0 or index >= len(cached.bitstring_bytes) * 8:
        return StatusCheckResult.INDEX_OUT_OF_RANGE

    # ------------------------------------------------------------------ 6
    # Bit check: bit == 1 → revoked
    # ------------------------------------------------------------------ 6
    try:
        is_revoked = check_bit(cached.bitstring_bytes, index)
    except IndexError:
        return StatusCheckResult.INDEX_OUT_OF_RANGE

    if is_revoked:
        return StatusCheckResult.REVOKED

    return StatusCheckResult.NOT_REVOKED


# ---------------------------------------------------------------------------
# Cache population helpers
# ---------------------------------------------------------------------------


def build_cached_entry(
    status_list_info: StatusListInfo,
    raw_jwt_bytes: bytes,
    anchor: Optional[StatusAnchor] = None,
    now: Optional[int] = None,
) -> CachedStatusList:
    """Build a :class:`CachedStatusList` entry from a verified JWT.

    Args:
        status_list_info: Parsed claims from the status list JWT.
        raw_jwt_bytes: The full JWT bytes (kept for API compatibility but no
            longer used for hashing — the bitstring hash is used instead).
        anchor: Optional on-chain anchor record.
        now: Override current timestamp (for testing).

    Returns:
        A ready-to-cache :class:`CachedStatusList`.
    """
    bitstring_bytes = decode_bitstring(status_list_info.encoded_list)
    # Hash the raw decompressed bitstring bytes — same as Discovery's current_hash
    # and the value published to the StatusRegistry on-chain anchor.
    bitstring_hash = hashlib.sha256(bitstring_bytes).hexdigest()
    return CachedStatusList(
        info=status_list_info,
        bitstring_bytes=bitstring_bytes,
        downloaded_at=now if now is not None else int(time.time()),
        bitstring_hash=bitstring_hash,
        anchor=anchor,
    )
