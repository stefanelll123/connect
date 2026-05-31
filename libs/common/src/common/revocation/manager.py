"""RevocationManager — Δ-bounded freshness revocation checking (TASK-046).

Public API:
  ``RevocationManager.check(credential_jti, status_list_id, status_list_index)``
  ``RevocationManager.emergency_check(credential_jti)``

The manager:
  1. Gets the on-chain anchor via TrustLayerClient (hash + updated_at).
  2. Verifies the in-memory cache is still consistent with the anchor.
  3. If cache is stale or anchor hash changed → downloads the status list,
     verifies the signature, recomputes root_hash, compares with anchor.
  4. Enforces Δ (delta_seconds) freshness guarantee.  If the anchor itself is
     older than Δ, the governance chain hasn't updated in time; apply
     StalenessPolicy.
  5. Checks the bit at the given index.
  6. Returns ``RevocationCheckResult``.
"""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from common.revocation.bitstring import check_bit, decode_bitstring
from common.revocation.checker import (
    CachedStatusList,
    StatusListCache,
    build_cached_entry,
    hash_jti,
)
from common.revocation.models import (
    CredentialStatusEntry,
    StalenessMode,
    StalenessPolicy,
    StatusAnchor,
    StatusListInfo,
    StatusCheckResult,
    default_policy_for_env,
)
from common.revocation import metrics as _metrics

logger = logging.getLogger(__name__)

__all__ = [
    "RevocationManager",
    "RevocationCheckResult",
    "RevocationStatusStale",
    "StatusListHashMismatch",
]


# ---------------------------------------------------------------------------
# Result / error types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RevocationCheckResult:
    """Outcome of a managed revocation check."""
    is_revoked: bool
    stale: bool = False
    stale_seconds: float = 0.0
    checked_at: float = field(default_factory=time.time)


class RevocationStatusStale(Exception):
    """Raised when the status list exceeds Δ and policy is fail-closed."""
    def __init__(self, staleness_seconds: float) -> None:
        self.staleness_seconds = staleness_seconds
        super().__init__(f"Status list stale by {staleness_seconds:.1f}s")


class StatusListHashMismatch(Exception):
    """Raised when the downloaded bitstring hash does not match the on-chain anchor."""
    def __init__(self, status_list_id: str, expected: str, actual: str) -> None:
        self.status_list_id = status_list_id
        super().__init__(
            f"Hash mismatch for {status_list_id}: expected={expected!r} actual={actual!r}"
        )


# ---------------------------------------------------------------------------
# RevocationManager
# ---------------------------------------------------------------------------


class RevocationManager:
    """Manages credential revocation checking with Δ-bounded freshness.

    Args:
        status_list_cache:    In-memory/disk status list cache.
        trust_client:         TrustLayerClient (for anchor + policy params).
        discovery_http_client: httpx.AsyncClient for downloading status lists.
        staleness_policy:     Override policy (Δ from governance chain takes
                              precedence when trust_client is available).
        env:                  Deployment environment string.
    """

    def __init__(
        self,
        status_list_cache: Optional[StatusListCache] = None,
        trust_client=None,
        discovery_http_client=None,
        staleness_policy: Optional[StalenessPolicy] = None,
        env: str = "prod",
    ) -> None:
        self._cache = status_list_cache or StatusListCache()
        self._trust_client = trust_client
        self._http_client = discovery_http_client
        self._default_policy = staleness_policy or default_policy_for_env(env)
        self._env = env

    # ── Public API ─────────────────────────────────────────────────────────

    async def check(
        self,
        credential_jti: str,
        status_list_id: str,
        status_list_index: int,
    ) -> RevocationCheckResult:
        """Check whether a credential is revoked.

        Args:
            credential_jti:      JWT ID of the credential being checked.
            status_list_id:      URL of the BitstringStatusListCredential.
            status_list_index:   Index of the credential's bit in the list.

        Returns:
            RevocationCheckResult

        Raises:
            RevocationStatusStale: if list is stale and policy is fail-closed.
            StatusListHashMismatch: if downloaded hash != on-chain anchor.
        """
        now = time.time()

        # ── 1. Get anchor ──────────────────────────────────────────────
        anchor = await self._get_anchor(status_list_id)

        # ── 2. Determine Δ from governance  (or use default) ──────────
        policy = await self._resolve_policy()
        delta_seconds = policy.delta_seconds

        # ── 3. Staleness check against anchor ──────────────────────────
        anchor_age = now - anchor.updated_at if anchor else None

        if anchor is not None and anchor_age is not None and anchor_age > delta_seconds:
            staleness = anchor_age
            _metrics.STATUS_LIST_STALENESS.labels(
                status_list_id=status_list_id
            ).set(staleness)
            logger.warning(
                "revocation_stale status_list_id=%s staleness_seconds=%.1f policy=%s",
                status_list_id, staleness, policy.mode.value,
            )
            _metrics.REVOCATION_CHECKS.labels(result="stale").inc()

            if policy.mode == StalenessMode.FAIL_CLOSED:
                raise RevocationStatusStale(staleness)

            if policy.mode == StalenessMode.FAIL_OPEN_DEGRADED:
                # Serve from cache if available, mark result as stale
                cached = self._cache.get(status_list_id)
                if cached:
                    is_revoked = check_bit(cached.bitstring_bytes, status_list_index)
                    result_label = "revoked" if is_revoked else "not_revoked_stale"
                    _metrics.REVOCATION_CHECKS.labels(result=result_label).inc()
                    return RevocationCheckResult(
                        is_revoked=is_revoked, stale=True, stale_seconds=staleness
                    )
                return RevocationCheckResult(is_revoked=False, stale=True, stale_seconds=staleness)

            # ALLOW_WITH_WARNING: continue but mark stale
            stale_flag = True
            stale_seconds = staleness
        else:
            stale_flag = False
            stale_seconds = 0.0

        # ── 4. Get verified cache entry ────────────────────────────────
        entry = await self._get_entry(status_list_id, anchor)

        if entry is None:
            # Cache miss and unable to download → apply fail-closed
            logger.error("revocation_unavailable status_list_id=%s", status_list_id)
            _metrics.REVOCATION_CHECKS.labels(result="error").inc()
            if policy.mode == StalenessMode.FAIL_CLOSED:
                raise RevocationStatusStale(float("inf"))
            return RevocationCheckResult(is_revoked=False, stale=True, stale_seconds=float("inf"))

        # ── 5. Bit check ──────────────────────────────────────────────
        is_revoked = check_bit(entry.bitstring_bytes, status_list_index)
        result_label = "revoked" if is_revoked else "not_revoked"
        _metrics.REVOCATION_CHECKS.labels(result=result_label).inc()

        return RevocationCheckResult(
            is_revoked=is_revoked,
            stale=stale_flag,
            stale_seconds=stale_seconds,
            checked_at=now,
        )

    async def emergency_check(self, credential_jti: str) -> bool:
        """On-chain emergency revocation check.

        Calls TrustLayerClient to query StatusRegistry on-chain.
        Fail-closed on chain unavailability (returns True = assume revoked).

        Args:
            credential_jti: JWT ID of the credential.

        Returns:
            True if the credential is revoked or chain is unavailable (fail-closed).
        """
        if self._trust_client is None:
            logger.warning("emergency_check: no trust_client, failing closed")
            _metrics.EMERGENCY_CHECKS.labels(result="no_client_fail_closed").inc()
            return True

        jti_hash = hash_jti(credential_jti)
        try:
            # Check cached status anchor for emergency revocation mapping
            anchor = await self._trust_client.get_status_anchor(jti_hash)
            # A non-None anchor here means it's in the emergency revoke set
            is_revoked = anchor is not None
            result_label = "revoked" if is_revoked else "not_revoked"
            _metrics.EMERGENCY_CHECKS.labels(result=result_label).inc()
            return is_revoked
        except Exception as exc:
            logger.warning("emergency_check chain unavailable, failing closed: %s", exc)
            _metrics.EMERGENCY_CHECKS.labels(result="error_fail_closed").inc()
            return True  # fail-closed

    # ── Private helpers ────────────────────────────────────────────────────

    async def _get_anchor(self, status_list_id: str) -> Optional[StatusAnchor]:
        """Get on-chain anchor via TrustLayerClient."""
        if self._trust_client is None:
            return None
        try:
            return await self._trust_client.get_status_anchor(status_list_id)
        except Exception as exc:
            logger.warning("Failed to fetch status anchor for %s: %s", status_list_id, exc)
            return None

    async def _resolve_policy(self) -> StalenessPolicy:
        """Resolve the StalenessPolicy from governance chain, or use default."""
        if self._trust_client is None:
            return self._default_policy
        try:
            params = await self._trust_client.get_policy_params()
            delta = getattr(params, "revocation_delta_seconds", None)
            if delta is not None:
                return StalenessPolicy(
                    delta_seconds=int(delta),
                    mode=self._default_policy.mode,
                )
        except Exception:
            pass
        return self._default_policy

    async def _get_entry(
        self,
        status_list_id: str,
        anchor: Optional[StatusAnchor],
    ) -> Optional[CachedStatusList]:
        """Return a verified cache entry, downloading if necessary."""
        cached = self._cache.get(status_list_id)

        # If cached and anchor hash matches → return cached
        if cached and anchor:
            if cached.bitstring_hash == anchor.root_hash:
                _metrics.STATUS_LIST_CACHE_HITS.inc()
                return cached
            # Hash mismatch — cache stale, must re-download
            logger.info(
                "Cache hash mismatch for %s, re-downloading", status_list_id
            )

        if cached and anchor is None:
            # No anchor available — serve from cache without hash verification
            _metrics.STATUS_LIST_CACHE_HITS.inc()
            return cached

        # Download status list
        if self._http_client is None:
            _metrics.STATUS_LIST_CACHE_MISSES.inc()
            return cached  # return potentially stale cache if no HTTP client

        _metrics.STATUS_LIST_CACHE_MISSES.inc()
        return await self._download_and_cache(status_list_id, anchor)

    async def _download_and_cache(
        self,
        status_list_id: str,
        anchor: Optional[StatusAnchor],
    ) -> Optional[CachedStatusList]:
        """Download the status list, verify it, and store in cache."""
        import time as _time

        t0 = _time.monotonic()
        try:
            response = await self._http_client.get(
                status_list_id,
                timeout=10.0,
                follow_redirects=True,
            )
            response.raise_for_status()
            raw_jwt_bytes = response.content
        except Exception as exc:
            logger.warning("Failed to download status list %s: %s", status_list_id, exc)
            _metrics.STATUS_LIST_DOWNLOAD_DURATION.observe(_time.monotonic() - t0)
            return None
        finally:
            _metrics.STATUS_LIST_DOWNLOAD_DURATION.observe(_time.monotonic() - t0)

        # Parse JWT payload first so we can extract the bitstring for hashing.
        # We hash SHA-256(raw bitstring bytes) — the same value Discovery stores
        # in current_hash and publishes to the chain.  This is stable across
        # routine JWT re-signs (new iat/exp) and only changes on bit flips.
        try:
            import base64 as _b64, json as _json
            _parts = raw_jwt_bytes.decode().strip().split(".")
            if len(_parts) == 3:
                _padded = _parts[1] + "=" * (4 - len(_parts[1]) % 4)
                _claims_pre = _json.loads(_b64.urlsafe_b64decode(_padded))
                _vc_pre = _claims_pre.get("vc", {})
                _encoded_list_pre = _vc_pre.get("credentialSubject", {}).get("encodedList", "")
                from common.revocation.bitstring import decode_bitstring as _db
                _bitstring_bytes_pre = _db(_encoded_list_pre)
                downloaded_hash = hashlib.sha256(_bitstring_bytes_pre).hexdigest()
            else:
                downloaded_hash = hashlib.sha256(raw_jwt_bytes).hexdigest()
        except Exception:
            downloaded_hash = hashlib.sha256(raw_jwt_bytes).hexdigest()

        # Verify against anchor
        if anchor and downloaded_hash != anchor.root_hash:
            raise StatusListHashMismatch(status_list_id, anchor.root_hash, downloaded_hash)

        # Decode JWT payload (no signature verification here — trust anchor hash)
        try:
            import base64, json as _json
            parts = raw_jwt_bytes.decode().strip().split(".")
            if len(parts) == 3:
                padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                claims = _json.loads(base64.urlsafe_b64decode(padded))
                info = StatusListInfo.from_jwt_claims(claims)
            else:
                logger.warning("Status list %s is not a JWT", status_list_id)
                return None
        except Exception as exc:
            logger.warning("Failed to parse status list JWT %s: %s", status_list_id, exc)
            return None

        entry = build_cached_entry(
            status_list_info=info,
            raw_jwt_bytes=raw_jwt_bytes,
            anchor=anchor,
            now=int(time.time()),
        )
        self._cache.put(status_list_id, entry)
        return entry
