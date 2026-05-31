# Revocation and Status Mechanism

**Status:** Implemented  
**Component:** Security — Credential Lifecycle  
**Depends on:** TASK-003 (Cryptography Suite), TASK-004 (VC Schemas)

---

## 1. Overview

Credential revocation in this system follows the **W3C Bitstring Status List v1.0** specification. The Discovery service publishes signed *StatusListCredentials* as JWT-VCs. Each Verifiable Credential references a specific bit in one of these lists. Producer Sentinels cache the status lists locally, validate their integrity against on-chain hash anchors, and enforce a **bounded-freshness parameter Δ** that controls how stale a cached list may be before enforcement mode changes.

This document specifies the credential status structure, publishing workflow, caching model, staleness modes, on-chain anchoring, emergency revocation path, and the complete status verification procedure.

---

## 2. Credential Status Object

Every `AccessGrantCredential` includes a `credentialStatus` claim conforming to W3C Bitstring Status List v1.0 §2:

```json
{
  "id": "https://discovery.example.gov/api/v1/status/list-001#42",
  "type": "BitstringStatusListEntry",
  "statusListIndex": "42",
  "statusListCredential": "https://discovery.example.gov/api/v1/status/list-001",
  "statusPurpose": "revocation"
}
```

| Field | Description |
|---|---|
| `id` | Status entry URI: `<statusListCredential>#<index>` |
| `type` | Always `"BitstringStatusListEntry"` |
| `statusListIndex` | Decimal string — the credential's zero-based bit position in the bitstring |
| `statusListCredential` | HTTPS URL of the `BitstringStatusListCredential` JWT |
| `statusPurpose` | `"revocation"` or `"suspension"` |

The index is assigned at issuance time and stored in the Discovery database. Each status list holds up to **131 072 credentials** (2¹⁷ bits, 16 KiB uncompressed — the W3C spec minimum).

---

## 3. BitstringStatusListCredential Format

The status list itself is a JWT-VC whose payload is:

```json
{
  "jti": "urn:uuid:<uuid-v4>",
  "iss": "did:key:<discovery_public_key>",
  "sub": "https://discovery.example.gov/api/v1/status/list-001",
  "iat": 1741910400,
  "exp": 1741996800,
  "vc": {
    "type": ["VerifiableCredential", "BitstringStatusListCredential"],
    "credentialSubject": {
      "id": "https://discovery.example.gov/api/v1/status/list-001",
      "type": "BitstringStatusList",
      "statusPurpose": "revocation",
      "encodedList": "<base64url(gzip(bitstring_bytes))>"
    }
  }
}
```

### 3.1 Bitstring Encoding

The bitstring is a packed sequence of bits, one per credential entry, using **MSB-first (big-endian) bit ordering**:

- Credential at index $N$ occupies **byte** $\lfloor N/8 \rfloor$ and **bit** $(7 - (N \bmod 8))$ of that byte.
- Bit value `0` → credential is valid; bit value `1` → credential is revoked.

```
Byte 0:   b7 b6 b5 b4 b3 b2 b1 b0
Index:     0  1  2  3  4  5  6  7
```

The packed bytes are then compressed and encoded:

```
encodedList = base64url(gzip(bitstring_bytes, mtime=0))
```

`mtime=0` is required for deterministic output (needed for reproducible hash anchors).

### 3.2 Status List Naming

```
https://discovery.example.gov/api/v1/status/{status_list_id}
```

where `status_list_id` is a UUID-v4. Each issuer × credential-type pair gets its own list to limit blast radius in case of compromise.

### 3.3 Validity Window

Default `exp = iat + 86 400` (24 hours). The Sentinel must re-download before `exp` regardless of Δ.

---

## 4. Distribution Endpoint

```
GET /api/v1/status/{status_list_id}
```

| Parameter | Value |
|---|---|
| Authentication | None — public endpoint |
| Response Content-Type | `application/vc+jwt` |
| Cache-Control | `public, max-age=<delta_seconds>, must-revalidate` |
| ETag | `W/"<sha256_hex_of_jwt>"` |
| Last-Modified | HTTP-date of last bitstring write |

**Responses:**

| Status | Meaning |
|---|---|
| 200 | StatusListCredential JWT string |
| 304 | Not Modified (If-None-Match matched ETag) |
| 404 | Status list not found |

---

## 5. Bounded-Freshness Parameter Δ

Δ is the maximum age of the cached status list before staleness enforcement activates. It is measured relative to the on-chain `anchor.updatedAt` timestamp:

$$\text{stale} = (\text{now} - \text{downloaded\_at}) > \Delta$$

### 5.1 Default Δ Values by Environment

| Environment | Δ (seconds) | Default Staleness Mode |
|---|---|---|
| `prod` | 600 (10 min) | `FAIL_CLOSED` |
| `test` | 1 800 (30 min) | `FAIL_OPEN_DEGRADED` |
| `dev` | 3 600 (1 hour) | `ALLOW_WITH_WARNING` |

On-chain values from `TrustPolicyRegistry` take precedence over local config.

### 5.2 Staleness Modes

| Mode | Behaviour when stale |
|---|---|
| `FAIL_CLOSED` | Reject ALL status checks with `STATUS_STALE_FAIL_CLOSED` (HTTP 503). Default for `prod`. |
| `FAIL_OPEN_DEGRADED` | Continue with stale data; restrict to read-only operations; log warning. |
| `ALLOW_WITH_WARNING` | Continue with stale data for all operations; emit warning metric `status_stale_requests_total`. |

`FAIL_OPEN_DEGRADED` and `ALLOW_WITH_WARNING` require explicit configuration with documented risk acceptance. `FAIL_CLOSED` requires no justification.

---

## 6. On-Chain Anchoring

After publishing a new or updated status list, the Discovery service writes an anchor to the `StatusRegistry` smart contract (TASK-016):

```
StatusRegistry.publishStatusAnchor(
    statusListId = keccak256(url_bytes),
    rootHash     = SHA-256(jwt_bytes),       // hex-encoded
    updatedAt    = block.timestamp
)
```

The Sentinel reads the anchor before (or after) downloading the status list:

```
anchor = StatusRegistry.get_status_anchor(statusListId)
# Returns { rootHash: str, updatedAt: int, issuerId: str }
```

**Verification:** `SHA-256(downloaded_jwt_bytes) == anchor.rootHash`

If the hashes differ, the response is rejected with `STATUS_HASH_MISMATCH`. This detects:
- Serving a tampered status list (re-inclusion attack).
- Rollback attacks (serving an older list while the anchor shows a newer `updatedAt`).

---

## 7. Emergency Revocation Path

For compromised high-value credentials where waiting for the next status list refresh is unacceptable, the Discovery service can call:

```
StatusRegistry.emergencyRevoke(
    credentialIdHash = keccak256(jti_bytes)
)
```

This path **bypasses the status list** entirely. Sentinels check this mapping on every VC verification:

```
jti_hash = SHA-256(jti.encode())       // hex-encoded
is_emergency_revoked = jti_hash in emergency_revoked_set
```

The `emergency_revoked_set` is populated from on-chain `StatusRegistry.EmergencyRevoke` events. It is checked **first**, before any cache or staleness logic. The emergency revoke set is **not** subject to Δ-bounded staleness — it is refreshed at every anchor refresh cycle.

**Access control:** `emergencyRevoke` is restricted to the `security-admin` role on-chain.  
**Cost:** One on-chain write per credential — use only for genuine emergencies.

---

## 8. Cache Architecture at the Sentinel

```
┌─────────────────────────────────┐
│  StatusListCache (in-process)   │
│  ─────────────────────────────  │
│  url → CachedStatusList         │
│    .info           (StatusListInfo)
│    .bitstring_bytes (bytes)     │
│    .downloaded_at  (int ts)     │
│    .jwt_sha256     (hex str)    │
│    .anchor         (optional)   │
└─────────────────────────────────┘
```

- **In-memory only** (this library layer). For multi-instance deployments, back the cache with a shared Redis store at the Sentinel service layer.
- **Refresh scheduler** (Sentinel service, not this library): runs at Δ/2 ± 10% jitter to prevent thundering herd.
- **Restart recovery**: see Sentinel service `persistent_cache` module.

### 8.1 `CachedStatusList` Fields

| Field | Type | Description |
|---|---|---|
| `info` | `StatusListInfo` | Parsed JWT claims |
| `bitstring_bytes` | `bytes` | Decompressed bitstring |
| `downloaded_at` | `int` | Unix timestamp of download |
| `jwt_sha256` | `str` | Hex SHA-256 of raw JWT bytes |
| `anchor` | `StatusAnchor \| None` | On-chain anchor at download time |

---

## 9. Status Verification Procedure

The following steps are executed by `check_credential_status()` for every VC that carries a `credentialStatus` field.

| Step | Action | Failure Code |
|---|---|---|
| 1 | Compute `jti_hash = SHA-256(credential_jti)` and check against `emergency_revoked` set | `EMERGENCY_REVOKED` |
| 2 | Look up `statusListCredential` URL in `StatusListCache` | `STALE_FAIL_CLOSED` (FAIL_CLOSED) or `LIST_UNAVAILABLE` (other modes) |
| 3 | Check staleness: `now - downloaded_at > Δ` | `STALE_FAIL_CLOSED` (FAIL_CLOSED) or continue (other modes) |
| 4 | If `expected_anchor` provided, verify `cached.jwt_sha256 == expected_anchor.root_hash` | `HASH_MISMATCH` |
| 5 | Verify `0 ≤ statusListIndex < len(bitstring_bytes) × 8` | `INDEX_OUT_OF_RANGE` |
| 6 | Read bit at `statusListIndex`: if `1` → revoked | `REVOKED` |
| — | All checks pass | `NOT_REVOKED` |

**Result enum:** `StatusCheckResult` — `NOT_REVOKED`, `REVOKED`, `EMERGENCY_REVOKED`, `STALE_FAIL_CLOSED`, `HASH_MISMATCH`, `INDEX_OUT_OF_RANGE`, `LIST_UNAVAILABLE`.

---

## 10. Error Codes and HTTP Status Mapping

| Code | HTTP | Description |
|---|---|---|
| `STATUS_REVOKED` | 403 | Credential bitstring bit is set |
| `EMERGENCY_REVOKED` | 403 | Credential is emergency-revoked on-chain |
| `STATUS_STALE_FAIL_CLOSED` | 503 | Status list stale beyond Δ in `FAIL_CLOSED` mode |
| `STATUS_HASH_MISMATCH` | 403 | Downloaded status list SHA-256 ≠ on-chain anchor |
| `STATUS_INDEX_OUTOFRANGE` | 400 | `statusListIndex` outside bitstring bounds |
| `STATUS_LIST_UNAVAILABLE` | 502 | Status list URL unreachable and cache is stale |

---

## 11. Security Constraints

1. **Always verify JWT signature** of a downloaded status list before trusting its `encodedList`. Unsigned or incorrectly-signed lists MUST be rejected.
2. **Hash mismatch is fatal.** Any discrepancy between `SHA-256(downloaded_jwt)` and `anchor.rootHash` MUST cause immediate rejection with `STATUS_HASH_MISMATCH`. Do not continue with potentially tampered data.
3. **Emergency revoke is bypass-safe.** The emergency revoke check happens before any cache or Δ logic — a stale cache cannot prevent emergency revoke detection.
4. **`FAIL_CLOSED` is the mandatory default for `prod`.** `FAIL_OPEN_DEGRADED` and `ALLOW_WITH_WARNING` require explicit operational opt-in and documented risk acceptance.
5. **Rollback detection.** If `anchor.updatedAt` is newer than `downloaded_at`, the Sentinel MUST re-download the status list and re-verify before accepting a `NOT_REVOKED` result.
6. **`mtime=0` in gzip encoding** is required to ensure the `encodedList` is byte-for-byte reproducible across compressors for hash anchoring.
7. **No external fetches in this library layer.** `check_credential_status()` operates purely on the in-process cache. HTTP fetching and anchor reading are the responsibility of the Sentinel service layer.

---

## 12. Implementation Reference

| Module | Location |
|---|---|
| Bitstring codec | [libs/common/src/common/revocation/bitstring.py](../../libs/common/src/common/revocation/bitstring.py) |
| Data models | [libs/common/src/common/revocation/models.py](../../libs/common/src/common/revocation/models.py) |
| Cache + checker | [libs/common/src/common/revocation/checker.py](../../libs/common/src/common/revocation/checker.py) |
| Unit tests | [libs/common/tests/unit/revocation/](../../libs/common/tests/unit/revocation/) |
