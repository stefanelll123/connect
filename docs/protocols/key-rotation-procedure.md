# Key Rotation Procedure

**Status:** Implemented (specification — runtime managed by Sentinel service layer)  
**Component:** Security — Sentinel Identity Lifecycle  
**Depends on:** Multi-Instance Migration (TASK-008), Config Bundle (TASK-040)

---

## 1. Overview

Key rotation allows replacing the Ed25519 private key of a logical Sentinel DID without downtime and without invalidating in-flight VCs. A **grace period** (default 600 seconds) allows all instances to hot-reload the new key before the old key is rejected.

Rotation is triggered by an admin via the Discovery API or `sentinelctl rotate-key`. It is **not** automated — rotation must be explicitly initiated by a `security-admin` role bearer.

---

## 2. When to Rotate

| Trigger | Urgency | Action |
|---|---|---|
| Scheduled rotation (periodic hygiene) | Non-urgent | Plan a maintenance window |
| Suspected key compromise | Urgent | Initiate immediately; use minimum grace period (60 s) |
| Operator offboarding | Non-urgent | Rotate before removing Vault access |
| Infrastructure migration (Vault move) | Non-urgent | Rotate as part of migration window |

---

## 3. Pre-conditions

Before initiating rotation:

- [ ] All instances are running and healthy (heartbeat `status = ACTIVE`).
- [ ] Config bundle distribution endpoint (TASK-040) is reachable.
- [ ] Vault has writable access to both `current` and `previous` key version paths.
- [ ] A `security-admin` Vault token or IAM role is available.

---

## 4. Step-by-Step Rotation Procedure

### Step 1 — Generate the New Key (K2)

```bash
sentinelctl generate-key --service-id citizen-data-service --role PRODUCER --env prod
# → prints new DID and stores K2 under sentinels/.../did_private_key@v2 in Vault
```

Or, if Discovery generates the key on behalf of the operator:

```
POST /api/v1/sentinels/{sentinel_id}/rotate-key
Authorization: Bearer <security-admin token>

{
    "reason": "Quarterly scheduled rotation",
    "grace_period_seconds": 600
}
```

Response `202 Accepted`:
```json
{
    "rotation_id": "<uuid>",
    "grace_period_end": "2024-03-15T14:30:00Z",
    "new_key_version": 2
}
```

### Step 2 — Discovery Stores K2 and Sets Grace Period

Discovery:
1. Generates K2, derives new public key and new DID.
2. Writes K2 to Vault at `sentinels/{svc}/{role}/{env}/did_private_key@v2`.
3. Keeps K1 at `@v1` (previous version).
4. Sets `sentinel.state = KEY_ROTATING`, `sentinel.grace_period_end = now + grace_seconds`.
5. Publishes updated config bundle containing both `current_kid` (K2) and `previous_kid` (K1).

### Step 3 — Grace Period: Dual Key Acceptance

During the grace period (`now < grace_period_end`):

- **Producer Sentinels** accept PoP JWTs signed with **either K1 or K2** by checking the `kid` header of the incoming JWS.
- Only the key identified by `kid` in the JWS header is used for verification — not a "try all keys" approach.
- Instances that have already hot-reloaded K2 will sign new proofs with K2.
- Instances still running K1 will sign with K1 — this is valid until `grace_period_end`.

### Step 4 — Instances Hot-Reload K2

Each instance polls the config bundle endpoint at `Δ/2` interval (TASK-040). When it receives a bundle with `key_version = 2`:

1. Reads K2 from Vault.
2. Verifies that `derive_did(K2.public_key) == new_did` matches the bundle.
3. Atomically swaps the in-memory private key reference from K1 to K2.
4. Begins signing new proofs with K2.
5. Logs `key_rotation_hot_reload` audit event.

### Step 5 — Re-issue Credentials with K2

Discovery re-issues all active credentials (VCs) for this Sentinel with K2 as the new subject public key. The old VCs signed under K1 are revoked via the status list (TASK-007).

Timeline for re-issuance: must complete before `grace_period_end`.

### Step 6 — Grace Period Expires

At `grace_period_end`:

1. Discovery sets `sentinel.state = ACTIVE` (rotation complete).
2. K1 is moved to `@archived` in Vault (retained for audit; not usable for verification).
3. Producer Sentinels stop accepting K1-signed proofs — `POP_SIGNATURE_INVALID` is returned.
4. Discovery increments `approved_key_versions` to `[v2]` only.

### Step 7 — Cleanup

```bash
# Verify all instances are on K2
sentinelctl status --sentinel-id <id>

# Archive K1 in Vault (if not done automatically)
vault kv metadata put secret/sentinels/citizen-data-service/PRODUCER/prod/did_private_key \
    custom_metadata="v1_archived_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

---

## 5. Rollback Procedure

If K2 proves defective during the grace period:

```
POST /api/v1/sentinels/{sentinel_id}/rotate-key/abort
Authorization: Bearer <security-admin token>
{
    "rotation_id": "<uuid>",
    "reason": "K2 key generation failed validation"
}
```

Abort actions:
1. Discovery deletes K2 from Vault.
2. Sets `sentinel.state = ACTIVE` (back to K1 only).
3. Clears `grace_period_end`.
4. Publishes updated config bundle: `current_kid = K1`, `previous_kid = null`.
5. Instances hot-reload back to K1 only mode.

---

## 6. `KeyRotationEvent` Entity

| Field | Type | Description |
|---|---|---|
| `rotation_id` | UUID | Unique rotation identifier |
| `sentinel_id` | UUID | The logical sentinel being rotated |
| `old_key_version` | int | Previous key version number |
| `new_key_version` | int | New key version number |
| `grace_period_end` | datetime | When old key becomes invalid |
| `status` | enum | `IN_PROGRESS`, `COMPLETED`, `FAILED`, `ABORTED` |
| `initiated_by` | str | Admin actor ID |
| `reason` | str | Required — free text |
| `created_at` | datetime | Rotation start timestamp |
| `completed_at` | datetime | Rotation completion timestamp |

---

## 7. API Endpoints

### Initiate Rotation

```
POST /api/v1/sentinels/{sentinel_id}/rotate-key
Authorization: Bearer <security-admin token>
Content-Type: application/json

{
    "reason": "string (required)",
    "grace_period_seconds": 600  // range: 60–3600
}
```

| Response | Code | Body |
|---|---|---|
| Accepted | 202 | `{rotation_id, grace_period_end, new_key_version}` |
| Already in progress | 409 | `ROTATION_ALREADY_IN_PROGRESS` |
| Unauthorized | 401 | `AUTH_REQUIRED` |
| Forbidden | 403 | `INSUFFICIENT_ROLE` |

### Abort Rotation

```
POST /api/v1/sentinels/{sentinel_id}/rotate-key/abort
Authorization: Bearer <security-admin token>

{
    "rotation_id": "<uuid>",
    "reason": "string (required)"
}
```

| Response | Code |
|---|---|
| OK | 200 |
| Not found | 404 |
| Too late (grace period expired) | 409 |

---

## 8. Security Constraints

1. **Minimum grace period:** 60 seconds. Shorter grace periods risk locking out instances that have not yet hot-reloaded.
2. **Maximum grace period:** 3 600 seconds (1 hour). Longer windows increase the dual-key exposure risk.
3. **Hard expiry:** After `grace_period_end`, old key MUST be rejected with no exceptions. No manual extension via API.
4. **`kid` header check:** Dual-key acceptance checks the `kid` claim in the JWS header and verifies against the matching key only. It does NOT try all keys.
5. **Audit log:** Every rotation event (initiate, hot-reload, complete, abort) must be written to the immutable audit log.
6. **No concurrent rotations:** Only one `KEY_ROTATING` state per sentinel at a time. Calling `rotate-key` while a rotation is in progress returns `409 ROTATION_ALREADY_IN_PROGRESS`.

---

## 9. Emergency Fast Rotation (Compromise Response)

For suspected key compromise:

```
POST /api/v1/sentinels/{sentinel_id}/rotate-key
{
    "reason": "SECURITY: Suspected key compromise — see incident INC-20240315",
    "grace_period_seconds": 60
}
```

Simultaneously:
- Revoke all active VPs for this Sentinel via `StatusRegistry.emergencyRevoke`.
- Notify the security operations channel.
- Begin the standard rotation procedure above with a 60-second grace period.

This provides a 60-second window for instances to hot-reload K2. Any PoPs still signed by K1 are rejected after 60 seconds.
