# Multi-Instance and Sentinel Migration Specification

**Status:** Implemented  
**Component:** Security — Sentinel Identity Lifecycle  
**Depends on:** TASK-005 (Onboarding), TASK-006 (Request Security), TASK-007 (Revocation)

---

## 1. Overview

This document specifies how multiple Sentinel instances can share a single logical identity (DID), how a Sentinel is migrated to a new host, and how re-enrollment works after an incident.

The core invariant is: **one DID per (service_id, role, env) tuple**. All instances of the same service/role/env share an Ed25519 private key. Instances are differentiated only by an ephemeral `instance_id` (UUID-v4), which is generated at startup, stored only in memory and heartbeat records, and never embedded in any signed artifact.

---

## 2. Identity Model

| Concept | Scope | Persistence |
|---|---|---|
| DID (e.g. `did:key:z6Mk...`) | `(service_id, role, env)` | Permanent — stored in Discovery DB + on-chain |
| Private key | `(service_id, role, env)` | Stored in Vault (prod) or encrypted local file (dev) |
| `instance_id` (UUID-v4) | Single process run | Memory + heartbeat table only |
| `endpoint_url` | Single process run | Reported on rejoin; updated on migration |

**Why shared DID?** Horizontal scaling without re-registration, no change to issued credentials when instances come and go.

**Why ephemeral instance_id?** Limits blast radius — a compromised instance_id reveals only routing information, not cryptographic material.

---

## 3. Key Storage Backends

### 3.1 `MODE_VAULT` (Production)

Ed25519 private key stored in HashiCorp Vault KV v2:

```
{kv_mount}/data/sentinels/{service_id}/{role}/{env}/did_private_key
```

Secret value:
```json
{
    "private_key_hex": "<64 hex chars>",
    "key_version": 1
}
```

**Access:** Vault AppRole or Kubernetes auth. The Vault token is obtained at container startup and is not written to disk.

**Namespacing:** Each `(service_id, role, env)` tuple has its own Vault path. Keys are **never shared across services**.

**Key lifecycle in Vault:**
- Initial provisioning: `sentinelctl init` writes to Vault.
- Key rotation: `sentinelctl rotate-key` writes new version alongside old (see §5).
- Revocation/decommission: `sentinelctl decommission` deletes the Vault secret.

### 3.2 `MODE_LOCAL` (Development / Break-Glass)

Ed25519 private key stored in an AES-256-GCM encrypted JSON file:

```
{data_dir}/keys/{service_id}-{role}-{env}.key.enc
```

File format:
```json
{
    "version": 1,
    "service_id": "...",
    "role": "PRODUCER",
    "env": "dev",
    "key_version": 1,
    "salt": "<32 hex chars>",
    "nonce": "<24 hex chars>",
    "ciphertext": "<base64url(AES-256-GCM(plaintext, tag))>"
}
```

Plaintext:
```json
{"private_key_hex": "<64 hex chars>"}
```

Key derivation:
```
master_key = scrypt(password, salt, N=32768, r=8, p=1, dklen=32)
```

Password source: `SENTINEL_SECRET_KEY` environment variable.

Additional Authenticated Data (AAD):
```
"{service_id}:{role}:{env}".encode()
```

The AAD binds the ciphertext to the specific identity — copying a key file to a different path does not grant access to a different identity.

> ⚠️ **Warning:** `MODE_LOCAL` is for break-glass recovery and development only. In production, all instances must use `MODE_VAULT`.

---

## 4. Instance Registration (Rejoin)

When a new instance starts:

1. Read the DID private key from the key backend.
2. Derive the DID from the public key (`did:key:...`).
3. Generate a new `instance_id` (UUID-v4).
4. POST `/api/v1/sentinels/rejoin` with proof-of-possession:

```json
{
    "did": "did:key:z6MkExample",
    "instance_id": "550e8400-e29b-41d4-a716-446655440000",
    "service_id": "citizen-data-service",
    "role": "PRODUCER",
    "env": "prod",
    "endpoint_url": "https://sentinel-2.example.internal:8443",
    "proof": "<proof-of-possession JWT signed with DID key>"
}
```

5. Discovery verifies the PoP JWT against the existing DID record in the database.
6. Discovery upserts `sentinel_instances` table: `{sentinel_id, instance_id, endpoint_url, last_seen=now, status=ACTIVE}`.
7. Discovery updates the `ServiceDescriptor` endpoints array.
8. Instance receives `SignedConfigBundle` and begins heartbeat loop.

**Idempotency:** Calling rejoin twice with the same `instance_id` returns the same response and updates `last_seen`. Calling with a new `instance_id` creates a new instance record.

**Proof format:** The PoP JWT must conform to the TASK-006 proof envelope specification with `statusPurpose = "rejoin"` and the challenge returned by `GET /api/v1/sentinels/challenge`.

---

## 5. Multi-Instance Endpoint Publication

- Each instance has its own `endpoint_url`.
- The `ServiceDescriptor.endpoints` array is managed by Discovery.
- When an instance reconnects, its endpoint is added / re-activated.
- When an instance disconnects (graceful drain or heartbeat TTL expiry), its endpoint is removed.
- **Consumer Sentinels** use the endpoint array to select a Producer instance (round-robin by default; implementations may use active health checks).

`SentinelInstance` entity:

| Field | Type | Description |
|---|---|---|
| `sentinel_id` | UUID | FK to logical sentinel record |
| `instance_id` | UUID | Per-process unique identifier |
| `endpoint_url` | str | HTTPS URL this instance listens on |
| `status` | enum | `ACTIVE`, `DRAINING`, `DEAD` |
| `last_seen` | datetime | Updated by heartbeat |
| `version` | str | Sentinel application version |
| `registered_at` | datetime | First rejoin timestamp |

---

## 6. VM Migration Procedure

### 6.1 `MODE_VAULT` (recommended)

1. Admin creates a migration ticket (TASK-005) via Discovery UI.
2. Operator starts a new instance on the new host.
3. New instance authenticates to Vault (Kubernetes auth / AppRole) using the same `role_id` and `secret_id`.
4. Reads the same private key from Vault — **no file transfer needed**.
5. Calls `/api/v1/sentinels/rejoin` with the migration ticket as auth.
6. Old instance is drained (`DELETE /api/v1/sentinels/instances/{instance_id}`).

### 6.2 `MODE_LOCAL` (dev / break-glass)

1. Admin creates a migration ticket (TTL max 30 minutes, single-use).
2. Operator copies the encrypted key file to the new host using a secure channel (SCP/SFTP over mTLS; **not** email or plain HTTP).
3. New instance reads the same key file using the same `SENTINEL_SECRET_KEY`.
4. Calls `/api/v1/sentinels/rejoin` with the migration ticket.
5. Old instance is decommissioned.

**Migration ticket constraints:**
- Single-use (Discovery marks it USED on first successful rejoin).
- Maximum TTL: 30 minutes.
- Scoped to a specific `(sentinel_id, env)` — cannot be used for a different sentinel.

---

## 7. Encrypted Backup (`MODE_LOCAL` only)

**Purpose:** Break-glass recovery when the key file is lost and no Vault is available.

**CLI:**
```bash
sentinelctl backup --passphrase <passphrase>
# → produces {sentinel_id}.wallet.bak
```

Backup file format:
```json
{
    "version": 1,
    "service_id": "...",
    "role": "...",
    "env": "...",
    "did": "did:key:z6Mk...",
    "key_version": 1,
    "salt": "<hex>",
    "nonce": "<hex>",
    "ciphertext": "<base64url>"
}
```

Master key: `scrypt(passphrase, salt=random_16_bytes, N=32768, r=8, p=1, dklen=32)`

**Restore:**
```bash
sentinelctl restore --file {sentinel_id}.wallet.bak --passphrase <passphrase>
```

The restore command verifies GCM authentication before writing any key material to disk.

> ⚠️ This is a last-resort mechanism. Production environments must use Vault.

---

## 8. Graceful Shutdown

Before process termination:

1. Instance transitions status to `DRAINING` via the next heartbeat (or an explicit update).
2. Instance calls `DELETE /api/v1/sentinels/instances/{instance_id}`.
3. Discovery removes the instance endpoint from the `ServiceDescriptor` immediately.
4. Pending in-flight requests are allowed to drain for up to 30 seconds (Kubernetes `preStop` hook).

**Kubernetes preStop hook:**
```yaml
lifecycle:
  preStop:
    exec:
      command: ["sentinelctl", "drain", "--timeout=30s"]
```

---

## 9. Security Constraints

1. **Vault namespacing** — each `(service_id, role, env)` uses a separate Vault path. No cross-service key sharing.
2. **`instance_id` isolation** — must not appear in any signed artifact (VCs, ProofClaims, onboarding tokens). It is purely operational.
3. **Migration ticket TTL** — maximum 30 minutes, single-use. Discovery must invalidate immediately on successful use.
4. **`MODE_LOCAL` as last resort only** — operators must document risk acceptance when using encrypted local key files in production.
5. **AAD binding** — the AES-256-GCM ciphertext is bound to `"{service_id}:{role}:{env}"` via AAD. Copying a key file to a different identity path does not work.
6. **No plaintext private keys on disk** — ever. Mode `LOCAL` always encrypts before writing.

---

## 10. Implementation Reference

| Module | Location |
|---|---|
| Key backend protocol | [libs/common/src/common/secret_storage/backend.py](../../libs/common/src/common/secret_storage/backend.py) |
| Local AES-GCM backend | [libs/common/src/common/secret_storage/local_backend.py](../../libs/common/src/common/secret_storage/local_backend.py) |
| Vault KV v2 backend | [libs/common/src/common/secret_storage/vault_backend.py](../../libs/common/src/common/secret_storage/vault_backend.py) |
| Unit tests | [libs/common/tests/unit/secret_storage/](../../libs/common/tests/unit/secret_storage/) |
