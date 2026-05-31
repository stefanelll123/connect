# ADR-006 — Secret Storage Architecture

**Status:** ACCEPTED  
**Date:** 2025-01-01  
**Deciders:** Platform Architecture Working Group

---

## Context

The Sentinel Identity Platform handles long-lived private key material:
- Ed25519 private keys for each Sentinel DID
- Issuer signing keys (held by Discovery)
- Blockchain RPC credentials

Requirements:
1. **Private keys must never be written to disk in plaintext.**
2. **Keys must be accessible to multiple instances** of the same Sentinel
   (multi-instance support — TASK-008).
3. **Key rotation must be possible** without modifying the Sentinel DID
   (transition period via key aliasing).
4. **Auditability** — every key read must be logged.
5. **Dev-mode simplicity** — engineers should not need a full Vault cluster
   for local development.

---

## Decision

**Production: HashiCorp Vault (KV v2 + Transit Engine)**

- Private key bytes are stored in Vault KV v2 at well-known paths:
  `secret/sentinel/<env>/<service_id>/private_key`
- Vault AppRole authentication for automated services; Kubernetes SA token
  auth in K8s deployments.
- Vault audit log is enabled; every `kv/data/read` is recorded.
- The Vault Transit engine is used for AES-256-GCM encryption of data at
  rest (config bundles stored locally).

**Development: Vault dev mode**

- `vault server -dev` with root token `root` (value from `.env.example`).
- Single-node; non-persistent; auto-unsealed.
- Docker Compose provides this automatically (`docker-compose.yaml`).

**Fallback / air-gapped: AES-256-GCM encrypted local file**

- Private key bytes encrypted with AES-256-GCM, key derived from a master
  passphrase via HKDF-SHA256.
- File stored at `~/.sentinel/private_key.enc`.
- Only used when Vault is unavailable and explicitly configured.
- The master passphrase is injected via environment variable
  (`SENTINEL_KEY_PASSPHRASE`).

### Key Hierarchy

```
Vault Transit Master Key (HMAC-SHA256 backed)
  └── Per-environment wrapping key
       └── AES-256-GCM key (for local encrypted file fallback)
            └── Ed25519 private key bytes (32 bytes)
```

---

## Consequences

### Positive

- **Vault is the industry standard** for secrets management.  Audited,
  well-documented, widely deployed in government cloud environments.
- **Dynamic secrets** — Vault can issue short-lived tokens; the Sentinel
  exchanges a long-lived AppRole for a short-lived Vault token on startup.
- **Lease renewal** — Sentinels renew their Vault lease on a background timer;
  key material is never held indefinitely without re-authentication.
- **Multi-instance** — all instances of the same service use the same
  path in Vault → same key → same DID.
- **No plaintext disk writes** — the only storage is in Vault or the
  AES-GCM encrypted file (master key never stored).

### Negative

- **Vault dependency** — if Vault is unavailable and no cached key exists,
  new Sentinel processes cannot start.  Mitigated by: short-term in-memory
  key caching with configurable TTL.
- **Operational complexity** — Vault PKI, AppRole management, and audit log
  rotation add operational burden.  Accepted as the cost of secure key
  management.
- **Air-gapped fallback is less secure** — the passphrase-based fallback relies
  on operator security practices.  It is explicitly marked as a fallback only.

---

## Rejected Alternatives

### Environment variable injection (plaintext)

Trivially exposed via `docker inspect`, `ps aux`, or `env` dumps.  Not
acceptable for production key material.

### Kubernetes Secrets (base64 only)

Kubernetes Secrets are base64-encoded, not encrypted by default.  Requires
KMS integration (EKS with AWS KMS, or KSOPS) to achieve encryption at rest
— at which point using Vault directly is simpler and more auditable.

### AWS Secrets Manager / GCP Secret Manager

Cloud-vendor specific.  The platform must support on-premises (government
data center) deployment where cloud KMS is not available or permitted.
HashiCorp Vault is cloud-agnostic.

### Hardware HSM (immediate adoption)

HSM integration (PKCS#11 / AWS CloudHSM) is the gold standard for key
protection.  Deferred to post-MVP because HSM procurement and integration
adds months to the timeline.  The architecture is designed so that Vault's
Transit Engine can be replaced with an HSM-backed Vault seal without
changing application code.

---

## References

- HashiCorp Vault KV v2 — https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2
- HashiCorp Vault AppRole — https://developer.hashicorp.com/vault/docs/auth/approle
- AES-256-GCM (NIST SP 800-38D) — https://csrc.nist.gov/publications/detail/sp/800-38d/final
- HKDF (RFC 5869) — https://www.rfc-editor.org/rfc/rfc5869
