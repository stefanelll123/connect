# Reference Architecture — Sentinel Identity Platform

**Status:** APPROVED  
**Version:** 1.0  
**Owner:** Platform Architecture Working Group  
**Classification:** INTERNAL

---

## 1. System Overview

The Sentinel Identity Platform is a **decentralized inter-agency
data-access gateway** for e-government environments.  It enables a
service operated by one government entity (the *Consumer*) to access
data from a service operated by another government entity (the
*Producer*) with cryptographically verifiable, policy-enforced
authorization.

**Core design principle:** Trust is established via W3C Verifiable
Credentials anchored to a permissioned blockchain.  No central
authority can grant or revoke access in real time — the producer
Sentinel always makes the final enforcement decision offline, using
on-chain and locally cached trust material.

### 1.1 Key Properties

- **Zero-trust:** Every cross-entity request carries a VP + signed
  proof; nothing is trusted by network position alone.
- **Offline enforcement:** The Producer Sentinel can reject requests
  without contacting Discovery.
- **Environment isolation:** `dev`, `test`, and `prod` environments
  are cryptographically isolated — different DIDs, different
  credentials, different keys.
- **Multi-instance safe:** Multiple Sentinel instances for the same
  service share the same DID (key shared via Vault) without
  distributing private key material.
- **Fail-closed:** When on-chain or status data is unavailable or
  stale beyond Δ, requests are rejected (not passed through).

---

## 2. Component Catalogue

### 2.1 Discovery Service

**Role:** Central configuration orchestrator and DID registry.

**Responsibilities:**

| Function | Description |
|---|---|
| Service Registration | Registers Producer and Consumer services; assigns DID per env |
| Enrollment Token Issuance | Issues one-time enrollment tokens for Sentinel onboarding |
| VC Issuance | Issues AccessGrantCredentials to authorized Consumer Sentinels |
| Status List Management | Maintains and publishes Bitstring Status List VCs |
| Config Bundle Serving | Serves signed config bundles to Sentinels on pull |
| Issuer Registry Sync | Syncs issuer status with IssuerRegistry smart contract |

**Does NOT:**
- Make final authorization decisions (enforcement is at Producer Sentinel).
- Store private keys of Sentinels.
- Forward or proxy business-layer requests.

### 2.2 Producer Sentinel

**Role:** Reverse-proxy enforcement gateway in front of a Producer Service.

**Responsibilities:**

| Function | Description |
|---|---|
| VP Verification | Verifies the JWT-VP + signed ProofClaims on every inbound request |
| Policy Enforcement | Checks scope, env, aud, revocation status |
| Revocation Cache | Caches the Bitstring Status List; refreshes on schedule |
| IssuerRegistry Lookup | Queries on-chain IssuerRegistry for issuer liveness |
| Nonce Issuance | Issues per-request nonces to bound ProofClaims |
| Audit Emission | Emits structured audit log entries for every decision |
| Config Pull | Periodically pulls signed config bundle from Discovery |

### 2.3 Consumer Sentinel

**Role:** Forward-proxy enrichment gateway intercepting outbound requests.

**Responsibilities:**

| Function | Description |
|---|---|
| DID Key Management | Holds (via Vault) the Consumer Sentinel's Ed25519 private key |
| VP Assembly | Assembles a JWT-VP from the stored AccessGrantCredential(s) |
| ProofClaims Construction | Builds and signs the ProofClaims JWS for each request |
| Header Injection | Attaches `Authorization: SentinelProof <jws>` and `SentinelVP: <jwt-vp>` |
| Token Refresh | Monitors credential expiry and requests rotation from Discovery |
| Config Pull | Periodically pulls signed config bundle from Discovery |

### 2.4 Blockchain Trust Layer

**Role:** Immutable append-only trust anchor.

**Smart Contracts** (all on the permissioned EVM-compatible chain):

| Contract | Function |
|---|---|
| `SentinelRegistry` | Registers Sentinel DIDs; stores public key hash per env |
| `IssuerRegistry` | Tracks authorized credential issuers; enables/disables issuers |
| `TrustPolicyRegistry` | Stores Δ (freshness window), allowed algorithms, policy params |
| `StatusListAnchor` | Anchors SHA-256 hash of Status List bitstring per update |

**Important:** No private key material is ever stored on-chain.
Only public key hashes and policy parameters.

### 2.5 Secret Storage

**Role:** Secure vault for all private key material.

| Mode | Technology | Use Case |
|---|---|---|
| Production | HashiCorp Vault (KV v2 + Transit engine) | All production Sentinel private keys |
| Development | Vault dev mode (root token) | Local development only |
| Fallback | AES-256-GCM encrypted local file | Air-gapped or Vault-unavailable scenarios |

See [ADR-006](adrs/ADR-006-secret-storage.md) for the full decision.

---

## 3. Responsibilities Matrix

| Function | Discovery | Consumer Sentinel | Producer Sentinel | Blockchain | Secret Storage |
|---|---|---|---|---|---|
| Register services | ✅ | — | — | ✅ (anchor) | — |
| Issue enrollment tokens | ✅ | — | — | — | — |
| Issue VCs | ✅ | — | — | — | — |
| Hold private keys | — | ✅ (via Vault) | ✅ (via Vault) | — | ✅ |
| Assemble VP | — | ✅ | — | — | — |
| Sign ProofClaims | — | ✅ | — | — | — |
| Verify VP + ProofClaims | — | — | ✅ | — | — |
| Enforce policy | — | — | ✅ | — | — |
| Check revocation | — | — | ✅ | ✅ (anchor) | — |
| Check issuer liveness | ✅ (on onboard) | — | ✅ (on request) | ✅ (source) | — |
| Publish status list | ✅ | — | — | ✅ (hash anchor) | — |
| Serve config bundles | ✅ | — | — | — | — |
| Emit audit log | ✅ | ✅ | ✅ | — | — |

---

## 4. API Contract Summary

| Interface | Protocol | Auth | Spec Reference |
|---|---|---|---|
| Consumer → Discovery | HTTPS REST | Bearer enrollment token / mTLS | TASK-026 |
| Sentinel → Discovery (config pull) | HTTPS REST | mTLS + Sentinel DID | TASK-027 |
| Consumer Sentinel → Producer Sentinel | HTTPS (proxied) | `Authorization: SentinelProof` + `SentinelVP` | TASK-029 |
| Discovery → Blockchain | JSON-RPC / WebSocket | RPC key (env secret) | TASK-015 |
| Sentinel → Blockchain | JSON-RPC (read-only) | Public RPC | TASK-015 |
| Sentinel → Vault | Vault HTTP API | AppRole / K8s SA token | TASK-008 |

---

## 5. Data Flow Catalogue

### 5.1 Nominal Cross-Entity Request Flow

```
Consumer Service
  → Consumer Sentinel (intercepts outbound request)
      [assembles JWT-VP from stored VC]
      [builds ProofClaims JWS over method/path/query/body]
  → Producer Sentinel (receives request on :8080)
      [Step 1] Validates ProofClaims: iss, aud, env, exp, jti (anti-replay)
      [Step 2] Verifies JWT-VP signature
      [Step 3] Verifies JWT-VC inside VP (10-step procedure)
      [Step 4] Checks revocation status from cached Status List
      [Step 5] Verifies issuer is active in IssuerRegistry (on-chain)
      [Step 6] Checks scope against requested resource
      [Step 7] If all pass → proxy request to Producer Service
  → Producer Service
  → response routed back through Producer Sentinel (audit) → Consumer Service
```

### 5.2 Onboarding Flow

See [diagrams/seq-sentinel-onboarding.puml](diagrams/seq-sentinel-onboarding.puml).

### 5.3 VC Issuance Flow

See [diagrams/seq-vc-issuance.puml](diagrams/seq-vc-issuance.puml).

---

## 6. Network Topology

```
┌─────────────────────────────────────────────────────────────────────┐
│  Government Entity A (Consumer)                                     │
│  ┌─────────────────┐    ┌────────────────────────────────────────┐ │
│  │ Consumer Service │───▶│ Consumer Sentinel (:9000 forward proxy)│ │
│  └─────────────────┘    └─────────────────┬──────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                     HTTPS + SentinelProof header │
                                                  │
┌─────────────────────────────────────────────────▼───────────────────┐
│  Government Entity B (Producer)                                     │
│  ┌─────────────────────────────────────┐   ┌──────────────────────┐│
│  │ Producer Sentinel (:8080 rev proxy)  │──▶│  Producer Service    ││
│  └────────────────┬────────────────────┘   └──────────────────────┘│
└───────────────────┼─────────────────────────────────────────────────┘
                    │
          ┌─────────▼─────────┐       ┌─────────────────────┐
          │  Discovery Service │       │  Blockchain (EVM)   │
          │  (central, shared) │       │  SentinelRegistry   │
          └────────────────────┘       │  IssuerRegistry     │
                                       │  TrustPolicyRegistry│
                                       └─────────────────────┘
```

All inter-service communication is over TLS 1.3 minimum.
Sentinel-to-Sentinel communication uses mTLS with DID-bound certificates.

---

## 7. Trust Boundaries

| Boundary | Trusted Side | Untrusted Side | Enforcement |
|---|---|---|---|
| TB-001 | Producer Sentinel | Consumer Sentinel | VP + ProofClaims verification |
| TB-002 | Discovery | Any unauthenticated caller | Enrollment token + mTLS |
| TB-003 | Producer Sentinel | Discovery (config only, not authz) | Signed config bundle |
| TB-004 | Blockchain | Any writer without valid tx | Smart contract access control |
| TB-005 | Vault | Any caller without valid token | Vault AppRole / K8s SA |
| TB-006 | Producer Service | Internet / Consumer Services | Producer Sentinel (proxy enforcer) |

**Critical invariant:** Discovery is in the untrusted zone relative to Producer
Sentinel's authorization decisions.  A compromised Discovery cannot grant access
— it can only modify config and issue enrollment tokens.  Sentinels verify
credentials against on-chain state independently.

---

## 8. Security Invariants

See [security-invariants.md](security-invariants.md) for the full numbered list.

Summary:

| ID | Invariant |
|---|---|
| SI-001 | Stale status → reject |
| SI-002 | Enrollment token is one-time use |
| SI-003 | VP proof is bound to exact aud DID + env |
| SI-004 | Discovery cannot authorize — only Sentinels enforce |
| SI-005 | Disabled issuer VCs are rejected immediately |
| SI-006 | alg:none MUST be rejected before any crypto |
| SI-007 | Cross-env credentials are rejected |
| SI-008 | Replay window is 30 seconds + JTI cache |
| SI-009 | Private keys never leave Vault in plaintext |
| SI-010 | All audit log entries are append-only |

---

## 9. Data Classification

| Data | Classification | Location | Notes |
|---|---|---|---|
| Sentinel private key | SECRET | Vault only | Never in logs, never in DB |
| Issuer signing key | SECRET | Vault only | Never transmitted |
| JWT-VC content | INTERNAL | DB + cache | May contain authorization scope |
| Enrollment token | SECRET (while unused) | Single transmission | One-time use |
| Bitstring Status List | PUBLIC | CDN / Discovery | Publicly verifiable |
| DID (public key) | PUBLIC | Blockchain | Derivable from public key |
| Audit log | INTERNAL | Append-only log store | No key material |
| Config bundle | INTERNAL | Signed, at-rest | Contains service endpoints |
