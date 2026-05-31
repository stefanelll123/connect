# Threat Model — Sentinel Identity Platform

**Status:** APPROVED  
**Version:** 1.0  
**Classification:** INTERNAL  
**Methodology:** STRIDE  
**Cross-reference:** [threat-table.csv](threat-table.csv), [asvs-mapping.md](asvs-mapping.md),
[outage-policy.md](outage-policy.md), [traceability-matrix.md](traceability-matrix.md)

---

## 1. Asset Catalogue

| # | Asset | Classification | Storage Location | Notes |
|---|---|---|---|---|
| A-001 | Sentinel Ed25519 private DID keys | **SECRET** | Vault KV v2 only | Never in logs, DB, or env vars |
| A-002 | Issuer signing keys (Discovery) | **SECRET** | Vault KV v2 only | Used to sign VCs and config bundles |
| A-003 | Verifiable Credentials (JWT-VC) | **INTERNAL** | PostgreSQL + in-memory | Contains scope, env, aud fields |
| A-004 | Config bundles | **INTERNAL** | PostgreSQL + Sentinel memory | Contains service endpoints |
| A-005 | Enrollment tokens | **SECRET** (while unused) | Vault + single transmission | One-time use; expires in 1 h |
| A-006 | Bitstring Status Lists | **PUBLIC** | PostgreSQL + CDN cache | Publicly verifiable |
| A-007 | Discovery registry DB | **INTERNAL** | PostgreSQL (encrypted at rest) | Services, Sentinels, VCs, audit |
| A-008 | Blockchain RPC credentials | **SECRET** | Vault / environment config | Required for on-chain writes |
| A-009 | Audit log | **INTERNAL** | Append-only log store | No key material — forensic trail |
| A-010 | mTLS client certificates | **SECRET** | Vault PKI / filesystem | Used for Sentinel ↔ Discovery auth |
| A-011 | JTI replay cache contents | **INTERNAL** | Redis (TTL 30 s) | Short-lived; integrity important |

---

## 2. Adversary Catalogue

| # | Adversary | Capabilities | Goals |
|---|---|---|---|
| ADV-001 | Insider Admin | Full access to Discovery admin API; can issue enrollment tokens and VCs | Issue unauthorized VCs; register rogue Sentinels |
| ADV-002 | Network Attacker (on-path) | Can observe and replay HTTPS traffic between Sentinels | Replay valid requests; modify request payloads |
| ADV-003 | Compromised Consumer Sentinel | Valid DID and VC; attacker controls the process | Escalate scope; forge ProofClaims for other resources |
| ADV-004 | Compromised Discovery | Can modify registry, issue enrollment tokens, serve malicious config | Register rogue Sentinels; redirect traffic; issue VCs for unauthorized services |
| ADV-005 | Compromised Issuer | Controls an issuer key; can issue fraudulent VCs | Grant unauthorized access to any service |
| ADV-006 | Rogue Sentinel | No valid enrollment token; attempts registration | Appear as a legitimate producer and intercept traffic |

---

## 3. STRIDE Threat Table

See [threat-table.csv](threat-table.csv) for the machine-readable version.

### Flow: Consumer → Producer Request Execution

| ID | Component | STRIDE | Threat Description | Impact | Likelihood | Mitigation |
|---|---|---|---|---|---|---|
| T-001 | Producer Sentinel | R | **ProofClaims JWS replay** — attacker captures a valid request and replays it within the exp window | HIGH | HIGH | JTI dedup cache (Redis SETNX, 30 s TTL); exp check (30 s max TTL); req hash binding |
| T-003 | Producer Sentinel | E | **Cross-environment VC** — attacker submits a `dev` VC in `prod` | HIGH | MEDIUM | `env` claim validation at VC verifier (Step 7); separate DIDs per env (ADR-007) |
| T-007 | Consumer Sentinel | S | **Consumer Sentinel DID key theft** — private key extracted from Vault or memory | HIGH | LOW | Keys in Vault only; no plaintext disk; Vault audit log; SI-009 |
| T-010 | Consumer Sentinel | T | **Config bundle tampering** — attacker modifies the config bundle in transit | MEDIUM | LOW | JWS signature on config bundle; verified before application (SI-012) |

### Flow: Sentinel Onboarding

| ID | Component | STRIDE | Threat Description | Impact | Likelihood | Mitigation |
|---|---|---|---|---|---|---|
| T-002 | Discovery | S | **Rogue Sentinel registration with forged token** — attacker uses an intercepted or brute-forced enrollment token | HIGH | MEDIUM | One-time use tokens (SI-002); UUID entropy (128-bit); short expiry (1 h) |
| T-005 | Discovery | S | **Enrollment token theft and reuse** — attacker steals the token during transmission | HIGH | LOW | mTLS for the onboarding channel; token transmitted only once; Vault storage |
| T-008 | Discovery | T | **Discovery compromise enabling endpoint injection** — attacker modifies service endpoints in config | HIGH | LOW | Config bundle JWS signature; Sentinels verify signature before trusting (SI-012) |

### Flow: Credential Issuance and Verification

| ID | Component | STRIDE | Threat Description | Impact | Likelihood | Mitigation |
|---|---|---|---|---|---|---|
| T-006 | Discovery / Issuer | S | **Issuer key compromise enabling mass VC forgery** — attacker signs VCs for any service | CRITICAL | LOW | Issuer disable via IssuerRegistry (on-chain, takes effect within 1 TTL); SI-005 |

### Flow: Revocation

| ID | Component | STRIDE | Threat Description | Impact | Likelihood | Mitigation |
|---|---|---|---|---|---|---|
| T-004 | Producer Sentinel | I | **Stale status list acceptance** — Sentinel accepts a revoked VC because its status list is outdated | HIGH | MEDIUM | Δ-bounded freshness window; FAIL_CLOSED on stale cache (SI-001, outage-policy.md) |
| T-013 | Producer Sentinel | T | **Status list bitstring tampering** — attacker replaces cached bitstring to clear revocation bits | HIGH | LOW | SHA-256 hash verified against on-chain anchor before trusting (SI-013) |

### Flow: Blockchain

| ID | Component | STRIDE | Threat Description | Impact | Likelihood | Mitigation |
|---|---|---|---|---|---|---|
| T-009 | Blockchain / All | D | **Blockchain reorg causing stale trust state** — chain reorg reverts an issuer-disable tx | MEDIUM | LOW | Require ≥ 12 block confirmations for registry writes; Sentinel caches verified state |

---

## 4. Detailed Threat Analysis

### T-001 — Replay of ProofClaims JWS

**Flow:** seq-request-execution  
**Adversary:** ADV-002 (Network Attacker)  
**Attack path:**
1. Attacker intercepts a valid `Authorization: SentinelProof <jws>` header.
2. Attacker re-submits the same JWS to the Producer Sentinel within the 30-second window.

**Mitigations:**
- `exp = iat + 30` — JWS expires 30 seconds after issue.
- `jti` (UUIDv4) stored in Redis with `SETNX key 1 EX 30` — any second use returns 0 (already seen).
- `req.body_hash` and `req.query_hash` are bound to the original payload — changing anything invalidates the signature.

**Residual risk:** An exact replay within 30 s would succeed if the JTI cache is unavailable (Redis down). Mitigated by: Redis failover (sentinel/cluster).

---

### T-002 — Rogue Sentinel Registration

**Flow:** seq-sentinel-onboarding  
**Adversary:** ADV-006 (Rogue Sentinel), ADV-001 (Insider Admin)  
**Attack path:**
1. Attacker obtains an enrollment token (intercept, insider, or brute-force).
2. Attacker calls `POST /api/v1/sentinels/enroll` with their own DID.

**Mitigations:**
- Token is 128-bit UUID (effectively unguessable).
- Token is one-time use — invalidated on first successful use (SI-002).
- Token transmitted over mTLS — interception requires breaking TLS.
- Token has 1-hour expiry.
- Even if registered, the rogue Sentinel would need a valid VC from an authorized issuer — and VC issuance requires additional admin approval.

---

### T-003 — Cross-Environment VC Replay

**Flow:** seq-request-execution  
**Adversary:** ADV-003 (Compromised Consumer Sentinel)  
**Attack path:**
1. Attacker obtains a valid `dev` VC (easier with weaker `dev` controls).
2. Attacker submits the `dev` VC to a `prod` Producer Sentinel.

**Mitigations:**
- `env: dev` claim in the VC payload is checked at Step 7 of the 10-step procedure.
- `prod` Sentinel rejects with `ENV_MISMATCH` → HTTP 403.
- Each env uses a different Sentinel DID — so even if the `env` check is bypassed, the `aud` check (which uses the `prod` DID) would fail.

---

### T-004 — Stale Status List Acceptance

**Flow:** All verification flows  
**Adversary:** ADV-004 (Compromised Discovery)  
**Attack path:**
1. A VC is revoked by Discovery at `t=0`.
2. Producer Sentinel's status list cache has TTL > `t`.
3. At `t + δ` (before cache refresh), the revoked VC is still accepted.

**Mitigations:**
- Δ-bounded freshness: if `now - last_refresh > Δ`, apply FAIL_CLOSED.
- Status list refresh schedule: every `min(Δ/2, 60s)` in `prod`.
- On-chain hash anchor: discovered tampering triggers FAIL_CLOSED.

---

### T-006 — Issuer Key Compromise

**Flow:** VC issuance  
**Adversary:** ADV-005 (Compromised Issuer)  
**Attack path:**
1. Attacker gains access to the issuer's private key in Vault.
2. Attacker issues fraudulent VCs for any service and scope.

**Mitigations:**
- `IssuerRegistry.disableIssuer(issuer_did)` — admin can revoke issuer liveness on-chain.
- Sentinel checks `isActive(issuer_did)` on every request (Step 10).
- VCs signed by disabled issuer are rejected within 1 TTL cycle (SI-005).
- Vault audit log records every key access — forensic trail.
- Key access requires AppRole with narrow policy — blast radius limited.

---

## 5. Outage and Staleness

See [outage-policy.md](outage-policy.md) for the full specification.

### Summary: FAIL_CLOSED is the default

When any of the following are unavailable or stale, the default behavior is to
**reject the request** (not allow it through):

- Status list older than Δ → `STATUS_REVOKED` (fail-closed)
- IssuerRegistry query fails/times out → `ISSUER_UNTRUSTED` (fail-closed)
- DID resolution times out → `DID_UNRESOLVABLE` (fail-closed)
- Config bundle signature invalid → retain old config (fail-closed for new config)

Exception: `FAIL_OPEN_DEGRADED` mode may be configured for `dev` and `test`
environments only, never for `prod`.

---

## 6. Security Testing Summary

See [traceability-matrix.md](traceability-matrix.md) for the full T-xxx → TASK-xxx → TEST-xxx mapping.

| Threat | Test Type | Test Reference |
|---|---|---|
| T-001 (Replay) | Integration | TEST-INT-001 |
| T-002 (Rogue registration) | Integration | TEST-INT-002 |
| T-003 (Cross-env VC) | Unit + E2E | TEST-UNIT-003, TEST-E2E-003 |
| T-004 (Stale status) | Integration | TEST-INT-004 |
| T-005 (Token theft) | Integration | TEST-INT-005 |
| T-006 (Issuer compromise) | E2E | TEST-E2E-006 |
| T-007 (Key theft) | Security audit | AUDIT-001 |
| T-008 (Config tampering) | Unit | TEST-UNIT-008 |
| T-009 (Chain reorg) | Integration | TEST-INT-009 |
| T-010 (Config tampering) | Unit | TEST-UNIT-010 |
