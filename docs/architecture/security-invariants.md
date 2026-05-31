# Security Invariants — Sentinel Identity Platform

**Status:** APPROVED  
**Version:** 1.0  
**Classification:** INTERNAL

Each invariant is numbered, described, and associated with a testable criterion.
All invariants MUST hold at all times in all environments.  Any code change that
violates an invariant requires a formal exception and a revised threat model.

---

## SI-001 — Stale Status Triggers Rejection

**Statement:**  
A request MUST be rejected if the most recent status list anchor age
(now − `status_anchor_updated_at`) exceeds the configured Δ value for the
current environment.

**Rationale:** Prevents acceptance of credentials after revocation if the
Producer Sentinel cannot verify that the status list is current.

**Test criterion:**  
Set `status_anchor_updated_at` to `now − (Δ + 1)`.  Submit a request with a
valid, non-revoked credential.  Assert HTTP 403 `STATUS_REVOKED` or 503.

**Δ defaults:**

| Environment | Δ (seconds) |
|---|---|
| `prod` | 600 |
| `test` | 3 600 |
| `dev` | 86 400 |

---

## SI-002 — Enrollment Token is One-Time Use

**Statement:**  
An enrollment token issued by Discovery MUST be invalidated immediately after
its first successful use.  Any subsequent use of the same token MUST be rejected
with HTTP 401.

**Rationale:** Prevents an attacker who intercepts or steals an enrollment token
from using it to register a second (rogue) Sentinel.

**Test criterion:**  
Use enrollment token T to register Sentinel A.  Attempt to use T again.
Assert HTTP 401 and that no second Sentinel is registered.

---

## SI-003 — VP Proof is Bound to Exact Audience DID and Environment

**Statement:**  
A Verifiable Presentation MUST be accepted only if the `aud` claim in the
ProofClaims JWT matches the Producer Sentinel's DID exactly AND the `env` claim
matches the current environment string exactly.

**Rationale:** Prevents a VP issued for Producer A from being replayed at
Producer B, and prevents cross-environment attacks.

**Test criterion:**  
Issue a VP with `aud: did:key:ztarget`.  Submit to a Sentinel with DID
`did:key:zdifferent`.  Assert HTTP 403 `AUD_MISMATCH`.

Issue a VP with `env: dev`.  Submit to a Sentinel running in `prod`.
Assert HTTP 403 `ENV_MISMATCH`.

---

## SI-004 — Discovery Cannot Authorize; Only Sentinels Enforce

**Statement:**  
The Producer Sentinel MUST make authorization decisions based solely on:
(1) the cryptographic validity of the VP/ProofClaims, and
(2) the on-chain IssuerRegistry and TrustPolicyRegistry state.

Discovery may provide configuration, but a compromised Discovery MUST NOT be
able to cause a Producer Sentinel to accept an otherwise invalid credential.

**Rationale:** Limits blast radius of Discovery compromise.

**Test criterion:**  
Simulate a compromised Discovery that serves a config bundle claiming
all credentials are valid.  Submit a revoked credential.  Assert the Producer
Sentinel still rejects with HTTP 403 `STATUS_REVOKED`.

---

## SI-005 — Disabled Issuer VCs MUST Be Rejected Immediately

**Statement:**  
When an issuer is disabled in the IssuerRegistry smart contract, all VCs
issued by that issuer MUST be rejected within one polling cycle (≤ IssuerRegistry
cache TTL).  Caches MUST be invalidated or refreshed before the next request.

**Rationale:** Ensures that a compromised issuer cannot continue to grant access
after its key is revoked on-chain.

**Test criterion:**  
Issue a valid VC from issuer I.  Disable issuer I on-chain.  After one cache
refresh cycle, submit a request with the VC.  Assert HTTP 403 `ISSUER_UNTRUSTED`.

---

## SI-006 — `alg:none` MUST Be Rejected Before Any Cryptographic Operation

**Statement:**  
The JWT parsing library MUST reject any JWT where the `alg` header is `none`,
`None`, `NONE`, or empty string BEFORE attempting signature verification or
payload parsing.

**Rationale:** Prevents algorithm confusion attacks that bypass signature checks.

**Test criterion:**  
Construct a JWT with header `{"alg": "none"}` and an arbitrary payload.
Assert `ProhibitedAlgorithmError` or `ALG_PROHIBITED` before any key lookup.

**Implementation reference:** `libs/common/src/common/crypto/algorithms.py`
`assert_algorithm_allowed()`.

---

## SI-007 — Cross-Environment Credentials Are Rejected

**Statement:**  
A credential with `env: dev` MUST be rejected in `prod` and `test` environments.
A credential with `env: test` MUST be rejected in `prod` and `dev`.

**Rationale:** Prevents environment-escalation attacks using lower-security
credentials.

**Test criterion:**  
Issue a credential with `env: dev`.  Submit to a `prod` Sentinel.
Assert HTTP 403 `ENV_MISMATCH`.

---

## SI-008 — Replay Window is 30 seconds + JTI Deduplication Cache

**Statement:**  
A ProofClaims JWT MUST be rejected if:
(a) its `exp` is in the past (beyond clock skew), OR
(b) its `jti` has already been seen in the replay cache within the last
    `max(exp − iat, 30)` seconds.

**Rationale:** Bounds the replay window to ≤ 30 seconds even if an attacker
captures a valid signed request.

**Test criterion:**  
Submit a valid request.  Re-submit the exact same token within 30 seconds.
Assert HTTP 401 on the second submission.

---

## SI-009 — Private Keys Never Leave Vault in Plaintext

**Statement:**  
All Ed25519 private keys MUST be stored in Vault (KV v2 or Transit engine).
Private key bytes MUST NOT be written to disk, logs, environment variables, or
transmitted over any non-Vault channel.

**Rationale:** Single point of key compromise via log exfiltration or disk
access is eliminated.

**Test criterion:**  
Static analysis / secret scanning: no private key patterns (`-----BEGIN`,
base64 32-byte sequences) in application logs or config files.
Dynamic: Vault audit log shows all key reads; no plaintext key appears in
application stdout/stderr.

---

## SI-010 — Audit Log Entries Are Append-Only

**Statement:**  
Every authorization decision (accept or reject) MUST produce a structured
audit log entry.  Audit log store MUST be append-only — no entry may be
modified or deleted by the application.

**Rationale:** Provides a forensic trail for incident response.

**Test criterion:**  
Attempt to DELETE or UPDATE an audit log entry via the application API.
Assert HTTP 405 or 403.  Verify the record is unchanged in the store.

---

## SI-011 — Scopes Are Checked at the Resource Level

**Statement:**  
The Producer Sentinel MUST compare the `scope` claim in
`vc.credentialSubject.scope` against the requested resource path and method
before proxying.  A credential with `scope: ["service:X:read"]` MUST NOT
authorize a POST to service X.

**Test criterion:**  
Issue a VC with `scope: ["service:citizen-data:read"]`.  Attempt a POST
to `/citizen-data/`.  Assert HTTP 403.

---

## SI-012 — All Configuration Bundles Must Be Signature-Verified

**Statement:**  
Sentinels MUST verify the JWS signature on every config bundle before applying
any field from it.  An unsigned or invalid config bundle MUST be discarded and
the previous valid config MUST be retained.

**Rationale:** Prevents a compromised Discovery from poisoning Sentinel config
(e.g., injecting a rogue upstream endpoint).

**Test criterion:**  
Serve a config bundle with a tampered signature.  Assert Sentinel logs a
`CONFIG_SIGNATURE_INVALID` error and retains the previous config.

---

## SI-013 — Status List Signature Must Be Verified Before Trusting It

**Statement:**  
Before evaluating any revocation bit, the Sentinel MUST verify the JWS
signature on the `BitstringStatusListCredential` AND verify the SHA-256 hash
of the bitstring against the on-chain anchor in `StatusListAnchor`.

**Test criterion:**  
Tamper with the bitstring bytes of a cached status list.  Assert that the
Producer Sentinel detects the hash mismatch and treats the credential as
revoked (fail-closed).

---

## SI-014 — mTLS is Required for Sentinel ↔ Discovery Communication

**Statement:**  
All communication between Sentinels and Discovery MUST use mutual TLS (mTLS).
One-way TLS (server auth only) is not sufficient for these channels.

**Test criterion:**  
Attempt to connect to Discovery without presenting a client certificate.
Assert the connection is rejected at the TLS layer.

---

## SI-015 — Production Secrets Are Never Present in Development Config

**Statement:**  
The `.env.example` file and all checked-in configuration MUST contain only
placeholder values (e.g., zeroed addresses, `REPLACE_ME` strings).  CI MUST
fail if a real private key or production secret is detected in any committed
file.

**Test criterion:**  
`detect-secrets scan --baseline .secrets.baseline` MUST produce no new findings
in CI.  Pre-commit hook enforces this on every commit.
