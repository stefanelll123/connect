# Secure Sentinel Onboarding Protocol

**Document version:** 1.0  
**Status:** Approved  
**Depends on:** ADR-008 (Transport Baseline), TASK-003 (Crypto), TASK-004 (VC Schemas)

---

## 1. Overview

The onboarding protocol is a two-phase mutual-authentication handshake that allows a Sentinel (producer or consumer) to register itself with the Discovery service and receive its initial configuration bundle and verifiable credentials.

The protocol provides:

* **Identity binding** — the Sentinel's DID key is cryptographically bound to its enrollment token at completion time.
* **Anti-replay** — enrollment tokens are one-time-use; challenges expire in 120 seconds; JTI dedup in Redis.
* **Environment isolation** — tokens are bound to a specific `(service_id, role, env)` triple; cross-env registration is impossible.
* **Operator approval gate** — prod tokens require a second admin to approve before they can be used.

---

## 2. Actors

| Actor | Description |
|-------|-------------|
| **Admin** | Human operator with `enrollment-admin` role; holds Discovery API credentials |
| **Sentinel** | Software component being onboarded; holds an Ed25519 DID key pair |
| **Discovery** | Backend service; issues tokens, validates proofs, emits config bundles |

---

## 3. Enrollment Token

### 3.1 JWT Structure

```
Header:
  alg: "EdDSA"
  typ: "enrollment+jwt"
  kid: "<Discovery enrollment signing key DID fragment>"

Payload:
  iss:                            "<Discovery service DID>"
  jti:                            "<UUIDv4>"          — token ID; stored as hash(jti) in DB
  iat:                            <Unix timestamp>
  exp:                            <iat + 600>          — default 10-minute window
  service_id:                     "<service identifier>"
  role:                           "PRODUCER" | "CONSUMER"
  env:                            "dev" | "test" | "prod"
  nonce:                          "<base64url(32 random bytes)>"
  required_approval:              true | false
  instance_metadata_constraints:  null | { cloud_provider, region, instance_id }
```

### 3.2 Lifecycle

```
PENDING  → (second admin approves) → APPROVED
APPROVED → (Sentinel uses)         → CONSUMED
PENDING  → (30-min window passes)  → EXPIRED (GC)
```

Only tokens in status `APPROVED` can be used in Phase 1. Attempting to use a `PENDING` or `CONSUMED` token returns the respective error code.

### 3.3 Storage

Discovery stores `SHA-256(raw_token_bytes)` in the database, never the plaintext token. The plaintext token is returned **once** in the token-creation API response and is never logged or re-exposed.

---

## 4. Phase 1 — Challenge Request

Sentinel → Discovery: `POST /api/v1/sentinels/onboard`

### Request body

```json
{
  "enrollment_token": "<JWT compact>",
  "did":              "did:key:z6Mk...",
  "did_public_key_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x":   "<base64url>"
  }
}
```

### Discovery validation steps

1. Parse and verify enrollment token JWS signature using Discovery's enrollment signing key.
2. Check `exp` — reject with `ENROLLMENT_TOKEN_EXPIRED` if expired.
3. Compute `hash(enrollment_token)` and look up in DB.
4. Check status == `APPROVED` — reject with `ENROLLMENT_TOKEN_NOT_APPROVED` (status PENDING) or `ENROLLMENT_TOKEN_ALREADY_CONSUMED` (status CONSUMED).
5. Validate `did` format: must match `^did:key:z6Mk`.
6. Validate `did_public_key_jwk`: `kty=OKP`, `crv=Ed25519`, no `d` field.

### Challenge generation

```
server_challenge = base64url(os.urandom(32))
Redis.SET onboard_challenge:{jti} {server_challenge} EX 120
```

### Response (HTTP 200)

```json
{
  "challenge":      "<base64url, 32 bytes>",
  "expires_in":     120,
  "correlation_id": "<UUID>"
}
```

---

## 5. Phase 2 — Proof Submission

Sentinel → Discovery: `POST /api/v1/sentinels/onboard/complete`

### Proof JWT

The Sentinel constructs and signs a Proof of Possession JWT:

```
Header:
  alg: "EdDSA"
  typ: "onboard-proof+jwt"
  kid: "<Sentinel DID>#<multibase pubkey>"

Payload:
  iss:        "<Sentinel DID>"
  aud:        "<Discovery DID>"
  iat:        <Unix timestamp>
  exp:        <iat + 120>        — maximum window; MUST NOT exceed 120s
  token_id:   "<enrollment token jti>"
  challenge:  "<base64url challenge received from Phase 1>"
```

### Request body

```json
{
  "enrollment_token": "<JWT compact>",
  "proof":            "<Proof JWT compact>"
}
```

### Discovery verification steps (atomic)

1. Re-verify enrollment token signature and expiry.
2. Look up `onboard_challenge:{jti}` in Redis — return `CHALLENGE_EXPIRED` if missing.
3. Resolve `sentinel_did` from Phase 1 request (stored in Redis alongside challenge).
4. For `did:key`, derive Ed25519 public key directly from the DID string (no network call).
5. Verify proof JWT signature using derived public key → `PROOF_SIGNATURE_INVALID`.
6. Check `proof.aud == Discovery DID` → `PROOF_INVALID`.
7. Check `proof.challenge == stored challenge` → `PROOF_INVALID`.
8. Check `proof.token_id == enrollment.jti` → `TOKEN_MISMATCH`.
9. Check `proof.exp - proof.iat <= 120` → `PROOF_INVALID`.
10. Execute atomic DB transaction:
    - `SELECT * FROM enrollment_tokens WHERE token_hash = hash(token) FOR UPDATE`
    - Set `consumed_at = now()`, `status = CONSUMED`
    - `INSERT INTO sentinels ...` or `UPDATE sentinels SET ...` if re-onboarding
11. Delete challenge from Redis.
12. Return onboarding bundle.

---

## 6. Onboarding Bundle

```json
{
  "sentinel_id": "<UUID>",
  "did":         "did:key:z6Mk...",
  "role":        "PRODUCER" | "CONSUMER",
  "env":         "dev" | "test" | "prod",
  "service_id":  "<service identifier>",
  "config_version": 1,
  "bundle": { "< signed config bundle — see TASK-027 >" },
  "initial_credentials": ["<JWT-VC>", ...],
  "trust_anchors": {
    "chain_network": "sepolia",
    "chain_id":      11155111,
    "rpc_urls":      ["https://rpc.example.gov/sepolia"],
    "contract_addresses": {
      "issuer_registry":         "0x...",
      "trust_policy_registry":   "0x...",
      "status_registry":         "0x...",
      "service_registry":        "0x..."
    }
  }
}
```

---

## 7. Re-onboarding / Migration

When a Sentinel migrates to a new VM, the admin issues a **migration ticket** via:

```
POST /api/v1/sentinels/{sentinel_id}/migration-ticket
Body: { "reason": "<string, max 500 chars>" }
```

Migration ticket JWT:

```
Header: { alg: "EdDSA", typ: "migration-ticket+jwt", kid: "..." }
Payload:
  iss:          "<Discovery DID>"
  jti:          "<UUID>"
  iat, exp:     <iat + 1800>  — 30 min
  sentinel_id:  "<UUID>"
  sentinel_did: "<known Sentinel DID>"
  reason:       "<string>"
```

The re-onboarding flow is identical to initial onboarding (Phase 1 + Phase 2), but:

* Uses `migration_ticket` instead of `enrollment_token` in the request body.
* Discovery updates `instance_metadata` and `last_seen` rather than creating a new record.
* The Sentinel MUST present the **same DID** as stored in the sentinel record — DID rotation during migration is not permitted; use the key-rotation protocol instead (see TASK-042).

---

## 8. Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| `ENROLLMENT_TOKEN_INVALID` | 400 | JWT signature or structure is invalid |
| `ENROLLMENT_TOKEN_EXPIRED` | 401 | JWT `exp` claim has passed |
| `ENROLLMENT_TOKEN_NOT_APPROVED` | 401 | Token exists but status is PENDING |
| `ENROLLMENT_TOKEN_ALREADY_CONSUMED` | 409 | Token has already been used |
| `DID_FORMAT_INVALID` | 400 | DID string does not match `^did:key:z6Mk` |
| `JWK_INVALID` | 400 | Public key JWK is malformed or wrong curve |
| `CHALLENGE_EXPIRED` | 400 | Challenge nonce has expired (>120 s) |
| `PROOF_SIGNATURE_INVALID` | 401 | PoP proof JWT signature does not verify |
| `PROOF_INVALID` | 400 | Proof JWT structure or claims are invalid |
| `TOKEN_MISMATCH` | 401 | `proof.token_id` does not match enrollment token `jti` |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many onboarding attempts (max 5/token, 10/IP/min) |

Error response body:

```json
{
  "error":          "<error_code>",
  "message":        "<human-readable, non-sensitive description>",
  "correlation_id": "<UUID>"
}
```

---

## 9. Security Constraints

1. Enrollment token MUST be consumed atomically using `SELECT FOR UPDATE` — concurrent-replay prevention.
2. Plaintext token returned **once** at creation — never stored, never logged.
3. Discovery stores `hash(enrollment_token)` — not the token itself.
4. Challenge stored in Redis with `TTL=120` — not in DB — ensuring expiry is hard.
5. `proof.exp - proof.iat` MUST be ≤ 120 s — longer-lived proofs are rejected.
6. mTLS MUST be enforced on `/api/v1/sentinels/onboard` — plaintext HTTP returns 400.
7. Rate limiting: max 5 attempts per token jti, 10 per IP per minute.
8. Instance metadata constraints (if present in token) MUST be verified on Phase 2.

---

## 10. Threat Mapping

| Threat | Mitigation |
|--------|-----------|
| T-002 Rogue Sentinel registration | One-time token + PoP challenge-response |
| T-005 Enrollment token theft in transit | mTLS onboarding channel |
| SI-002 Sentinel must authenticate with unique DID | DID bound at Phase 1; verified at Phase 2 |
| SI-008 Enrollment tokens one-time use | `consumed_at` + `SELECT FOR UPDATE` |
