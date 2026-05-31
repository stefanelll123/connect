# Request Security Envelope Specification

**Document ID:** PROTO-002  
**Status:** Active  
**Depends on:** [Onboarding Protocol](onboarding-protocol.md), [VC Schemas](../standards/vc-validation-procedure.md)  
**Implements:** TASK-006  

---

## 1. Overview

Every request sent by a **Consumer Sentinel** to a **Producer Sentinel** must carry a cryptographically signed *Request Proof* — a compact JWS that binds the request to a specific audience, environment, HTTP method, path, query, and body.  This envelope resists replay attacks, cross-environment confusion, and body substitution.

The design uses [RFC 9449 DPoP](https://www.rfc-editor.org/rfc/rfc9449) as a reference for required properties (`jti`/`iat`/binding) but is transport-agnostic at the semantic level: the same proof structure works over direct HTTP, Discovery-routed HTTP, DIDComm, and MQTT.

---

## 2. HTTP Headers

Authenticated requests carry two required headers:

```
Authorization: SentinelProof <compact_jws_proof>
SentinelVP:    <compact_jws_vp>
```

Both headers are **required**.  Absence of either results in `401 MISSING_PROOF` or `401 MISSING_VP` respectively.  No fallback or downgrade to a weaker scheme is permitted.

---

## 3. ProofClaims JWT

### 3.1 JOSE Header

| Parameter | Value | Notes |
|-----------|-------|-------|
| `alg` | `EdDSA` | Ed25519 signing (only `EdDSA` and `ES256` are allowed) |
| `typ` | `sentinel-proof+jwt` | Must match exactly |
| `kid` | `did:key:z6Mk…#z6Mk…` | Consumer Sentinel verification method ID |

### 3.2 JWT Payload (ProofClaims)

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | string | ✅ | Consumer Sentinel DID (`did:key:z6Mk…`) |
| `aud` | string | ✅ | Producer Service DID (`did:key:z6Mk…`) |
| `env` | `"dev"│"test"│"prod"` | ✅ | Deployment environment — bound to proof |
| `iat` | integer | ✅ | Unix timestamp of signing |
| `exp` | integer | ✅ | Expiry, must equal `iat + ttl`, max 30 s |
| `jti` | string | ✅ | UUIDv4 — unique per proof, used for replay detection |
| `req` | object | ✅ | Request binding (see §3.3) |
| `nonce` | string | ➖ | Session nonce from Producer (`Sentinel-Nonce` header) |
| `trace_id` | string | ➖ | W3C trace-id for distributed tracing |

### 3.3 Request Binding Object (`req`)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `method` | string | ✅ | Uppercase HTTP method: `GET│POST│PUT│PATCH│DELETE│HEAD│OPTIONS` |
| `path` | string | ✅ | URL-decoded path with leading `/`, query excluded, max 2 048 chars |
| `query_hash` | string | ✅ | `base64url(SHA-256(raw_query_string))`; use `EMPTY_HASH` if no query |
| `body_hash` | string | ✅ | `base64url(SHA-256(raw_body_bytes))`; use `EMPTY_HASH` for GET/HEAD/empty |
| `content_type` | string│null | ➖ | Normalized Content-Type (no parameters); null for GET/HEAD/OPTIONS/DELETE |

**EMPTY_HASH constant:** `47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU`  
(base64url of SHA-256 of empty bytes)

### 3.4 Example Payload

```json
{
  "iss": "did:key:z6MkConsumerSentinelDID",
  "aud": "did:key:z6MkProducerServiceDID",
  "env": "prod",
  "iat": 1741910400,
  "exp": 1741910430,
  "jti": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "req": {
    "method": "POST",
    "path": "/api/v1/citizens/123/records",
    "query_hash": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
    "body_hash": "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
    "content_type": "application/json"
  },
  "nonce": "YOGa5yPcHcSm9wnKHxEJ",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
}
```

---

## 4. Body Hash Computation

```
body_hash = base64url(SHA-256(raw_body_bytes))
```

- Hash the **raw, undecoded bytes** as they appear on the wire — never a decoded, re-serialized, or JSON-normalized representation.
- For **gzip** `Content-Encoding`: hash the **compressed** bytes.  The Producer must decompress **after** hash verification.
- For bodyless methods (GET, HEAD, OPTIONS, TRACE) or an empty body: always use `EMPTY_HASH`.
- Maximum body size: **4 MiB**.  Requests exceeding this limit must be rejected before hash computation.

```
query_hash = base64url(SHA-256(raw_query_string.encode('utf-8')))
```
Use `EMPTY_HASH` when there is no query component.

---

## 5. Verification Procedure (Producer Sentinel)

Steps are executed in order.  A failure at any step terminates verification immediately.

| Step | Action | Error Code | HTTP |
|------|--------|-----------|------|
| 1 | Decode compact JWS header; verify `typ == "sentinel-proof+jwt"` | `PROOF_ALG_PROHIBITED` | 400 |
| 2 | Verify JWS signature using Consumer DID public key | `PROOF_SIGNATURE_INVALID` | 401 |
| 3 | Check `exp > now - maxClockSkew` | `PROOF_EXPIRED` | 401 |
| 4 | Check `iat ≤ now + maxClockSkew` | `PROOF_NOT_YET_VALID` | 401 |
| 5 | Check `exp - iat ≤ maxProofTtlSeconds` | `PROOF_TTL_TOO_LONG` | 400 |
| 6 | Check `aud == this producer's DID` | `AUD_MISMATCH` | 403 |
| 7 | Check `env == this producer's environment` | `ENV_MISMATCH` | 403 |
| 8 | Recompute `body_hash`; compare with `req.body_hash` | `BODY_HASH_MISMATCH` | 400 |
| 9 | Look up `jti` in replay cache | `REPLAY_DETECTED` | 401 |
| 10 | **INSERT** `jti` into replay cache **before** forwarding | — | — |
| 11 | Validate nonce (if session nonce is active) | `NONCE_INVALID` | 401 |
| 12 | Parse claims into typed `ProofClaims`; proceed to VP verification | — | — |

> **TOCTOU security invariant:** Step 10 (INSERT) **must** precede forwarding the request to the backend service.  Inserting the jti *after* forwarding creates a race window where two concurrent identical requests could both pass step 9 before either has been inserted.

---

## 6. Replay Cache

### 6.1 Cache Key

```
replay:{jti}:{iss}
```

Combining `jti` and `iss` (Consumer DID) prevents cross-issuer JTI collisions.

### 6.2 TTL Formula

```
cache_ttl = (exp - iat) + maxClockSkew + 5 seconds
```

The TTL **must not** be shorter than the full proof validity window.

### 6.3 Redis Implementation (Multi-Instance)

```
SET replay:{jti}:{iss} "1" PX {ttl_ms} NX
```

`SET NX` is atomic — if it returns `nil`, the key existed → `REPLAY_DETECTED`.

### 6.4 In-Memory Fallback (Single-Instance / Development)

An in-process dict with expiry timestamps provides single-node replay protection.  Log a warning when this fallback is active in a multi-instance deployment.

---

## 7. Session Nonce (Defence-in-Depth)

The Producer can require a per-session nonce by returning it in a response:

```
Sentinel-Nonce: <nonce_value>
```

The Consumer **must** include this value as `nonce` in the next proof.  The Producer verifies it and marks it consumed.

Redis key: `session_nonce:{producer_did}:{consumer_did}:{nonce}`, TTL 300 s.

Session nonces are an **additional** layer — their absence does not exempt a proof from replay-cache protection.

---

## 8. VP Binding

After ProofClaims passes all steps, extract the VP from `SentinelVP`:

1. Verify VP JWT signature.
2. Verify `VP.nonce == ProofClaims.jti` — the VP is bound to this specific proof instance.
3. Verify VP contains at least one `AccessGrantCredential`.
4. Pass VP to the policy engine (TASK-047).

---

## 9. Path Rewriting and Intermediaries

When Discovery or a load balancer rewrites the URL path, the `req.path` **must** be the path as presented to the Producer Sentinel.

Configuration option: `proof_path_mode`:
- `"original"` — Consumer uses the path it originally constructed.
- `"rewritten"` — Consumer uses the path as the Producer will receive it (requires coordination with the intermediary).

---

## 10. Error Response Format

All verification errors return JSON:

```json
{
  "error": "REPLAY_DETECTED",
  "message": "Proof jti has already been seen in the replay window.",
  "correlation_id": "<uuid>"
}
```

| Code | HTTP | Description |
|------|------|-------------|
| `MISSING_PROOF` | 401 | `Authorization: SentinelProof` header absent |
| `MISSING_VP` | 401 | `SentinelVP` header absent |
| `PROOF_ALG_PROHIBITED` | 400 | Prohibited `alg` or wrong `typ` |
| `PROOF_SIGNATURE_INVALID` | 401 | JWS signature verification failed |
| `PROOF_EXPIRED` | 401 | `exp` has passed |
| `PROOF_NOT_YET_VALID` | 401 | `iat` is too far in the future |
| `PROOF_TTL_TOO_LONG` | 400 | `exp - iat` exceeds max |
| `AUD_MISMATCH` | 403 | `aud` does not match this Producer's DID |
| `ENV_MISMATCH` | 403 | `env` does not match this Producer's environment |
| `BODY_HASH_MISMATCH` | 400 | Recomputed body hash does not match |
| `REPLAY_DETECTED` | 401 | `jti` already in replay cache |
| `NONCE_INVALID` | 401 | Session nonce absent or wrong |

---

## 11. Security Constraints Summary

1. `jti` **must** be inserted into the replay cache before backend forwarding (TOCTOU).
2. Replay cache TTL **must** cover the full validity window — never truncate.
3. `body_hash` **must** be computed over raw undecoded wire bytes.
4. For gzip content-encoding, hash the compressed bytes.
5. Session nonce absence does not bypass replay protection.
6. Cross-environment replay is prevented by `env` binding in **both** ProofClaims and VP.
7. VP is bound to ProofClaims via `VP.nonce == ProofClaims.jti`.
