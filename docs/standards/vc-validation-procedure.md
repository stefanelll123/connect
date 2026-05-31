# VC/VP Validation Procedure

**Status:** APPROVED  
**Version:** 1.0  
**Applies to:** All Sentinel services that consume a JWT-VC or JWT-VP

---

## Overview

This document defines the **deterministic 10-step procedure** for verifying a
Verifiable Credential (JWT-VC) or Verifiable Presentation (JWT-VP).  Steps
are numbered and ordered.  **Any step failure MUST immediately halt processing
and return the indicated error code** — partial verification is not permitted.

The term *verifier* refers to any Sentinel instance (typically a Producer
Sentinel) that validates a credential before authorizing a request.

---

## Inputs

| Parameter | Type | Description |
|---|---|---|
| `token` | string | JWT-VC or JWT-VP compact serialization |
| `expected_issuer_did` | string \| None | Expected `iss` DID, or None to skip issuer pin |
| `expected_subject_did` | string | Consumer Sentinel's DID (`sub` must match) |
| `expected_audience_did` | string | Producer Service DID (matched against `vc.credentialSubject.aud`) |
| `expected_env` | string | Active environment: `dev` \| `test` \| `prod` |
| `max_clock_skew_seconds` | int | Allowed clock skew (default: 30 s) |
| `issuer_registry` | IssuerRegistry | On-chain or cached registry of trusted issuers |
| `status_list_cache` | StatusListCache | Cache + fetcher for Bitstring Status Lists |

---

## 10-Step Verification Procedure

### Step 1 — Parse JOSE Header and Validate Algorithm

1. Split the token on `.` — MUST have exactly 3 parts; otherwise → `INVALID_SIGNATURE`.
2. base64url-decode the header.
3. Parse as JSON — malformed JSON → `INVALID_SIGNATURE`.
4. Extract `alg`. 
5. If `alg` is in `PROHIBITED_ALGS` or is absent/empty → **HALT with `ALG_PROHIBITED`**.
6. If `alg` is not in `ALLOWED_ALGS` → **HALT with `ALG_PROHIBITED`**.

> **Rationale:** Algorithm check MUST precede all other steps to prevent
> algorithm confusion attacks.

---

### Step 2 — Resolve Issuer DID and Retrieve Public Key

1. Parse the payload (base64url-decode, JSON-parse).
2. Extract `iss` claim — MUST be a non-empty string → else `ISSUER_UNTRUSTED`.
3. If `iss` does not start with `did:key:` and `did:ethr:` is not supported → `DID_UNRESOLVABLE`.
4. Call `resolve_did_key(iss)` with a timeout of **2000 ms**.
5. Timeout or network failure → **HALT with `DID_UNRESOLVABLE`**.
6. Extract the verification key from the DID Document (match `kid` in header
   to verification method ID).
7. If no match → **HALT with `DID_UNRESOLVABLE`**.

---

### Step 3 — Verify JWT Signature

1. Re-compute the signing input: `BASE64URL(header) || '.' || BASE64URL(payload)`.
2. Verify the signature bytes against the signing input using the public key from Step 2.
3. Any signature verification failure → **HALT with `INVALID_SIGNATURE`**.

---

### Step 4 — Verify `iss` Matches Expected Issuer

1. If `expected_issuer_did` is provided:
   - `iss` MUST equal `expected_issuer_did` (exact string match) → else `ISSUER_UNTRUSTED`.
2. If `expected_issuer_did` is None: pass (dynamic issuer resolution used).

---

### Step 5 — Verify `sub` Matches Consumer Sentinel DID

1. Extract `sub` claim — MUST be non-empty.
2. `sub` MUST equal `expected_subject_did` → else `AUD_MISMATCH`.

> **Rationale:** Prevents a credential issued for Sentinel A from being used
> by Sentinel B.

---

### Step 6 — Verify Temporal Validity

1. Extract `nbf` (not-before) and `exp` (expiry) — both MUST be present as
   NumericDate integers.
2. Let `now = current Unix timestamp`.
3. `now < (nbf - max_clock_skew_seconds)` → **HALT with `VC_NOT_YET_VALID`**.
4. `now > (exp + max_clock_skew_seconds)` → **HALT with `VC_EXPIRED`**.

---

### Step 7 — Verify `env` Claim

1. Navigate to `vc.credentialSubject.env` (or top-level `env` claim).
2. `env` MUST equal `expected_env` (exact, case-sensitive) → else `ENV_MISMATCH`.

> **Rationale:** Prevents cross-environment replay (using a `dev` VC in `prod`).
> See threat T-003.

---

### Step 8 — Verify `aud` Claim (Audience Binding)

1. Navigate to `vc.credentialSubject.aud`.
2. `aud` MUST equal `expected_audience_did` → else `AUD_MISMATCH`.

> **Note:** For VPs, `aud` in the top-level JWT payload is also checked.

---

### Step 9 — Check Revocation Status

1. Extract `credentialStatus` from `vc.credentialStatus`.
2. If absent and `statusPurpose: revocation` was expected → `STATUS_REVOKED` (fail-closed).
3. Fetch `statusListCredential` URL from cache.
4. If cache is stale beyond Δ (see outage policy) → apply FAIL_CLOSED mode.
5. Verify the Status List Credential's own signature (recursively verify the
   JWT-VC — but only Steps 1–3 and Step 6 to avoid infinite recursion).
6. Decompress the bitstring (gzip, base64url-decode).
7. Check the bit at index `statusListIndex`.
8. If bit is `1` → **HALT with `STATUS_REVOKED`**.

---

### Step 10 — Verify Issuer is Active in IssuerRegistry (On-Chain)

1. Query `issuer_registry.is_active(iss)`.
2. If the result is `false` or the query fails → **HALT with `ISSUER_UNTRUSTED`**.
3. If the on-chain query times out (> 2000 ms) and the cache is stale → FAIL_CLOSED.

---

## Verification Result

On success (all steps pass), return:

```json
{
  "valid": true,
  "error_code": null,
  "error_detail": null,
  "verified_at": "2025-01-15T10:30:00Z"
}
```

On failure at any step, return:

```json
{
  "valid": false,
  "error_code": "VC_EXPIRED",
  "error_detail": "VC expired at 2025-01-14T08:00:00Z (now: 2025-01-15T10:30:00Z)",
  "verified_at": "2025-01-15T10:30:00Z"
}
```

### Error Code Reference

| Error Code | HTTP Status | Step | Description |
|---|---|---|---|
| `ALG_PROHIBITED` | 400 | 1 | JWT uses a prohibited or missing algorithm |
| `INVALID_SIGNATURE` | 401 | 3 | JWT signature verification failed or token malformed |
| `ISSUER_UNTRUSTED` | 403 | 4, 10 | Issuer DID not trusted or not active in registry |
| `AUD_MISMATCH` | 403 | 5, 8 | Subject or audience DID does not match expected |
| `VC_NOT_YET_VALID` | 401 | 6 | VC `nbf` is in the future beyond clock skew |
| `VC_EXPIRED` | 401 | 6 | VC `exp` is in the past beyond clock skew |
| `ENV_MISMATCH` | 403 | 7 | VC `env` claim does not match current environment |
| `STATUS_REVOKED` | 403 | 9 | Credential is marked revoked in the status list |
| `SCHEMA_INVALID` | 400 | — | VC payload does not conform to expected schema |
| `DID_UNRESOLVABLE` | 502 | 2 | Issuer DID cannot be resolved within timeout |

---

## Clock Skew Policy

| Environment | `max_clock_skew_seconds` |
|---|---|
| `prod` | 30 |
| `test` | 60 |
| `dev` | 300 |

---

## Cross-References

- Algorithm constants: `libs/common/src/common/crypto/algorithms.py`
- DID resolution: `libs/common/src/common/crypto/did_key.py`
- JWS verification: `libs/common/src/common/crypto/jws.py`
- Outage/staleness policy: `docs/security/outage-policy.md`
- Threat model (cross-env replay T-003, replay T-001): `docs/security/threat-model.md`
