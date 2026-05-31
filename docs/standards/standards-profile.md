# Standards Profile — Sentinel Identity Platform

**Status:** APPROVED  
**Version:** 1.0  
**Effective from:** 2025-01-01  
**Owner:** Platform Security Working Group

---

## 1. Purpose and Scope

This document is the **authoritative, immutable standards selection** for every
cryptographic, transport, and data-format decision in the Sentinel Identity
Platform.  Engineering teams **MUST NOT** make algorithm or format selections
beyond what is defined here without a formal ADR amendment.

Scope: All services, libraries, smart contracts, and client applications that
exchange Verifiable Credentials, Verifiable Presentations, or signed request
proofs within the platform ecosystem.

---

## 2. DID Method

| Property | Selection |
|---|---|
| Primary DID method | **`did:key`** — W3C DID Core v1.0 + did:key v0.7 |
| Fallback DID method | `did:ethr` (on-chain, reserved for future on-chain resolution) |

### 2.1 Key Derivation for `did:key`

1. Generate an **Ed25519 key pair** using a CSPRNG.
2. Encode the raw 32-byte public key with the **Ed25519 multicodec prefix**
   `0xed01` (little-endian varint).
3. base58btc-encode the prefixed bytes: `z<base58btc(0xed01 || pubkey)>`.
4. Prepend `did:key:` → `did:key:z6Mk...`.

### 2.2 DID Document Structure

A `did:key` DID Document for Ed25519 contains exactly:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "verificationMethod": [{
    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  }],
  "authentication": ["did:key:z6Mk...#z6Mk..."],
  "assertionMethod": ["did:key:z6Mk...#z6Mk..."]
}
```

> **No `service` endpoints.** `did:key` DIDs are self-contained.  Service
> endpoints, if needed, are communicated via signed config bundles.

---

## 3. Verifiable Credentials Data Model

| Property | Selection |
|---|---|
| Specification | W3C VC Data Model v2.0 |
| Securing format | **JWT** (JOSE) — not JSON-LD Proofs |
| Media type | `application/vc+jwt` |

### 3.1 JWT Claim Mapping (VC DM 2.0 → JWT)

| VC DM 2.0 field | JWT claim | Type |
|---|---|---|
| `issuer` | `iss` | string (DID) |
| `credentialSubject.id` | `sub` | string (DID) |
| `validFrom` | `nbf` | NumericDate (Unix seconds) |
| `validUntil` | `exp` | NumericDate (Unix seconds) |
| `id` | `jti` | string (URN UUID) |
| `type` | `vc.type` | array of strings |
| *(all credential claims)* | `vc.credentialSubject.*` | per-schema |

### 3.2 JOSE Header for JWT-VC

```json
{
  "alg": "EdDSA",
  "typ": "vc+jwt",
  "kid": "<issuer-DID>#<verification-method-id>"
}
```

---

## 4. Securing Mechanism — JOSE/JWT Profile

| Property | Selection |
|---|---|
| Specification | W3C VC-JOSE-COSE |
| Profile | JOSE/JWT |
| Primary algorithm | **EdDSA (Ed25519)** |
| Secondary algorithm | **ES256 (P-256)** — optional |
| Prohibited algorithms | RS256, RS384, RS512, PS256, HS256, HS384, HS512, `alg:none`, NONE, None |

> **MUST explicitly reject `alg:none`** at the library level, in all casing
> variants (`none`, `None`, `NONE`), before any signature verification step.

### 4.1 JWT-VP Securing

Verifiable Presentations are also secured as JWT-VP:

- Media type: `application/vp+jwt`
- JOSE header `typ`: `vp+jwt`
- Payload carries `vp` claim containing the `verifiableCredential` array
  (each VC is its own compact JWT string).

---

## 5. Revocation / Credential Status

| Property | Selection |
|---|---|
| Specification | W3C Bitstring Status List v1.0 |
| Status credential type | `BitstringStatusListCredential` |
| Bitstring encoding | base64url-encoded gzip-compressed bitstring |

### 5.1 `credentialStatus` Claim

Every issued VC **MUST** include:

```json
"credentialStatus": {
  "id": "https://discovery.example.gov/status/list-001#42",
  "type": "BitstringStatusListEntry",
  "statusListIndex": "42",
  "statusListCredential": "https://discovery.example.gov/status/list-001",
  "statusPurpose": "revocation"
}
```

### 5.2 On-Chain Anchoring

The SHA-256 hash of the raw status list bitstring bytes is anchored in the
`TrustPolicyRegistry` smart contract on each update.  Sentinels verify the
downloaded bitstring against the on-chain hash before trusting it.

---

## 6. Request Anti-Replay — ProofClaims

See TASK-006 for the full ProofClaims specification.  Summary:

| Claim | Type | Description |
|---|---|---|
| `iss` | string | Consumer Sentinel DID |
| `aud` | string | Producer Service DID (or Discovery DID) |
| `env` | string | Environment: `dev` / `test` / `prod` |
| `iat` | NumericDate | Issued-at timestamp |
| `exp` | NumericDate | `iat + 30` seconds — TTL for anti-replay |
| `jti` | string | UUIDv4, unique per request — fed into replay cache |
| `req.method` | string | Uppercase HTTP method (`GET`, `POST`, …) |
| `req.path` | string | URL-decoded path with leading `/` |
| `req.query_hash` | string | SHA-256(raw query string), base64url |
| `req.body_hash` | string | SHA-256(raw body bytes), base64url |
| `nonce` | string | Opaque challenge from producer or Discovery |

Transmitted as: `Authorization: SentinelProof <compact-JWS>`

---

## 7. HTTP Integration

- **MVP**: ProofClaims header approach only (see §6).
- **Future**: RFC 9421 HTTP Message Signatures as an optional advanced mode.
  When adopted, signed components MUST include:
  `@method`, `@path`, `@query`, `content-digest`, `content-type`.

---

## 8. Media Types Reference

| Artifact | Media Type |
|---|---|
| JWT-VC | `application/vc+jwt` |
| JWT-VP | `application/vp+jwt` |
| ProofClaims JWS | Compact serialization in `Authorization: SentinelProof <jws>` |
| Config Bundle | `application/json` with JWS envelope |
| Enrollment Token | `application/jwt` |
| Status List Credential | `application/vc+jwt` |

---

## 9. Validation Rules Overview

See [vc-validation-procedure.md](vc-validation-procedure.md) for the
deterministic 10-step procedure.  Any failure MUST halt validation immediately
and return a specific error code (see `VCValidationResult` in TASK-003).

---

## 10. Non-Normative References

- W3C DID Core v1.0 — https://www.w3.org/TR/did-core/
- W3C VC Data Model v2.0 — https://www.w3.org/TR/vc-data-model-2.0/
- W3C VC-JOSE-COSE — https://www.w3.org/TR/vc-jose-cose/
- W3C Bitstring Status List v1.0 — https://www.w3.org/TR/vc-bitstring-status-list/
- did:key method v0.7 — https://w3c-ccg.github.io/did-method-key/
- RFC 9449 DPoP — https://www.rfc-editor.org/rfc/rfc9449
- RFC 9421 HTTP Message Signatures — https://www.rfc-editor.org/rfc/rfc9421
- Multicodec — https://github.com/multiformats/multicodec
- Multibase — https://github.com/multiformats/multibase
