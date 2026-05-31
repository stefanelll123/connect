# Algorithm Matrix — Sentinel Identity Platform

**Status:** APPROVED  
**Version:** 1.0  
**Cross-reference:** [standards-profile.md](standards-profile.md)

---

## Purpose

This document lists every algorithm used in the system with its status,
applicable scope, and JWA/IANA name.  It is the single source of truth
for algorithm selection audits and compliance reviews.

Status values:
- **REQUIRED** — All implementations MUST support this algorithm.
- **OPTIONAL** — Implementations MAY support this algorithm (typically for HSM compatibility).
- **PROHIBITED** — Implementations MUST actively reject this algorithm at parse time.

---

## Algorithm Matrix

| # | Category | Algorithm | JWA Name | Status | Use Cases |
|---|---|---|---|---|---|
| 1 | DID Key Generation | Ed25519 | — | **REQUIRED** | Sentinel DID key pair generation; issuer key generation |
| 2 | VC/VP Signing | EdDSA (Ed25519) | `EdDSA` | **REQUIRED** | JWT-VC signing, JWT-VP signing, ProofClaims JWS signing |
| 3 | VC/VP Signing (HSM) | ECDSA P-256 | `ES256` | **OPTIONAL** | JWT-VC signing when HSM does not expose Ed25519 |
| 4 | JOSE Prohibited | RSASSA-PKCS1-v1_5 | `RS256`, `RS384`, `RS512` | **PROHIBITED** | Rejected in all JOSE headers |
| 5 | JOSE Prohibited | RSASSA-PSS | `PS256`, `PS384`, `PS512` | **PROHIBITED** | Rejected in all JOSE headers |
| 6 | JOSE Prohibited | HMAC with SHA-2 | `HS256`, `HS384`, `HS512` | **PROHIBITED** | Symmetric keys unsuitable for multi-party trust |
| 7 | JOSE Prohibited | No algorithm | `none`, `None`, `NONE`, `""` | **PROHIBITED** | Algorithm confusion attack — rejected before any crypto |
| 8 | Digest / Hash | SHA-256 | — | **REQUIRED** | `req.body_hash`, `req.query_hash`, bitstring anchoring, key fingerprints |
| 9 | Symmetric Encryption | AES-256-GCM | — | **REQUIRED** | Secret storage encryption at rest (private keys, enrollment tokens) |
| 10 | Key Derivation | HKDF-SHA256 | — | **REQUIRED** | Key derivation from master secret in Vault / local KDF |
| 11 | Password-Based KDF | scrypt | — | **REQUIRED** | Password-based key derivation for local (non-HSM) key storage |
| 12 | Random Generation | OS CSPRNG | — | **REQUIRED** | All key generation, JTI UUID generation, nonce generation |
| 13 | TLS | TLS 1.3 | — | **REQUIRED** | All service-to-service communication |
| 14 | TLS (minimum) | TLS 1.2 | — | **OPTIONAL** | Legacy gateway compatibility only — must disable TLS 1.0/1.1 |
| 15 | TLS Prohibited | TLS 1.0 | — | **PROHIBITED** | Deprecated; insufficient security |
| 16 | TLS Prohibited | TLS 1.1 | — | **PROHIBITED** | Deprecated; insufficient security |
| 17 | TLS Prohibited | SSL 3.0 | — | **PROHIBITED** | Cryptographically broken |
| 18 | Bitstring Compression | gzip | — | **REQUIRED** | Status list bitstring compression (per W3C Bitstring Status List) |
| 19 | Key Encoding | ED25519 multicodec + base58btc multibase | — | **REQUIRED** | `did:key` public key encoding in DID identifiers |

---

## Rationale

### Why EdDSA / Ed25519?

- 128-bit security with a compact 32-byte key and 64-byte signature.
- Deterministic signing — no per-signature randomness required, eliminating
  the Sony PS3 / ECDSA `k`-reuse vulnerability class.
- Side-channel resistance by design (constant-time implementations are standard).
- Supported natively in common HSM models (YubiHSM2, AWS CloudHSM, Google Cloud HSM).

### Why not RS256?

RSA-based algorithms require 2048-bit+ keys, produce much larger signatures,
and are vulnerable to padding oracle attacks if misconfigured.  Key management
complexity for RSA is higher than for elliptic-curve alternatives.

### Why not HS256?

Symmetric HMAC requires all verifiers to share the signing secret, which
breaks the multi-party trust model.  A compromised verifier (Sentinel) would
allow forgery of credentials.

### Why explicit `alg:none` prohibition?

Several JWT libraries historically defaulted to accepting `alg:none` if not
explicitly configured.  By treating all none-variants as a `PROHIBITED`
algorithm enumerated in code, we prevent library misconfiguration from
introducing the vulnerability.

---

## Implementation Reference

| Language | Library | Notes |
|---|---|---|
| Python | `cryptography >= 42` | Ed25519, P-256, AES-GCM, HKDF, scrypt |
| Python | `pyjwt >= 2.8` | Optional high-level JWT handling |
| Python | `joserfc >= 0.12` | Alternative JOSE implementation |
| TypeScript | `@noble/ed25519` | Browser-compatible Ed25519 |
| TypeScript | `jose` | Web Crypto API JOSE |
| Solidity | — | No asymmetric crypto on-chain; only keccak256 for hash anchoring |
