# ADR-001 — DID Method Selection

**Status:** ACCEPTED  
**Date:** 2025-01-01  
**Deciders:** Platform Architecture Working Group

---

## Context

The platform requires decentralized identifiers (DIDs) for Sentinels (both
consumer and producer) and for credential issuers.  The DID method determines
how public keys are published and resolved.

Key constraints:
1. **MVP timeline** — on-chain DID registration delays would significantly
   slow development and testing.
2. **No always-online dependency** — Sentinel enforcement must work without
   contacting an external DID resolver.
3. **Key agility** — migrating a Sentinel to a new key pair must be possible
   without changing the service's identity contract.
4. **Multi-instance** — multiple Sentinel instances for the same service must
   share the same DID.

---

## Decision

**Primary DID method: `did:key`** for all Sentinel and issuer DIDs in MVP.

Key derivation:
- Ed25519 key pair → 32-byte raw public key
- Prefix with multicodec `0xed01` → base58btc-encode with `z` multibase prefix
- Result: `did:key:z6Mk...`

**Reserve `did:ethr`** for on-chain registered entities in a future iteration
(production anchor, cross-chain interoperability).

---

## Consequences

### Positive

- **Self-contained resolution** — a `did:key` DID encodes its own public key;
  no network call required for resolution.
- **Zero on-chain cost** — no gas fees, no registration delay, no dependency
  on a live RPC endpoint during enrollment.
- **Spec compliant** — W3C DID Core v1.0 + did:key v0.7; all major JOSE
  libraries support Ed25519 key parsing.
- **Deterministic** — the same key always yields the same DID; simple to test.

### Negative

- **Key rotation changes DID** — if the private key is compromised and the
  public key changes, the service gets a new DID.  All VCs issued to the old
  DID become invalid and must be re-issued.
- **No service discovery** — `did:key` documents contain no service endpoints;
  service locations are communicated via signed config bundles.
- **No on-chain revocability** — the DID itself cannot be disabled on-chain
  (only the issuer can be disabled in IssuerRegistry).

---

## Rejected Alternatives

### `did:web`

Requires an HTTPS endpoint hosting the DID Document.  Introduces an HTTP
dependency for DID resolution, which fails offline and creates a SSRF surface.
Also requires DNS / TLS certificate management per entity.

### `did:ethr` (immediate adoption)

Requires a running EVM node and gas for every registration.  Slows down the MVP
and forces development environments to run a local chain.  Added as a reserve
method for post-MVP.

### `did:peer`

Pairwise DIDs — not suitable for a multi-consumer, multi-producer topology where
the DID must be consistently referenceable across multiple relationships.

---

## References

- W3C DID Core v1.0 — https://www.w3.org/TR/did-core/
- did:key v0.7 — https://w3c-ccg.github.io/did-method-key/
- Multicodec Ed25519 — https://github.com/multiformats/multicodec
