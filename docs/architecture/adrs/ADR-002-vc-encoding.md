# ADR-002 — VC Encoding Format (JWT-VC vs JSON-LD)

**Status:** ACCEPTED  
**Date:** 2025-01-01  
**Deciders:** Platform Architecture Working Group

---

## Context

W3C Verifiable Credentials can be secured using two major approaches:

1. **JWT-based (VC-JOSE-COSE)** — the credential is encoded as a JWT
   compact serialization with a JOSE header and JOSE signature.
2. **JSON-LD Proofs (Data Integrity)** — the credential is a JSON-LD
   document with an embedded proof object using a linked-data cryptosuite.

The system must choose one primary format for MVP.  The format governs
how VCs are issued, transmitted, verified, and stored.

---

## Decision

**Use JWT-VC (JOSE/JWT profile of VC-JOSE-COSE)** as the sole securing format
for Verifiable Credentials and Verifiable Presentations.

- Media type for VC: `application/vc+jwt`
- Media type for VP: `application/vp+jwt`
- JOSE header `typ`: `vc+jwt` / `vp+jwt`
- Algorithm: `EdDSA` (primary), `ES256` (optional secondary)

---

## Consequences

### Positive

- **Library availability** — JWT parsing is universally supported in Python,
  TypeScript/JavaScript, and all major languages.  No JSON-LD processor required.
- **Compact representation** — a compact JWT is a single string, easy to
  transmit in HTTP headers (e.g., `SentinelVP: <jwt-vp>`).
- **Simpler verification** — verification is a standard JWT check: decode
  header → resolve key → verify signature → check claims.  No RDF parsing,
  no canonicalization.
- **Wide interoperability** — JWT is the default for OIDC4VC (OpenID for
  Verifiable Credentials), ISO 18013-5 mDL, and most eIDAS 2.0 implementations.
- **Algorithm agility is controlled** — we can enforce the allowed algorithm
  set in the JOSE header without touching complex JSON-LD proof suites.

### Negative

- **Less semantic richness** — JSON-LD proofs support linked-data semantics and
  universal schema references.  For our closed e-government use case this is
  not required.
- **No `@context` expansion** — `vc.type` is a string array, not a fully
  resolved JSON-LD type.  We mitigate this with a local VC schema registry
  (TASK-004).
- **VP nesting** — a JWT-VP nests JWT-VC strings; if VCs from multiple issuers
  are bundled, the verifier must parse multiple JWTs.  This is acceptable for
  our 1-credential-per-VP MVP design.

---

## Rejected Alternatives

### JSON-LD Proofs (Data Integrity)

Requires a JSON-LD processor and a crypto suite implementation
(e.g., `Ed25519Signature2020`).  These are less mature in Python and add
significant complexity.  JSON-LD canonicalization (`URDNA2015`) is a complex
algorithm with multiple known edge cases and performance issues on constrained
environments.

### CBOR-LD / COSE

Suitable for IoT / constrained devices.  Adds complexity without benefit for
server-to-server communication.  No production-grade Python library available.

---

## References

- W3C VC Data Model v2.0 — https://www.w3.org/TR/vc-data-model-2.0/
- W3C VC-JOSE-COSE — https://www.w3.org/TR/vc-jose-cose/
- OpenID for VC — https://openid.net/specs/openid-4-verifiable-credential-issuance
