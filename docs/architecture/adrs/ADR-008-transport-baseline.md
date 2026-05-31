# ADR-008 — Transport Baseline

**Status:** ACCEPTED  
**Date:** 2025-01-01  
**Deciders:** Platform Architecture Working Group

---

## Context

The Sentinel platform communicates over three distinct channels:
1. **Consumer Sentinel → Producer Sentinel** (cross-entity requests)
2. **Sentinel → Discovery** (onboarding, config pull, VC fetch)
3. **Discovery / Sentinel → Blockchain node** (on-chain reads and writes)

Requirements:
1. **Confidentiality in transit** — all inter-service communication must be
   encrypted.
2. **Mutual authentication** for Sentinel ↔ Discovery (Security Invariant SI-014).
3. **Simplicity for MVP** — DIDComm adds overhead; standard HTTPS with header
   injection is simpler and more widely supported in existing e-government
   infrastructure.
4. **Upgrade path** — the design must allow DIDComm or RFC 9421 to be
   adopted later without changing the VP/VC core.

---

## Decision

**Baseline transport: HTTPS with TLS 1.3 (minimum TLS 1.2 for legacy gateways).**

- **Sentinel ↔ Discovery:** mTLS (mutual TLS).  Sentinels present a
  client certificate bearing their DID as a Subject Alternative Name (SAN).
- **Consumer Sentinel → Producer Sentinel:** One-way TLS (server cert on
  Producer Sentinel) + `Authorization: SentinelProof <jws>` header carrying
  the ProofClaims JWS.  The ProofClaims JWS provides mutual authentication at
  the application layer.
- **All services → Blockchain RPC:** HTTPS (JSON-RPC over TLS).

Prohibited:
- TLS 1.0, TLS 1.1, SSL 3.0 (see ADR algorithm matrix).
- Unencrypted HTTP for any channel carrying credentials or key material.

### DIDComm (Future)

DIDComm v2 may be adopted as an optional transport adapter in post-MVP.
When enabled, it would replace the raw HTTPS channel between Sentinels.
The VC/VP payload structure is protocol-agnostic and does not change.

---

## Consequences

### Positive

- **Universal support** — HTTPS + TLS 1.3 is supported by every reverse
  proxy, load balancer, firewall, and API gateway in the target government
  infrastructure.
- **No DIDComm dependency** — avoids the complexity of DIDComm message packing,
  key agreement (ECDH-ES + A256GCM), and routing.
- **Standard TLS tooling** — cert issuance, rotation, and revocation via
  standard PKI (Let's Encrypt, internal CA, or AWS ACM).
- **ProofClaims provides app-layer auth** — even without mTLS on the Consumer→
  Producer channel, the ProofClaims JWS provides cryptographic authentication
  at the application layer, bound to the specific request.

### Negative

- **mTLS cert management overhead** — managing client certificates for all
  Sentinels on the Discovery channel adds PKI complexity.
- **Not DIDComm** — pure DIDComm deployments (e.g., in self-sovereign identity
  wallets) would need an adapter.  This is acceptable for the inter-governmental
  use case where both sides are managed services.

---

## Rejected Alternatives

### DIDComm v2 (immediate adoption)

DIDComm v2 provides end-to-end encrypted, authenticated messaging using DIDs.
It is the long-term ideal transport.  However:
- No production-grade Python DIDComm library exists as of 2025-01.
- DIDComm message packing and routing adds latency for synchronous requests.
- Government firewalls may block non-standard ports/protocols.

DIDComm remains the target for post-MVP.

### gRPC / HTTP/2

Excellent performance but requires code generation (protobuf schema files)
and special handling in some government proxy environments.  REST over HTTPS
is more universally accepted.

### Plain HTTP (no TLS)

Rejected unconditionally.  Any credential or key material in transit without
encryption is a high-severity finding in any government security audit.

---

## References

- TLS 1.3 (RFC 8446) — https://www.rfc-editor.org/rfc/rfc8446
- DIDComm v2 — https://identity.foundation/didcomm-messaging/spec/v2.1/
- SI-014 in `security-invariants.md` — mTLS required for Sentinel ↔ Discovery
