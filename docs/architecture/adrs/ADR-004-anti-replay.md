# ADR-004 — Request Anti-Replay Strategy

**Status:** ACCEPTED  
**Date:** 2025-01-01  
**Deciders:** Platform Architecture Working Group

---

## Context

Every cross-entity HTTP request carries a Verifiable Presentation (JWT-VP)
authorizing the Consumer Sentinel to access the Producer.  Without an
anti-replay mechanism, an attacker who captures a valid request (network
eavesdropping, log exposure) could replay it to gain access.

Requirements:
1. **Per-request uniqueness** — each signed proof is cryptographically
   unique to the specific request (method + path + query + body).
2. **Short expiry** — the window of opportunity for replay is bounded.
3. **Audience binding** — the proof cannot be replayed to a different service.
4. **Environment binding** — the proof cannot be replayed across environments.
5. **Stateless for consumer** — Consumer Sentinel must not require shared state
   with Producer Sentinel to construct a proof.

---

## Decision

**Use a DPoP-inspired ProofClaims JWS** attached to every cross-entity request.

### ProofClaims JWT Structure

```json
// Header
{ "alg": "EdDSA", "typ": "sentinel-proof+jwt", "kid": "<consumer-sentinel-vm-id>" }

// Payload
{
  "iss": "<consumer-sentinel-did>",
  "aud": "<producer-service-did>",
  "env": "prod",
  "iat": 1700000000,
  "exp": 1700000030,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "req": {
    "method": "GET",
    "path": "/citizen-data/12345",
    "query_hash": "<sha256-b64url-of-raw-query>",
    "body_hash": "<sha256-b64url-of-raw-body>"
  },
  "nonce": "<opaque-from-producer-or-discovery>"
}
```

### Anti-Replay Enforcement (Producer Sentinel)

1. Verify JWT signature (EdDSA, via Consumer DID key).
2. Check `exp` — MUST be ≤ now + max_clock_skew.
3. Check `jti` is not in the JTI replay cache (Redis SETNX, TTL = `exp - iat`).
4. Check `aud` = current service DID.
5. Check `env` = current environment.
6. Check `req.method`, `req.path`, `req.query_hash`, `req.body_hash` match
   the actual inbound request.

TTL of ProofClaims: **30 seconds** (configurable; minimum enforced = 10s,
maximum = 120s in non-prod).

---

## Consequences

### Positive

- **Request binding** — proof is cryptographically bound to the exact HTTP
  method, path, query string, and body.  Modifying any field invalidates it.
- **Short TTL** — 30 s window minimizes replay risk.
- **Standard pattern** — inspired by RFC 9449 DPoP; well-understood and
  auditable.
- **No pre-shared secrets** — Consumer Sentinel's DID key is the only material
  needed; no HMAC secret distribution.
- **Environment isolation** — `env` claim prevents cross-env replay.

### Negative

- **JTI cache state** — Producer Sentinel must maintain a short-lived
  JTI → seen cache (Redis).  In multi-instance deployments, all instances
  must share this cache.
- **Body hash overhead** — computing SHA-256 of the request body adds latency
  for large payloads (mitigated: this is a streaming hash, not buffering).
- **Clock synchronization required** — Consumer and Producer clocks must be
  within `max_clock_skew` (30 s default).  NTP is assumed; enforced in
  deployment via `chrony`.

---

## Rejected Alternatives

### Bearer Token (static JWT)

A static access token carries no request-specific binding.  Replayable
indefinitely until expiry.  Does not bind to request method/path/body.

### HMAC-based request signing (AWS Signature v4 style)

Requires a shared secret between Consumer and Producer.  In a multi-entity
government context, distributing shared secrets is operationally complex and
creates a key-distribution problem.

### RFC 9421 HTTP Message Signatures (immediate adoption)

The full RFC 9421 approach is more comprehensive but requires HTTP-aware
intermediaries that inspect and re-sign forwarded requests.  Adopted as a
future upgrade path (see `standards-profile.md §7`).

### Nonce-only approach (producer issues nonce, consumer uses it once)

Requires a round-trip to the Producer before each request (nonce fetch → sign
→ submit).  Doubles latency for every request.  Acceptable for high-security
operations but not as the default flow.

---

## References

- RFC 9449 DPoP — https://www.rfc-editor.org/rfc/rfc9449
- RFC 9421 HTTP Message Signatures — https://www.rfc-editor.org/rfc/rfc9421
