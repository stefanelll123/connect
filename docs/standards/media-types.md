# Media Types — Sentinel Identity Platform

**Status:** APPROVED  
**Version:** 1.0  
**Cross-reference:** [standards-profile.md](standards-profile.md)

---

## Overview

This document enumerates every media type used by the Sentinel Identity
Platform for credential artifacts, API requests/responses, and transport
envelopes.  Service implementations MUST use the exact media type strings
listed here.  Do not use truncated or alternative forms (e.g., use
`application/vc+jwt`, not `application/jwt`).

---

## Registered Media Types

| # | Artifact | Media Type | Notes |
|---|---|---|---|
| 1 | JWT-encoded Verifiable Credential | `application/vc+jwt` | W3C VC-JOSE-COSE §4.1 |
| 2 | JWT-encoded Verifiable Presentation | `application/vp+jwt` | W3C VC-JOSE-COSE §4.2 |
| 3 | Enrollment Token | `application/jwt` | Opaque JWT; issued by Discovery |
| 4 | Config Bundle (signed) | `application/json` | JSON body with a JWS outer envelope |
| 5 | ProofClaims JWS | *(HTTP header, not body)* | `Authorization: SentinelProof <compact-JWS>` |
| 6 | Status List Credential | `application/vc+jwt` | Same type as JWT-VC |
| 7 | API request body (JSON) | `application/json` | Standard REST API payloads |
| 8 | API response body (JSON) | `application/json` | Standard REST API responses |
| 9 | Error response | `application/problem+json` | RFC 9457 Problem Details |

---

## JOSE Header `typ` Values

The JOSE header `typ` parameter identifies the token type and MUST be set:

| Artifact | `typ` value |
|---|---|
| JWT-VC | `vc+jwt` |
| JWT-VP | `vp+jwt` |
| ProofClaims JWS | `sentinel-proof+jwt` |
| Enrollment Token | `enrollment+jwt` |
| Config Bundle JWS | `sentinel-config+jwt` |

> **Note:** The `typ` value omits the `application/` prefix per RFC 8725 §3.11
> (short type names are preferred in JOSE headers).

---

## HTTP Header Usage

### Outbound Headers (Consumer Sentinel → Producer Sentinel)

| Header | Value | Purpose |
|---|---|---|
| `Authorization` | `SentinelProof <compact-JWS>` | ProofClaims JWT carrying request binding and anti-replay |
| `SentinelVP` | `<jwt-vp>` | Verifiable Presentation (contains JWT-VC) |
| `Content-Type` | `application/json` | For request bodies |

### Discovery API Auth

| Header | Value | Purpose |
|---|---|---|
| `Authorization` | `Bearer <enrollment-token>` | Sentinel authenticating to Discovery |
| `X-Sentinel-DID` | `did:key:z6Mk...` | Hint for Discovery to look up Sentinel record |

---

## Content Negotiation

APIs that return VCs MUST support `Accept: application/vc+jwt`.
APIs that return VPs MUST support `Accept: application/vp+jwt`.

Non-credential JSON endpoints use standard `application/json`.

---

## Version Media Types (Future)

If breaking changes are required in the VC structure, versioned subtypes
MUST be adopted rather than modifying the existing type:

```
application/vc+jwt;version=2
```

Existing parsers that do not recognise the version parameter MUST reject
the credential with `SCHEMA_INVALID` rather than silently misparse it.
