# OWASP ASVS v4.0 Control Mapping

**Document version:** 1.0  
**Standard:** OWASP Application Security Verification Standard v4.0  
**Scope:** Sentinels (Consumer + Producer), Discovery Service  
**Assurance Level:** L2 (default), L3 for cryptographic subsystem

---

## V2 — Authentication

| Control | Description | Component | Our Mechanism | TASK |
|---------|-------------|-----------|---------------|------|
| V2.1.1 | User-set passwords must be ≥12 characters | Discovery (admin UI) | Admin credentials managed via Vault with min-length policy | TASK-008 |
| V2.6.1 | Lookup secrets are random, ≥112 bits | Enrollment tokens | 128-bit UUID v4 one-time tokens | TASK-005 |
| V2.6.2 | Lookup secrets invalidated after single use | Enrollment tokens | Token deleted from DB on first use | TASK-005 |
| V2.6.3 | Lookup secrets resistant to offline attack | Enrollment tokens | SHA-256 stored hash; raw token never logged | TASK-005 |
| V2.8.4 | Time-based OTP can be used only once per time window | JTI anti-replay | JTI in Redis with TTL=exp-iat (max 30s), SETNX | TASK-006 |
| V2.9.1 | Cryptographic keys used in multi-factor at least 128 bits | DID keys | Ed25519 = 256-bit key | TASK-003 |

---

## V3 — Session Management

| Control | Description | Component | Our Mechanism | TASK |
|---------|-------------|-----------|---------------|------|
| V3.3.1 | Logout invalidates server-side session token | Enrollment token | Token deleted from DB immediately on use | TASK-005 |
| V3.4.1 | Cookie-based sessions use SameSite=Strict | Discovery UI | Vite dev server config + production NGINX headers | TASK-009 |
| V3.5.2 | OAuth bearer tokens are short-lived | VC JWT | `exp` claim enforced; ≤ 24h lifetime | TASK-004 |
| V3.5.3 | Stateless tokens include signature that can be revoked | VC JWT | Bitstring Status List checked on each verification | TASK-007 |

---

## V5 — Validation, Sanitisation and Encoding

| Control | Description | Component | Our Mechanism | TASK |
|---------|-------------|-----------|---------------|------|
| V5.1.1 | HTTP request parameters validated before processing | All services | Pydantic v2 models at every API boundary | TASK-005 TASK-006 |
| V5.1.2 | Framework-level request validation prevents mass assignment | Discovery | Pydantic `model_config = ConfigDict(extra="forbid")` | TASK-004 |
| V5.2.1 | Untrusted HTML sanitised if reflected | Discovery UI | React DOM prevents XSS; no `dangerouslySetInnerHTML` | TASK-009 |
| V5.3.1 | Output encoding contextual | Discovery UI | React JSX escaping | TASK-009 |
| V5.4.1 | Typed language or type-checking used | All Python services | mypy strict mode; TypeScript 5 strict | TASK-009 |

---

## V7 — Cryptography

| Control | Description | Component | Our Mechanism | TASK |
|---------|-------------|-----------|---------------|------|
| V7.1.1 | No personally identifiable information in logs | All | Telemetry sanitises PII before OTLP export | TASK-001 |
| V7.2.1 | Cryptographic modules use FIPS-approved algorithms | All | Ed25519, P-256, SHA-256, AES-256-GCM, TLS 1.3 | TASK-003 |
| V7.2.2 | Random number generation uses secure PRNG | did_key.py, tokens | `cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate()` | TASK-003 |
| V7.3.1 | Encryption keys generated cryptographically randomly | Sentinel DID keys | `Ed25519PrivateKey.generate()` backed by OS CSPRNG | TASK-003 |
| V7.4.1 | Secret keys used only in permitted operations | Signing | Private key bytes never exported except Vault backup | TASK-008 |
| V7.6.1 | PBKDF has at least 100,000 iterations, uses HMAC-SHA-256 | Admin passwords | scrypt (N=2^15, r=8, p=1) via `cryptography` | TASK-008 |

---

## V9 — Communications

| Control | Description | Component | Our Mechanism | TASK |
|---------|-------------|-----------|---------------|------|
| V9.1.1 | TLS required for all client connections | All services | NGINX TLS 1.3 termination; mTLS for Sentinel↔Discovery (ADR-008) | TASK-008 |
| V9.1.2 | Latest TLS only; TLS 1.0/1.1 disabled | All services | `ssl_protocols TLSv1.3` in NGINX; TLS 1.2 only if no alternative | TASK-008 |
| V9.1.3 | Only strong cipher suites enabled | All services | `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` | TASK-008 |
| V9.2.1 | Backend connections use trusted certificates | Service mesh | Vault PKI issues internally-trusted certs | TASK-008 |
| V9.2.2 | Connections fail if certificate invalid | Sentinels | `httpx` with `verify=True`; no `ssl_verify=False` paths | TASK-005 |

---

## V10 — Malicious Code

| Control | Description | Component | Our Mechanism | TASK |
|---------|-------------|-----------|---------------|------|
| V10.3.2 | Application manifest permissions minimal | Sentinel Docker | Non-root user in Dockerfile; read-only filesystem | TASK-009 |
| V10.3.3 | Application does not write to filesystem unnecessarily | Sentinel | Vault for all secrets; Redis for state; no local file writes | TASK-008 |

---

## V14 — Configuration

| Control | Description | Component | Our Mechanism | TASK |
|---------|-------------|-----------|---------------|------|
| V14.1.1 | Server-side components run with minimal privilege | All services | Non-root containers; AppArmor/seccomp profiles in K8s | TASK-009 |
| V14.2.1 | All components up to date | Monorepo | Dependabot / Renovate automated PRs | TASK-009 |
| V14.2.2 | All unneeded features disabled | Discovery | Only required FastAPI routers mounted | TASK-005 |
| V14.3.1 | Web/application server config hardened | Discovery | NGINX security headers: `Strict-Transport-Security`, `X-Frame-Options DENY`, `Content-Security-Policy` | TASK-009 |
| V14.4.1 | HTTP headers do not expose implementation details | All services | `Server:` header removed; `X-Powered-By` suppressed | TASK-009 |
| V14.5.1 | Authoritative HTTP request router rejects unexpected verbs | Discovery | FastAPI route decorators; 405 on unknown verbs | TASK-005 |

---

## Gap Analysis

| Control | Status | Rationale |
|---------|--------|-----------|
| V2.1 (user passwords) | Partial | Admin UI out of scope for MVP; covered by Vault auth |
| V3.4 (cookie security) | Partial | Cookie usage minimal; primary auth is DID-based |
| V13 (API security) | Covered by V5 + V9 | OpenAPI schema validation at every endpoint |
| V11 (Business Logic) | Domain-specific | Covered by TASK-specific acceptance criteria |
| V12 (File upload) | N/A | No file upload functionality |

*Controls not listed above are either N/A for this system type or not yet verified against implementation.*
