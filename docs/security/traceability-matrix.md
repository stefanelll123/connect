# Security Traceability Matrix

**Document version:** 1.0  
**Purpose:** Link each identified threat to the implementation task that mitigates it and the test(s) that verify it.

---

## Matrix

| Threat ID | Description | STRIDE | Mitigated by Task(s) | Test ID(s) | SI Reference |
|-----------|-------------|--------|----------------------|-----------|--------------|
| T-001 | ProofClaims JWS replay within exp window | Repudiation | TASK-006 (ProofClaims spec + JTI Redis dedup) | TEST-INT-001 | SI-003 |
| T-002 | Rogue Sentinel registration with stolen enrollment token | Spoofing | TASK-005 (Onboarding protocol + one-time tokens) | TEST-INT-002 | SI-002 SI-008 |
| T-003 | Cross-environment VC replay (dev VC in prod) | Elevation | TASK-003 (env claim) + TASK-004 (VC schema env field) | TEST-UNIT-003 | SI-007 |
| T-004 | Stale status list acceptance after revocation | Info Disclosure | TASK-007 (Bitstring Status List) + outage-policy.md | TEST-INT-004 | SI-004 |
| T-005 | Enrollment token theft during transmission | Spoofing | TASK-005 (mTLS onboarding channel) | TEST-INT-005 | SI-008 |
| T-006 | Issuer key compromise enabling mass VC forgery | Elevation | TASK-003 (IssuerRegistry.disableIssuer) + TASK-015 | TEST-E2E-006 | SI-005 |
| T-007 | Consumer Sentinel DID key theft from memory or Vault | Spoofing | TASK-008 (Vault integration, no plaintext disk writes) | AUDIT-001 | SI-009 |
| T-008 | Discovery compromise enabling endpoint injection via config | Tampering | TASK-008 (Config bundle JWS verification) | TEST-UNIT-008 | SI-012 |
| T-009 | Blockchain reorg reverting issuer-disable transaction | Denial of Service | TASK-015 (12-block confirmation requirement) | TEST-INT-009 | SI-005 |
| T-010 | Config bundle tampering in transit | Tampering | TASK-008 (JWS signature verification on config bundle) | TEST-UNIT-010 | SI-012 |
| T-011 | JWT alg:none attack bypassing signature verification | Tampering | TASK-003 (PROHIBITED_ALGS + assert_algorithm_allowed) | TEST-UNIT-006 | SI-006 |
| T-012 | Status list bitstring substitution in cache | Tampering | TASK-007 (SHA-256 hash vs on-chain anchor) | TEST-UNIT-013 | SI-013 |
| T-013 | Redis replay cache unavailable (JTI double-spend) | Denial of Service | TASK-006 (Redis HA + reject on Redis error) | TEST-INT-013 | SI-003 |

---

## Task Coverage Summary

| Task | Threats Mitigated | Implementation Artefacts |
|------|-------------------|--------------------------|
| TASK-003 | T-003, T-006, T-011 | `libs/common/src/common/crypto/` |
| TASK-004 | T-003 | `libs/common/src/common/vc_schemas/` |
| TASK-005 | T-002, T-005 | `libs/common/src/common/onboarding/` |
| TASK-006 | T-001, T-013 | `libs/common/src/common/proof/` |
| TASK-007 | T-004, T-012 | `libs/common/src/common/revocation/` |
| TASK-008 | T-007, T-008, T-010 | `libs/common/src/common/secret_storage/` |
| TASK-015 | T-006, T-009 | `contracts/contracts/IssuerRegistry.sol` |

---

## Test Coverage Summary

| Test ID | Type | Threat(s) Covered | Status |
|---------|------|-------------------|--------|
| TEST-UNIT-003 | Unit | T-003 | Planned — TASK-004 |
| TEST-UNIT-006 | Unit | T-011 | ✅ Implemented — `test_jws.py::TestVerifyJwsProhibitedAlgorithms` |
| TEST-UNIT-008 | Unit | T-008 | Planned — TASK-008 |
| TEST-UNIT-010 | Unit | T-010 | Planned — TASK-008 |
| TEST-UNIT-013 | Unit | T-012 | Planned — TASK-007 |
| TEST-INT-001 | Integration | T-001 | Planned — TASK-006 |
| TEST-INT-002 | Integration | T-002 | Planned — TASK-005 |
| TEST-INT-004 | Integration | T-004 | Planned — TASK-007 |
| TEST-INT-005 | Integration | T-005 | Planned — TASK-005 |
| TEST-INT-009 | Integration | T-009 | Planned — TASK-015 |
| TEST-INT-013 | Integration | T-013 | Planned — TASK-006 |
| TEST-E2E-006 | E2E | T-006 | Planned — TASK-015 |
| AUDIT-001 | Vault audit log | T-007 | Planned — TASK-008 |

---

## Security Invariant Cross-Reference

| Invariant | Statement summary | Threats Enforcing | Verified by |
|-----------|-------------------|-------------------|-------------|
| SI-002 | Every Sentinel must authenticate with a unique DID before calling any Discovery API | T-002 | TEST-INT-002 |
| SI-003 | JTI must be unique within exp window; duplicate JTI rejected with 401 | T-001, T-013 | TEST-INT-001, TEST-INT-013 |
| SI-004 | Stale status cache beyond Δ triggers FAIL_CLOSED in prod | T-004 | TEST-INT-004 |
| SI-005 | Discovery rejects VCs from disabled issuers on every request | T-006, T-009 | TEST-E2E-006, TEST-INT-009 |
| SI-006 | PROHIBITED_ALGS checked before any crypto operation | T-011 | TEST-UNIT-006 |
| SI-007 | env claim in VC must match the receiving Sentinel's env | T-003 | TEST-UNIT-003 |
| SI-008 | Enrollment tokens one-time use; deleted on first use | T-002, T-005 | TEST-INT-002, TEST-INT-005 |
| SI-009 | Private keys never written to disk in plaintext | T-007 | AUDIT-001 |
| SI-012 | Config bundles verified by JWS signature before application | T-008, T-010 | TEST-UNIT-008, TEST-UNIT-010 |
| SI-013 | Status list hash verified against on-chain anchor before use | T-012 | TEST-UNIT-013 |
