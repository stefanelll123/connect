# ADR-007 — Environment Isolation Model

**Status:** ACCEPTED  
**Date:** 2025-01-01  
**Deciders:** Platform Architecture Working Group

---

## Context

The platform operates across three environments: `dev`, `test`, and `prod`.
Services and Sentinels must be deployed in multiple environments without
the risk of credentials or trust material from one environment being accepted
in another.

Attack surface: a malicious actor could use a `dev`-environment credential
(which is easier to obtain, with weaker controls) to access a `prod` service.

Requirements:
1. **Strict credential isolation** — a credential valid in `dev` MUST be
   cryptographically unacceptable in `prod`.
2. **Separate key material per environment** — Sentinel `dev` keys must be
   completely different from `prod` keys.
3. **Separate on-chain state per environment** — the issuer registry in `dev`
   must not affect `prod`.
4. **Developer ergonomics** — `dev` must be easy to set up locally without
   external dependencies.

---

## Decision

**Each environment is cryptographically isolated by using a separate DID
(i.e., a separate Ed25519 key pair) per Sentinel per environment.**

- A `prod` Sentinel has `did:key:z6Mk<PROD_KEY>`.
- A `test` Sentinel has `did:key:z6Mk<TEST_KEY>`.
- A `dev` Sentinel has `did:key:z6Mk<DEV_KEY>`.

These are entirely different identities with no cryptographic relationship.

### `env` Claim Enforcement

Every issued credential carries `env: <value>` in `vc.credentialSubject.env`.
Every ProofClaims JWT carries `env: <value>`.
Producer Sentinels check that `env` matches exactly the current running
environment (`ENV` config variable).

### Separate Blockchain State

Smart contracts are deployed separately per environment:
- Local (`dev`): Hardhat local chain (chainId 31337)
- Integration (`test`): Sepolia testnet (chainId 11155111)
- Production: permissioned chain (chain ID TBD)

Contract addresses are stored per-environment in config.

### Separate Vault Paths

Vault KV paths are namespaced by environment:
```
secret/sentinel/prod/<service_id>/private_key
secret/sentinel/test/<service_id>/private_key
secret/sentinel/dev/<service_id>/private_key
```

---

## Consequences

### Positive

- **Cryptographic barrier** — using a different key per environment means
  a `dev` token cannot be used to impersonate a `prod` Sentinel.
- **`env` claim double-check** — even if an attacker somehow obtained a valid
  `dev` VC signature and replayed it at a `prod` verifier, the `env: dev`
  claim would cause immediate rejection.
- **Independent key rotation** — a `dev` key compromise does not require
  rotating `prod` keys.

### Negative

- **3× key management overhead** — each Sentinel service has 3 key pairs
  (one per env).  Mitigated by automated Vault provisioning via Terraform.
- **3× on-chain registrations** — each Sentinel must be registered in the
  appropriate environment's smart contract.

---

## Rejected Alternatives

### Single DID for all environments, `env` claim only

If the private key is shared across environments, a `dev` key compromise
immediately compromises `prod` identity.  The `env` claim alone is insufficient
as a barrier because the attacker controls the claim in a compromised issuer
scenario.

### Environment encoded as a DID namespace (`did:key:env:prod:z6Mk...`)

Not a valid DID format.  Custom DID methods add tooling complexity.  The
`env` claim in the credential payload alongside separate keys provides the
same isolation without a non-standard DID.

---

## References

- SI-007 in `security-invariants.md` — cross-environment credentials are rejected
- T-003 in `docs/security/threat-model.md` — cross-env VC replay threat
