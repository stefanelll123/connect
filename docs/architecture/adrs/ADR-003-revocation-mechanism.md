# ADR-003 — Revocation Mechanism: Bitstring Status List

**Status:** ACCEPTED  
**Date:** 2025-01-01  
**Deciders:** Platform Architecture Working Group

---

## Context

Once a credential is issued, the system must be able to revoke it — for
example, when a service is deregistered, its access rights change, or
a security incident is detected.

Requirements for the revocation mechanism:
1. **Verifiers can check status without contacting the issuer** — the
   Producer Sentinel may be offline from Discovery.
2. **Privacy-preserving** — checking if a single credential is revoked
   should not reveal which credentials are still valid.
3. **Scalable** — must support thousands of concurrent credentials per
   Discovery deployment.
4. **On-chain verifiable** — the Sentinel must be able to verify that
   the status list was not tampered with.

---

## Decision

**Adopt W3C Bitstring Status List v1.0** as the revocation mechanism.

### Mechanism

1. Discovery maintains a `BitstringStatusListCredential` — a JWT-VC whose
   payload contains a gzip-compressed, base64url-encoded bitstring.
2. Each issued credential includes a `credentialStatus` claim pointing to:
   - The URL of the `statusListCredential`
   - A `statusListIndex` integer (the bit position)
   - `statusPurpose: revocation`
3. To revoke credential at index N, Discovery sets bit N to `1`.
4. The updated bitstring's SHA-256 hash is anchored in the `StatusListAnchor`
   smart contract.
5. Verifiers (Producer Sentinels) download the status list, verify the JWS
   signature on the `BitstringStatusListCredential`, compare the bitstring hash
   against the on-chain anchor, then check the bit at `statusListIndex`.

### Freshness (Δ)

Verifiers cache the status list.  The maximum age is Δ (fetched from
`TrustPolicyRegistry` on-chain or from the signed config bundle).  If the
cached list is older than Δ, the verifier must refresh before making a decision.
If it cannot refresh, it MUST fail closed (reject the request).

---

## Consequences

### Positive

- **W3C standard** — implemented in the VC ecosystem (e.g., Veramo, SpruceID).
- **Privacy-preserving** — verifier downloads the list for the whole batch;
  the issuer cannot track individual credential checks.
- **Compact** — a bitstring of 131,072 entries fits in 16 KiB (before gzip).
- **On-chain verifiability** — SHA-256 hash anchor prevents tampering.
- **Offline-capable** — verifier needs only the cached list and the on-chain hash.

### Negative

- **Correlation risk for very small lists** — if a status list has very few
  entries, membership in the list itself could be identifying.  Mitigated by
  always padding to at least 1 000 entries.
- **Discovery must be available for revocation to take effect** — the
  Producer Sentinel does not learn about revocation until it refreshes.
  This is bounded by Δ.
- **Handling suspension** — `statusPurpose: suspension` is in-spec but adds
  logic;  MVP supports `revocation` only.

---

## Rejected Alternatives

### DID-based status (DID Document update)

Requires a live DID resolver for every verification.  Does not work in
offline/degraded mode.

### Simple revocation list (centralized endpoint)

Requires Sentinel to contact Discovery on every request — violates the
offline-enforcement requirement and creates a single point of failure.

### OCSP (Online Certificate Status Protocol)

Designed for X.509 PKI, not VCs.  Always online; no on-chain anchoring.
Privacy-disclosing (issuer sees every verification request).

### Revocation Registry (smart contract list)

Reading from chain on every request is too slow (block time ≥ 1 s) and
too expensive in gas.  The bitstring-on-IPFS + hash-on-chain approach
provides the same integrity at a fraction of the cost.

---

## References

- W3C Bitstring Status List v1.0 — https://www.w3.org/TR/vc-bitstring-status-list/
- Privacy analysis — https://www.w3.org/TR/vc-bitstring-status-list/#privacy-considerations
