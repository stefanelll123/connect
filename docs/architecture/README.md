# Architecture Documentation — Index

This directory contains all formal architecture documentation for the
**Sentinel Identity Platform**.

---

## Documents

| Document | Description |
|---|---|
| [reference-architecture.md](reference-architecture.md) | End-to-end reference architecture (components, trust boundaries, data flows, security invariants) |
| [security-invariants.md](security-invariants.md) | Numbered, testable security invariants (SI-001 to SI-015) |

## Architecture Decision Records (ADRs)

| ADR | Title | Status |
|---|---|---|
| [ADR-001](adrs/ADR-001-did-method.md) | DID Method Selection | ACCEPTED |
| [ADR-002](adrs/ADR-002-vc-encoding.md) | VC Encoding Format (JWT-VC vs JSON-LD) | ACCEPTED |
| [ADR-003](adrs/ADR-003-revocation-mechanism.md) | Revocation Mechanism — Bitstring Status List | ACCEPTED |
| [ADR-004](adrs/ADR-004-anti-replay.md) | Request Anti-Replay Strategy | ACCEPTED |
| [ADR-005](adrs/ADR-005-blockchain-network.md) | Blockchain Network Selection | ACCEPTED |
| [ADR-006](adrs/ADR-006-secret-storage.md) | Secret Storage Architecture | ACCEPTED |
| [ADR-007](adrs/ADR-007-environment-isolation.md) | Environment Isolation Model | ACCEPTED |
| [ADR-008](adrs/ADR-008-transport-baseline.md) | Transport Baseline | ACCEPTED |

## Diagrams

Located in [diagrams/](diagrams/).

| Diagram | Format | Description |
|---|---|---|
| `c4-context.puml` | PlantUML | C4 Level 1 — System Context |
| `c4-container.puml` | PlantUML | C4 Level 2 — Containers |
| `c4-component-discovery.puml` | PlantUML | C4 Level 3 — Discovery Service Components |
| `c4-component-sentinel.puml` | PlantUML | C4 Level 3 — Sentinel Components |
| `seq-service-registration.puml` | PlantUML | Sequence — Service Registration |
| `seq-sentinel-onboarding.puml` | PlantUML | Sequence — Sentinel Onboarding |
| `seq-vc-issuance.puml` | PlantUML | Sequence — VC Issuance |
| `seq-request-execution.puml` | PlantUML | Sequence — Consumer→Producer Request |
| `seq-revocation.puml` | PlantUML | Sequence — Credential Revocation |
| `seq-key-rotation.puml` | PlantUML | Sequence — Key/Credential Rotation |
| `seq-vm-migration.puml` | PlantUML | Sequence — VM Migration |
| `seq-multi-instance.puml` | PlantUML | Sequence — Multi-Instance Sentinel Join |

## Related Standards

See [../standards/](../standards/) for the algorithm matrix, VC validation
procedure, and media type registry.

## Related Security

See [../security/](../security/) for the threat model, ASVS mapping, and
outage policy.
