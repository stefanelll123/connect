# Runbooks Index

This directory contains operational runbooks for the Sentinel / Discovery platform.

## Severity Guide

| Level | Response SLO | Definition |
|-------|-------------|------------|
| **P1 — Critical** | 15 min | Service outage, active exploit, key compromise |
| **P2 — High** | 1 h | Degraded service, chain indexer stuck, revocation staleness |
| **P3 — Medium** | 4 h | Single component failure, elevated error rate |
| **P4 — Low** | 24 h | Non-critical anomaly, metric drift |

## Runbook Catalogue

| File | Scenario | Severity |
|------|----------|----------|
| [incident-sentinel-key-compromise.md](incident-sentinel-key-compromise.md) | Sentinel private key or signing key leaked | P1 |
| [incident-issuer-compromise.md](incident-issuer-compromise.md) | Issuer DID or credential issuance key compromised | P1 |
| [incident-credential-leakage.md](incident-credential-leakage.md) | Credential data exposure or unauthorised access | P1 |
| [incident-discovery-compromise.md](incident-discovery-compromise.md) | Discovery service intrusion or data breach | P1 |
| [incident-chain-outage.md](incident-chain-outage.md) | Chain RPC unreachable or indexer stuck | P2 |
| [backup-dr.md](backup-dr.md) | Backup schedule, DR procedures (RPO 6h, RTO 2h) | — |
| [break-glass-access.md](break-glass-access.md) | Emergency Vault access, 2-person rule | — |
| [recovery-checklist.md](recovery-checklist.md) | Post-incident recovery and verification | — |

## Quick Reference

```
# Check all service health
curl https://discovery.internal/health/ready
curl https://sentinel.internal/health

# Stream recent errors
kubectl logs -n sentinel-prod -l app=discovery --tail=100 -f | grep '"level":"error"'

# PagerDuty escalation
p1_lead: @oncall-security
p2_lead: @oncall-platform
```
