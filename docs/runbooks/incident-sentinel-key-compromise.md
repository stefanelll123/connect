# Incident Runbook — Sentinel Key Compromise

**Severity**: P1 — Critical  
**Response SLO**: 15 minutes to initial containment  
**Owner**: Security team + Platform on-call

---

## 1. Detection Signals

- PagerDuty alert: `IssuerDisabledOnChain` (if key used to issue credentials)
- Unusual signing activity in audit logs (`action: sentinel.signed` spike)
- Threat intel report of private key in public repository / paste site
- Unauthorised access alert from SIEM

---

## 2. Immediate Containment (< 5 min)

### 2a. Identify the compromised key

```bash
# List active signing keys
kubectl exec -n sentinel-prod deploy/sentinel-node -- \
  sentinel keys list --format json

# Check Vault for key metadata
vault kv get secret/sentinel/signing-key
```

### 2b. Rotate the signing key

> **Two-person rule** — requires approval from a second on-call engineer.

```bash
# Generate new key in Vault
vault write -f transit/keys/sentinel-signing-key/rotate

# Trigger sentinel key reload
kubectl rollout restart deployment/sentinel-node -n sentinel-prod
kubectl rollout status deployment/sentinel-node -n sentinel-prod --timeout=5m
```

### 2c. Disable on-chain if issuer key is compromised

```bash
# Via Discovery admin API
curl -s -X POST https://discovery.internal/api/v1/admin/issuers/${ISSUER_DID}/disable \
  -H "Authorization: Bearer ${ADMIN_JWT}" \
  -H "Content-Type: application/json" \
  -d '{"reason":"key_compromise_p1"}'
```

---

## 3. Revoke All Active Credentials Issued with Compromised Key

```bash
# List affected credentials
curl -s "https://discovery.internal/api/v1/admin/credentials?issuer_key_id=${KEY_ID}" \
  -H "Authorization: Bearer ${ADMIN_JWT}" | jq '.[].id'

# Bulk revoke
for CRED_ID in $(cat affected_creds.txt); do
  curl -s -X POST "https://discovery.internal/api/v1/credentials/${CRED_ID}/revoke" \
    -H "Authorization: Bearer ${ADMIN_JWT}" \
    -d '{"reason":"key_compromise"}'
done
```

Verify revocation propagated to sentinel (time-to-deny ≤ 30s):
```bash
# Watch sentinel metrics for DENY rate increase
kubectl exec -n sentinel-prod deploy/sentinel-node -- \
  curl -s http://localhost:9090/metrics | grep sentinel_deny_total
```

---

## 4. Evidence Collection

```bash
# Export audit log segment for the incident window
curl -s "https://discovery.internal/api/v1/audit/export" \
  -H "Authorization: Bearer ${ADMIN_JWT}" \
  -G --data-urlencode "from_ts=${INCIDENT_START}" \
  --data-urlencode "to_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o incident-audit-$(date +%Y%m%d).jsonl

# Capture Vault audit logs
vault audit list
```

---

## 5. Re-key and Re-issue

1. Generate new signing key: `vault write -f transit/keys/sentinel-signing-key`
2. Update Kubernetes Secret or Vault path: `kubectl create secret generic sentinel-signing-key --from-literal=...`
3. Restart affected sentinels: `kubectl rollout restart deployment/sentinel-node -n sentinel-prod`
4. Re-issue credentials for affected services:
   ```bash
   for SVC_ID in $(cat affected_services.txt); do
     curl -s -X POST "https://discovery.internal/api/v1/credentials/issue" \
       -H "Authorization: Bearer ${ADMIN_JWT}" \
       -d "{\"subject_id\":\"${SVC_ID}\",\"credential_type\":\"ServiceAccessCredential\"}"
   done
   ```

---

## 6. Post-Incident

- [ ] Root cause analysis in `postmortem/YYYY-MM-DD-sentinel-key-compromise.md`
- [ ] Update key rotation schedule (reduce from 90d → 30d)
- [ ] Review Vault access policies
- [ ] Notify affected service operators within 72h (regulatory requirement)
- [ ] Update threat model if new compromise vector identified
