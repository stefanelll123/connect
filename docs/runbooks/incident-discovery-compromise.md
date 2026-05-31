# Incident Runbook — Discovery Service Compromise

**Severity**: P1 — Critical  
**Response SLO**: 15 min  
**Owner**: Security team + Platform on-call

---

## 1. Detection Signals

- Unexpected admin API calls in audit logs (unknown actor_did)
- Vault alert: unexpected secret read from discovery namespace
- SIEM: lateral movement or privilege escalation in `sentinel-prod` namespace
- Discovery pod crash loop with OOM (potential exploit payload)
- New admin account creation via `/api/v1/admin/users`

---

## 2. Immediate Containment (< 5 min)

### Step 1 — Isolate the discovery service

```bash
# Apply emergency NetworkPolicy — block all ingress except monitoring
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-isolate-discovery
  namespace: sentinel-prod
spec:
  podSelector:
    matchLabels:
      app: discovery
  policyTypes: [Ingress, Egress]
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
EOF
```

### Step 2 — Rotate Discovery service credentials

```bash
# Rotate DB password
kubectl exec -n sentinel-prod deploy/postgres -- \
  psql -U postgres -c "ALTER USER sentinel PASSWORD '$(openssl rand -base64 32)';"

# Rotate Vault token for discovery
vault token revoke -accessor $(vault token lookup -format json | jq -r '.data.accessor')
vault token create -policy=discovery -ttl=1h
kubectl patch secret discovery-vault-token -n sentinel-prod \
  --patch "{\"data\":{\"token\":\"$(vault token create -format json | jq -r '.auth.client_token | @base64)\"}}"

# Force pod restart to pick up new creds
kubectl rollout restart deployment/discovery -n sentinel-prod
```

### Step 3 — Revoke all active admin JWTs

```bash
# Rotate JWT secret — invalidates ALL existing tokens
vault kv put secret/discovery/jwt-secret value=$(openssl rand -base64 64)
kubectl rollout restart deployment/discovery -n sentinel-prod
```

---

## 3. Forensics

```bash
# Capture discovery pod logs before restart for evidence
kubectl logs -n sentinel-prod -l app=discovery --previous > forensics-discovery-$(date +%Y%m%d%H%M).log

# Export full audit log
curl -s "https://discovery.internal/api/v1/audit/export" \
  -H "Authorization: Bearer ${BREAK_GLASS_JWT}" \
  --data-urlencode "from_ts=${INCIDENT_START}" \
  -o forensics-audit-$(date +%Y%m%d).jsonl

# Check for unexpected secret reads in Vault
vault audit list
kubectl logs -n vault vault-0 | grep '"path":"secret/data/discovery"' | tail -200
```

---

## 4. Recovery

1. Restore from last known-good backup (see [backup-dr.md](backup-dr.md))
2. Re-deploy Discovery from a verified container image:
   ```bash
   # Verify image signature before deploying
   cosign verify \
     --certificate-identity-regexp="https://github.com/ORG/REPO/.github/workflows/cd-build.yml" \
     --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
     ghcr.io/ORG/REPO/discovery:${KNOWN_GOOD_TAG}
   
   helm upgrade sentinel-discovery infra/helm/discovery \
     --namespace sentinel-prod \
     --set image.tag=${KNOWN_GOOD_TAG} \
     --atomic
   ```
3. Remove emergency isolation NetworkPolicy after recovery is verified:
   ```bash
   kubectl delete networkpolicy emergency-isolate-discovery -n sentinel-prod
   ```

---

## 5. Post-Incident Checklist

- [ ] All attacker-created accounts removed
- [ ] All JWTs rotated
- [ ] DB password rotated
- [ ] Vault policies audited — remove excess permissions
- [ ] Container image provenance verified
- [ ] Security postmortem filed
- [ ] Consider WAF deployment in front of Discovery
