# Incident Runbook — Credential Data Leakage

**Severity**: P1 — Critical  
**Response SLO**: 15 min  
**Owner**: Security + DPO

---

## 1. Detection Signals

- Unusual export volumes in audit logs (`action: audit.export` with large `events_count`)
- Credential data seen in external breach databases
- User report of credential reuse from an unexpected origin
- `sentinel_replay_rejections_total` spike (someone replaying leaked credentials)

---

## 2. Immediate Response

### Step 1 — Identify leaked credentials

```bash
# Pull audit export events to see who exported what
curl -s "https://discovery.internal/api/v1/audit" \
  -H "Authorization: Bearer ${ADMIN_JWT}" \
  -G --data-urlencode "action=audit.export" \
  --data-urlencode "from_ts=${INCIDENT_WINDOW_START}" | jq '.events'

# Check replay rejection spike for the suspected credential
kubectl logs -n sentinel-prod -l app=sentinel-node \
  --since=1h | grep PROOF_ALREADY_SEEN | jq '.credential_id' | sort | uniq -c | sort -rn | head
```

### Step 2 — Revoke leaked credentials

```bash
# Revoke by credential IDs from investigation
for CRED_ID in $(cat leaked_credentials.txt); do
  curl -s -X POST "https://discovery.internal/api/v1/credentials/${CRED_ID}/revoke" \
    -H "Authorization: Bearer ${ADMIN_JWT}" \
    -d '{"reason":"data_leakage_p1"}'
  echo "Revoked ${CRED_ID}"
done

# Wait for revocation to propagate to sentinel (≤ delta)
sleep 15
```

### Step 3 — Verify sentinel is blocking revoked credentials

```bash
# Check the deny rate is rising in Grafana
# Dashboard: Sentinel — Security Incidents → Replay Rejections Over Time
```

---

## 3. Scope Assessment

Questions to answer:
1. How many credentials were exposed?
2. Which service operators are affected?
3. Were JWTs or raw DID documents exposed?
4. Is there any evidence of active exploitation (replay attempts)?

```bash
# Count replay attempts per leaked credential
kubectl logs -n sentinel-prod -l app=sentinel-node --since=2h \
  | grep '"event":"replay_rejected"' | jq -r '.credential_id' \
  | sort | uniq -c | sort -rn
```

---

## 4. Notification Obligations

| Recipient | Timeline | Content |
|-----------|----------|---------|
| Internal security | Immediate | Full incident brief |
| DPO | < 1 h | Data categories and volume |
| Affected service operators | < 24 h | What was exposed, actions taken |
| Regulatory body (if PII) | ≤ 72 h | GDPR Art. 33 breach notification |

---

## 5. Post-Incident Checklist

- [ ] Confirm all leaked credentials revoked and propagated
- [ ] Add anomalous export volume alert rule to Prometheus
- [ ] Review audit export access controls (should require MFA)
- [ ] Postmortem with timeline and remediation plan
- [ ] Enable credential access rate-limiting if not already active
