# Incident Runbook — Issuer Compromise

**Severity**: P1 — Critical  
**Response SLO**: 15 min initial containment, ≤ 30 s on-chain disable propagation  
**Owner**: Security team + Platform on-call

---

## 1. Detection Signals

- Threat intelligence: issuer private key found in leak
- Anomalous issuance spike: `discovery_credential_issued_total` rate > baseline × 5
- PagerDuty: `IssuerDisabledOnChain` (self-reported by Discovery after automated detection)
- SIEM alert: new DID registration from unexpected IP

---

## 2. Immediate Containment

### Step 1 — Disable issuer on-chain (< 5 min)

```bash
# Get issuer DID from incident report or audit logs
ISSUER_DID="did:example:compromised-issuer"

# Disable via Discovery admin API (triggers IssuerRegistry.disableIssuer smart contract call)
curl -s -X POST "https://discovery.internal/api/v1/admin/issuers/${ISSUER_DID}/disable" \
  -H "Authorization: Bearer ${ADMIN_JWT}" \
  -H "Content-Type: application/json" \
  -d '{"reason":"issuer_compromise_p1","notify_affected_services":true}'
```

Verify on-chain:
```bash
# Check chain events in Discovery
curl -s "https://discovery.internal/api/v1/chain/events?event_type=IssuerRevoked&limit=5" \
  -H "Authorization: Bearer ${ADMIN_JWT}" | jq '.events[0]'
```

### Step 2 — Verify sentinel containment

Within 30 seconds of the on-chain transaction:
```bash
# Poll sentinel decision for a credential from the compromised issuer
SENTINEL_URL="http://sentinel-producer.sentinel-prod.svc:8080"
while true; do
  RESP=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Sentinel-VC: ${COMPROMISED_VC}" \
    -H "X-Nonce: $(uuidgen)" \
    -H "X-Timestamp: $(date +%s)" \
    "${SENTINEL_URL}/api/v1/request" -d '{}')
  echo "$(date -u +%T) HTTP $RESP"
  [[ "$RESP" == "403" ]] && echo "✓ Sentinel is now denying" && break
  sleep 1
done
```

---

## 3. Scope Assessment

```bash
# Find all credentials issued by the compromised issuer
curl -s "https://discovery.internal/api/v1/admin/credentials?issuer_did=${ISSUER_DID}&status=active" \
  -H "Authorization: Bearer ${ADMIN_JWT}" | jq 'length'

# Find all services that were issued credentials by this issuer
curl -s "https://discovery.internal/api/v1/admin/credentials?issuer_did=${ISSUER_DID}" \
  -H "Authorization: Bearer ${ADMIN_JWT}" | jq -r '.[].subject_id' | sort -u
```

---

## 4. Re-enroll Affected Services

Once the compromised issuer is fully disabled and a new trusted issuer is provisioned:

```bash
# Re-enroll each affected service
for SVC_ID in $(cat affected_services.txt); do
  curl -s -X POST "https://discovery.internal/api/v1/admin/services/${SVC_ID}/re-enroll" \
    -H "Authorization: Bearer ${ADMIN_JWT}" \
    -d '{"new_issuer_did":"did:example:new-trusted-issuer"}'
done
```

---

## 5. Post-Incident Checklist

- [ ] Document how key was compromised (HSM? env leak? git? CI secret?)
- [ ] Revoke any related API keys or OAuth tokens
- [ ] Review issuer key storage policy
- [ ] Postmortem filed within 5 business days
- [ ] Notify all affected service operators (regulatory 72h window)
- [ ] Update `sentinel_trust_cache_ttl` if propagation was slower than expected
