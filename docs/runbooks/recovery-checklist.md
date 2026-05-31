# Post-Incident Recovery Checklist

Use this checklist after any P1 or P2 incident before declaring the incident resolved and closing the PagerDuty ticket.

---

## Pre-Recovery (During Incident)

- [ ] PagerDuty incident created with correct severity
- [ ] Incident commander assigned
- [ ] Communication channel opened (`#incident-YYYYMMDD` in Slack)
- [ ] Break-glass access documented (if used)

---

## Recovery Verification Checklist

### 1. Service Health
- [ ] `curl https://discovery.internal/health/ready` returns `HTTP 200`
- [ ] `curl https://sentinel.internal/health` returns `HTTP 200`
- [ ] All Kubernetes pods in `sentinel-prod` namespace are `Running` / `Ready`
  ```bash
  kubectl get pods -n sentinel-prod -o wide
  ```

### 2. Data Integrity
- [ ] PostgreSQL row counts match pre-incident snapshot (within expected delta)
  ```bash
  kubectl exec -n sentinel-prod deploy/postgres -- \
    psql -U sentinel sentinel -c "SELECT relname, n_live_tup FROM pg_stat_user_tables;"
  ```
- [ ] Audit log hash chain passes tamper detection
  ```bash
  curl -s https://discovery.internal/api/v1/audit/tamper-check \
    -H "Authorization: Bearer ${ADMIN_JWT}"
  # Expected: {"status":"ok"}
  ```
- [ ] No unexpected credential revocations in audit log

### 3. Chain State
- [ ] Indexer lag < 10 blocks (warning threshold)
  ```bash
  curl -s https://discovery.internal/metrics | grep sentinel_chain_indexer_lag_blocks
  ```
- [ ] Chain RPC responding within SLO (< 500ms)

### 4. Security
- [ ] All compromised credentials revoked and propagated
- [ ] Affected keys rotated
- [ ] Emergency NetworkPolicies removed (if applied)
  ```bash
  kubectl get networkpolicy -n sentinel-prod | grep emergency
  ```
- [ ] Break-glass token rotated (if used)

### 5. Monitoring
- [ ] No active Prometheus alerts firing
  ```bash
  curl -s https://alertmanager.internal/api/v2/alerts | jq 'length'
  ```
- [ ] Grafana dashboards show normal baseline metrics

### 6. Smoke Tests
- [ ] All 5 smoke tests pass
  ```bash
  SMOKE_BASE_URL=https://discovery.internal bash tests/smoke/smoke_test.sh
  ```

---

## Post-Recovery Actions (Within 24h)

- [ ] Close PagerDuty incident with resolution summary
- [ ] Notify affected parties of recovery
- [ ] Schedule postmortem meeting (< 5 business days)
- [ ] File postmortem document: `docs/postmortems/YYYY-MM-DD-<title>.md`
- [ ] Capture action items with owners and due dates
- [ ] Update runbook if gaps identified during incident

---

## Sign-off

| Role | Name | Time |
|------|------|------|
| Incident Commander | | |
| Security Reviewer | | |
| Platform Lead | | |
