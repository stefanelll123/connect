# Backup & Disaster Recovery

**RPO**: 6 hours (maximum acceptable data loss)  
**RTO**: 2 hours (maximum time to restore service)  
**Owner**: Platform team

---

## 1. Backup Schedule

| Component | Tool | Frequency | Retention | Location |
|-----------|------|-----------|-----------|----------|
| PostgreSQL | pg_dump | Every 6h | 30 days | S3 `s3://sentinel-backups/postgres/` |
| Vault | `vault operator raft snapshot` | Every 12h | 90 days | S3 `s3://sentinel-backups/vault/` |
| Chain event cache | pg_dump (subset) | Every 6h | 14 days | S3 `s3://sentinel-backups/chain-cache/` |
| Kubernetes secrets | `kubectl get secrets` + encrypt | Daily | 30 days | S3 `s3://sentinel-backups/k8s-secrets/` |

---

## 2. PostgreSQL Backup

### Automated (CronJob)

```yaml
# k8s/cronjob-pg-backup.yaml — runs every 6 hours
# backups are encrypted with AWS KMS before upload
```

### Manual backup trigger

```bash
# Run on-demand backup
kubectl create job --from=cronjob/pg-backup pg-backup-manual-$(date +%Y%m%d%H%M) \
  -n sentinel-prod

# Verify backup in S3
aws s3 ls s3://sentinel-backups/postgres/ --recursive | sort | tail -5
```

### Restore procedure

```bash
# 1. Identify backup to restore
BACKUP_KEY=$(aws s3 ls s3://sentinel-backups/postgres/ | sort | tail -1 | awk '{print $4}')

# 2. Download and decrypt
aws s3 cp "s3://sentinel-backups/postgres/${BACKUP_KEY}" /tmp/sentinel.sql.enc
aws kms decrypt --ciphertext-blob fileb:///tmp/sentinel.sql.enc \
  --output text --query Plaintext | base64 -d > /tmp/sentinel.sql

# 3. Scale down discovery (prevent writes during restore)
kubectl scale deployment/discovery -n sentinel-prod --replicas=0

# 4. Restore
kubectl exec -n sentinel-prod deploy/postgres -- \
  psql -U sentinel sentinel < /tmp/sentinel.sql

# 5. Validate row counts
kubectl exec -n sentinel-prod deploy/postgres -- \
  psql -U sentinel sentinel -c "SELECT relname, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC;"

# 6. Restart discovery
kubectl scale deployment/discovery -n sentinel-prod --replicas=3
```

---

## 3. Vault Backup

```bash
# Manual snapshot
vault operator raft snapshot save vault-snapshot-$(date +%Y%m%d%H%M).snap

# Upload to S3
aws s3 cp vault-snapshot-*.snap s3://sentinel-backups/vault/ \
  --sse aws:kms --sse-kms-key-id ${KMS_KEY_ID}
```

### Vault Restore

> **Break-glass required** — see [break-glass-access.md](break-glass-access.md)

```bash
# 1. Stop Vault
kubectl scale statefulset/vault -n vault --replicas=0

# 2. Restore snapshot
vault operator raft snapshot restore vault-snapshot-YYYYMMDDHHMM.snap

# 3. Start Vault
kubectl scale statefulset/vault -n vault --replicas=3

# 4. Unseal (if auto-unseal not configured)
vault operator unseal
```

---

## 4. Full DR Scenario Playbook

**Scenario**: Complete cluster loss (AZ failure)

| Step | Action | Owner | Time Budget |
|------|--------|-------|-------------|
| 1 | Provision replacement cluster from IaC | Platform | 30 min |
| 2 | Restore Vault from latest snapshot | Security | 20 min |
| 3 | Restore PostgreSQL from latest backup | Platform | 20 min |
| 4 | Deploy Helm charts (discovery + sentinel) | Platform | 15 min |
| 5 | Verify smoke tests pass | Platform | 10 min |
| 6 | Update DNS / load balancer | Platform | 5 min |
| **Total** | | | **~100 min ≤ 2h RTO** |

---

## 5. Recovery Verification

After any restore, run the full smoke test suite:

```bash
SMOKE_BASE_URL=https://discovery.internal bash tests/smoke/smoke_test.sh
```

Expected output: all 5 checks PASS.
