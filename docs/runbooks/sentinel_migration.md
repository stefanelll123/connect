# Sentinel Migration Runbook

**Version:** 1.0  
**Component:** Sentinel Node  
**Last Updated:** 2024

---

## Overview

This runbook covers all sentinel lifecycle migration scenarios: routine host migrations, rolling multi-instance upgrades, and emergency procedures for compromised hosts.

> **Reviewer note:** This runbook must be reviewed and signed off by a second engineer before use in production.

---

## Pre-Migration Checklist

Complete **all** items before starting any migration.

- [ ] Verify latest backup exists and is **not older than 24 hours**
  ```bash
  ls -la $SENTINEL_BACKUP_PATH
  ```
- [ ] Verify Discovery admin access is available (valid API token)
  ```bash
  sentinelctl status --discovery-url $DISCOVERY_URL
  ```
- [ ] Target host meets system requirements:
  - OS: Ubuntu 22.04+ or RHEL 9+
  - Python 3.11+
  - Network access to Discovery Service, chain RPC, Redis, Vault (if Vault mode)
  - Ports 8443 (inbound), 8000 (outbound to Discovery) are open
- [ ] Note current `instance_id` and DID for audit trail
  ```bash
  sentinelctl status
  ```
- [ ] Coordinate downtime window with service consumers (or plan rolling migration)
- [ ] Verify chain governance has no pending policy update that could affect migration timing

---

## Single-Instance Migration

Use this procedure when there is exactly **one** sentinel instance serving a service.

> **Warning:** This procedure has a downtime window between steps 3 and 7 (~2–5 minutes).

### Step 1: Stop the existing sentinel safely

```bash
# On old host — send SIGTERM for graceful shutdown (marks endpoint as draining)
sudo systemctl stop sentinel
# Wait for in-flight requests to drain (DRAIN_TIMEOUT_SECONDS=30)
sleep 35
```

### Step 2: Create encrypted backup

```bash
# On old host
export BACKUP_PASSPHRASE="<strong-random-passphrase>"
sentinelctl backup \
  --store "$SENTINEL_HOME/store" \
  --output "/tmp/sentinel_backup_$(date +%Y%m%d_%H%M%S).enc"
# Record the SHA-256 fingerprint printed to stdout!
```

### Step 3: Transfer backup to new host

```bash
# Secure transfer only — never use unencrypted channels
scp /tmp/sentinel_backup_*.enc operator@new-host:/tmp/
```

### Step 4: Provision new host

On the new host:

```bash
# Install sentinel
pip install sentinel-node==<version>

# Create directory structure
mkdir -p ~/.sentinel/store ~/.sentinel/store/credentials
chmod 700 ~/.sentinel ~/.sentinel/store
```

### Step 5: Restore backup

```bash
# On new host
export BACKUP_PASSPHRASE="<passphrase from step 2>"
sentinelctl restore \
  --input /tmp/sentinel_backup_*.enc \
  --target-dir ~/.sentinel
```

### Step 6: Verify restore integrity

```bash
sentinelctl status
# Expected: DID matches pre-migration DID, key_version matches
```

### Step 7: Rejoin Discovery

```bash
export SENTINEL_PASSPHRASE="<key passphrase>"
export SENTINEL_ENDPOINT_URL="https://new-host.internal:8443"
sentinelctl rejoin \
  --discovery-url "$DISCOVERY_URL" \
  --service-id "$SENTINEL_SERVICE_ID" \
  --endpoint-url "$SENTINEL_ENDPOINT_URL"
# Expected: "Rejoin successful" or "Sentinel already registered (idempotent)"
```

### Step 8: Start sentinel and verify

```bash
sudo systemctl start sentinel
sleep 10
sentinelctl status
# Expected: sentinel_operational: true, discovery: ✓ online
```

### Step 9: Post-migration verification

```bash
# Test a real request through the sentinel
curl -v https://new-host.internal:8443/health

# Verify audit log shows new instance_id
grep "instance_id" ~/.sentinel/key_operations.log | tail -5

# Check Discovery shows new endpoint
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$DISCOVERY_URL/api/v1/services/$SENTINEL_SERVICE_ID/descriptor"
```

---

## Multi-Instance Rolling Migration

Use this procedure for zero-downtime migration of N sentinel instances.

**Principle:** Migrate one instance at a time. Do not migrate the next instance until the previous one is healthy.

### Step 1: Identify instances and order

```bash
# Query Discovery for all active endpoints
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$DISCOVERY_URL/api/v1/registry/resolve?service_id=$SENTINEL_SERVICE_ID"
# Note: instance_id, endpoint_url, weight for each instance
```

### Step 2: For each instance (repeat steps 2a–2f for each):

#### Step 2a: Reduce weight of target instance (optional)

```bash
# Reduce traffic to instance being migrated
curl -XPATCH -H "Authorization: Bearer $SENTINEL_TOKEN" \
  "$DISCOVERY_URL/api/v1/services/$SERVICE_ID/descriptor/endpoints" \
  -d '{"instance_id": "<target>", "weight": 10, "health_status": "active", "env": "prod"}'
sleep 30  # allow consumers to drain from this instance
```

#### Step 2b: Stop the instance gracefully

```bash
ssh operator@instance-host "sudo systemctl stop sentinel"
```

#### Step 2c: Create backup and provision new host

*(Follow Single-Instance steps 2–6 for this instance)*

#### Step 2d: Rejoin and start on new host

```bash
sentinelctl rejoin --discovery-url "$DISCOVERY_URL" --service-id "$SERVICE_ID"
sudo systemctl start sentinel
```

#### Step 2e: Verify this instance is healthy before proceeding

```bash
sentinelctl status
# Verify: sentinel_operational: true
# Verify Discovery shows this instance as active
curl "$DISCOVERY_URL/api/v1/registry/resolve?service_id=$SERVICE_ID" | jq '.endpoints'
```

#### Step 2f: Decommission old instance

```bash
# Remove deregistered old endpoint (if Discovery doesn't auto-expire)
curl -XPATCH -H "Authorization: Bearer $SENTINEL_TOKEN" \
  "$DISCOVERY_URL/api/v1/services/$SERVICE_ID/descriptor/endpoints" \
  -d "{\"instance_id\": \"<old-instance-id>\", \"health_status\": \"offline\", \"env\": \"prod\"}"
```

### Step 3: Final verification

```bash
# All instances should appear with health_status=active
curl "$DISCOVERY_URL/api/v1/registry/resolve?service_id=$SERVICE_ID" \
  | jq '[.endpoints[] | {instance_id: .instance_id[:8], status: .health_status, weight: .weight}]'
```

---

## Emergency Migration (Host Compromise)

> **Use this procedure only when the sentinel host is suspected to be compromised.**  
> This procedure results in a **new DID** — all consumer trust policies must be updated.

### Step 1: Immediately revoke credentials in Discovery

```bash
# Discovery admin action — revoke all credentials for the compromised sentinel DID
curl -XPOST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$DISCOVERY_URL/api/v1/sentinels/$COMPROMISED_SENTINEL_ID/revoke-all" \
  -d '{"reason": "host_compromise", "revoked_by": "security-team"}'
```

### Step 2: Rotate chain trust policy (if applicable)

Contact the governance admin to update the TrustPolicyRegistry to reject the old DID.

### Step 3: Provision new host with fresh identity

```bash
# NEW host — do NOT restore from backup (the key may be compromised)
export SENTINEL_PASSPHRASE="<new-strong-passphrase>"
sentinelctl init \
  --service-id "$SENTINEL_SERVICE_ID" \
  --role producer \
  --env prod
# Note the NEW DID printed to stdout
```

### Step 4: Re-enroll as new sentinel

Obtain a new enrollment token from a Discovery admin:

```bash
# Discovery admin issues new enrollment token
curl -XPOST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$DISCOVERY_URL/api/v1/enrollments" \
  -d "{\"service_id\": \"$SENTINEL_SERVICE_ID\", \"sentinel_did\": \"<NEW_DID>\"}"
```

Use the enrollment token to onboard:

```bash
export ENROLLMENT_TOKEN="<token from admin>"
sentinelctl rejoin \
  --discovery-url "$DISCOVERY_URL" \
  --service-id "$SENTINEL_SERVICE_ID"
```

### Step 5: Update consumer trust policies

Notify all consumer sentinels of the new DID via governance (TrustPolicyRegistry update or Discovery config bundle push).

### Step 6: Decommission compromised host

```bash
# Destroy the old host's key material (or shut down/isolate the VM)
# Document the incident in the security audit log
```

---

## Post-Migration Verification

After **any** migration:

```bash
# 1. Check sentinel is fully operational
sentinelctl status
# Expected: sentinel_operational: true, all checks green

# 2. Verify instance_id is stable
sentinelctl status | grep instance_id
# Should match the instance_id from before migration (except emergency migration)

# 3. Test a real request through the sentinel (producer mode)
# Send a test request with valid SentinelProof + SentinelVP headers
# Expected: 200 response from backend

# 4. Verify audit log entries
tail -20 "$SENTINEL_HOME/key_operations.log"
# Expected: rejoin entry with outcome=success

# 5. Monitor for 15 minutes
# Watch for: 401 errors, replay detection, chain policy fetch failures
```

---

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| `rejoin` returns 403 | Enrollment token expired or invalid | Obtain new enrollment token from Discovery admin |
| `rejoin` returns 401 | DID key mismatch | Verify backup was restored correctly; check `sentinelctl status` DID |
| `status` shows `discovery: ✗ unreachable` | Network/firewall issue | Check routing to Discovery URL, verify TLS cert |
| `status` shows `sentinel_operational: false` | Key file missing or corrupt | Re-run `sentinelctl restore` or `sentinelctl init` |
| Publisher lock not released | Redis crash during publish | Key expires automatically after `DESCRIPTOR_PUBLISH_LOCK_TTL` seconds |
| Requests failing after migration | Consumer cached old endpoint | Consumers refresh descriptor every 60s; wait or flush consumer cache |

---

## Security Notes

- **Never print or log private key material.** `sentinelctl` is designed to prevent this.
- The backup passphrase is **different** from the key passphrase to limit blast radius.
- In Vault mode: migration = redeploy pointing to same Vault path, followed by `sentinelctl rejoin`. No backup/restore needed.
- DID rotation grace period defaults to **300 seconds**. Do not permanently decommission the old host until the grace period has elapsed.
- All CLI operations are written to `$SENTINEL_HOME/key_operations.log` for audit purposes.
