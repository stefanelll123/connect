# Incident Runbook — Chain Outage / Indexer Stuck

**Severity**: P2 — High  
**Response SLO**: 1 hour  
**Owner**: Platform on-call

---

## 1. Detection Signals

- Grafana alert: `ChainIndexerLag > 50 blocks` (warning) or `> 200 blocks` (critical)
- Prometheus alert: `ChainIndexerLagCritical` firing
- Dashboard: Sentinel — Chain Events → Indexer Lag Over Time
- Discovery logs: `"event":"chain_rpc_timeout"` or `"event":"chain_connection_error"`

---

## 2. Diagnosis

```bash
# Check indexer lag metric
curl -s http://discovery.internal/metrics | grep sentinel_chain_indexer_lag_blocks

# Check current chain block vs Discovery's last indexed block
CHAIN_BLOCK=$(curl -s -X POST https://sepolia.infura.io/v3/${INFURA_KEY} \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","id":1}' | jq -r '.result' | xargs printf "%d\n" 2>/dev/null)
INDEXED_BLOCK=$(curl -s https://discovery.internal/api/v1/chain/status | jq '.last_block')
echo "Chain: ${CHAIN_BLOCK}  Indexed: ${INDEXED_BLOCK}  Lag: $((CHAIN_BLOCK - INDEXED_BLOCK))"

# View Discovery chain-related errors
kubectl logs -n sentinel-prod -l app=discovery --since=30m \
  | grep '"subsystem":"chain"' | tail -50
```

---

## 3. Remediation — RPC Provider Failure

### Step 1 — Try the backup RPC endpoint

Discovery supports primary + fallback RPC. To switch:
```bash
# Check current RPC config
kubectl get configmap discovery-config -n sentinel-prod -o jsonpath='{.data.chain-rpc-url}'

# Update ConfigMap to use backup provider
kubectl patch configmap discovery-config -n sentinel-prod \
  --patch '{"data":{"chain-rpc-url":"https://sepolia.backup-rpc.example.com"}}'

# Rolling restart to pick up new config
kubectl rollout restart deployment/discovery -n sentinel-prod
kubectl rollout status deployment/discovery -n sentinel-prod --timeout=5m
```

### Step 2 — Verify indexer catches up

```bash
# Watch lag metric converge
watch -n 5 'curl -s http://discovery.internal/metrics | grep sentinel_chain_indexer_lag_blocks'
```

---

## 4. Remediation — Indexer Process Crash Loop

```bash
# Check pod events
kubectl describe pod -n sentinel-prod -l app=discovery | grep -A 20 "Events:"

# Force pod restart
kubectl rollout restart deployment/discovery -n sentinel-prod

# If persistent, check DB connectivity
kubectl exec -n sentinel-prod deploy/discovery -- \
  python3 -c "import asyncpg; asyncio.run(asyncpg.connect('${DATABASE_URL}'))"
```

---

## 5. Extended Outage Response (> 30 min lag)

When the indexer is severely behind, sentinel nodes may be operating on stale data.  
Communicate to service operators:

```bash
# Create a maintenance notice (example)
curl -s -X POST https://discovery.internal/api/v1/admin/notices \
  -H "Authorization: Bearer ${ADMIN_JWT}" \
  -d '{"level":"warning","message":"Chain indexer recovering — status checks may be delayed up to N blocks."}'
```

Consider putting sentinel in advisory-only mode if lag > 500 blocks:
```bash
kubectl set env deployment/sentinel-node -n sentinel-prod SENTINEL_FAIL_SAFE_MODE=advisory
```
Undo after recovery:
```bash
kubectl set env deployment/sentinel-node -n sentinel-prod SENTINEL_FAIL_SAFE_MODE-
```

---

## 6. Post-Incident Checklist

- [ ] Root cause identified (network partition, RPC provider SLA breach, bug)
- [ ] Indexer fully caught up (lag = 0)
- [ ] Add second backup RPC endpoint if not already configured
- [ ] Review `ChainIndexerLag` alert thresholds
- [ ] Document in postmortem if > 1h of degraded operation
