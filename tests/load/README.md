# Connect Load Tests

Load tests for the three performance experiments described in §5.2 of the paper.

## Infrastructure

Three AWS EC2 instances provisioned by `../terraform/`:

| Node | Services | Port |
|---|---|---|
| **hub** (t3.large) | postgres + redis + hardhat (Anvil) + discovery + governance + otel-collector | 8000, 5432, 6379, 8545 |
| **producer** (t3.medium) | sentinel-producer + mock-backend | 8080, 9000 |
| **consumer** (t3.medium) | sentinel-consumer + **load test runner** | 8080 |

## Quick start

### 1. Provision the infrastructure

```bash
cd tests/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars — fill in passwords, SSH key path, repo URL
terraform init
terraform apply
```

`terraform apply` will:
- Create the VPC, subnets, security groups, IAM role
- Launch three EC2 instances
- Bootstrap each via `user_data` scripts (takes ~10–15 minutes for Docker builds)
- Deploy smart contracts to the Anvil chain
- Seed a test credential and write it to SSM for the load tests (Option A)

Check bootstrap progress:
```bash
# Tail hub bootstrap log
ssh ubuntu@<hub_ip> "tail -f /var/log/connect-bootstrap.log"
```

### 2. Set environment variables

After `terraform apply` completes, copy the output snippet:
```bash
terraform output load_test_env_snippet
# Then paste and export those variables, or source the file on the consumer:
ssh ubuntu@<consumer_ip>
source /opt/load-tests/.env
source /opt/load-test-venv/bin/activate
```

If running locally (not from the consumer EC2):
```bash
export PRODUCER_URL=http://<producer_public_ip>:8080
export DISCOVERY_URL=http://<hub_public_ip>:8000
export DISCOVERY_ADMIN_API_KEY=<your_key>
export AWS_DEFAULT_REGION=us-east-1
export SSM_PREFIX=/connect-test
pip install -r tests/load/requirements.txt
```

### 3. Run all experiments

```bash
cd /opt/load-tests     # or tests/load/ from the workspace root
bash run_load_tests.sh
```

Results are written to `results/YYYYMMDD_HHMMSS/`.

---

## Experiments

### (a) Phase A vs Phase B latency — P50 / P95 / P99

**What it measures**: The cost of the full cryptographic pipeline (Phase A) versus the
session-token fast-path (Phase B) for a single sentinel instance at 50 concurrent users.

```bash
# Phase A only
locust -f locustfile.py PhaseAUser \
  --headless -u 50 -r 5 -t 300s \
  --host $PRODUCER_URL --csv results/phase_a

# Phase B only
locust -f locustfile.py PhaseBUser \
  --headless -u 50 -r 5 -t 300s \
  --host $PRODUCER_URL --csv results/phase_b
```

**Expected output** (from paper target): P95 < 200 ms for Phase A; P95 < 50 ms for Phase B.

---

### (b) Throughput-vs-concurrency characterisation

**What it measures**: Saturates a single sentinel-producer instance by sweeping from 10 to
200 concurrent virtual users (70% Phase B + 30% Phase A). Identifies where P95 latency
first exceeds 500 ms — the practical concurrency ceiling.

```bash
# Automated sweep (handles all concurrency levels and writes summary CSV)
EXPERIMENTS=b bash run_load_tests.sh

# Single level manually
locust -f locustfile.py ThroughputUser \
  --headless -u 100 -r 10 -t 90s \
  --host $PRODUCER_URL --csv results/throughput_100u
```

**Output**: `results/concurrency_sweep_summary.csv` with req/s, P50/P95/P99 per level.

---

### (c) Revocation propagation timing — Δ bound

**What it measures**: The delay between a credential revocation event at the Discovery
service and the first DENY response from the sentinel producer. The paper claims this is
bounded by the revocation cache TTL Δ (default: 600 s).

```bash
N_RUNS=20 POLL_INTERVAL_MS=250 python revocation_timing.py
```

**Output**: Prints P50/P95/P99 propagation times and checks them against Δ=600 s.
Writes `results/revocation_timing.csv`.

---

## Interpreting results

The Locust CSV files contain per-endpoint statistics. Key columns:

| Column | Meaning |
|---|---|
| `50%` | P50 response time (ms) |
| `95%` | P95 response time (ms) |
| `99%` | P99 response time (ms) |
| `Requests/s` | Achieved throughput |
| `Failure Count` | Requests that returned non-2xx or wrong decision |

For the paper, report:
- **§5.2 (a)**: Phase A P50/P95/P99 vs Phase B P50/P95/P99 from the `_stats.csv` files
- **§5.2 (b)**: The `concurrency_sweep_summary.csv` table; mark the first level where P95 > 500 ms
- **§5.2 (c)**: The `revocation_timing.csv` P50/P95/P99 propagation times; compare to Δ=600 s

---

## Tear down

```bash
cd tests/terraform
terraform destroy
```

This removes all AWS resources. SSM parameters under `/connect-test/` are also deleted
(they are created by the EC2 instances themselves; Terraform does not manage them directly,
but they will be removed when the IAM role is destroyed).

To clean up SSM manually:
```bash
aws ssm delete-parameters --names \
  /connect-test/hub_ready \
  /connect-test/load_test/vc_jwt \
  /connect-test/contract/IssuerRegistry \
  /connect-test/contract/TrustPolicyRegistry \
  /connect-test/contract/StatusRegistry \
  /connect-test/contract/ServiceRegistry
```

---

## Troubleshooting

**No VC JWT / all requests fail with 401**
```bash
# Check SSM
aws ssm get-parameter --name /connect-test/load_test/vc_jwt --with-decryption
# If empty, re-run hub step 10 manually:
ssh ubuntu@<hub_ip>
curl -sf -X POST http://localhost:8000/api/v1/credentials/issue \
  -H "X-API-Key: $DISCOVERY_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"subject_id":"load-test-consumer","credential_type":"ServiceAccessCredential","claims":{}}'
```

**Hub bootstrap failed**
```bash
ssh ubuntu@<hub_ip> "cat /var/log/connect-bootstrap.log"
# Re-run from the failed step after fixing the issue
```

**Sentinel not responding**
```bash
ssh ubuntu@<producer_ip> "docker compose -f /opt/connect/docker-compose.producer.yml ps"
ssh ubuntu@<producer_ip> "docker compose -f /opt/connect/docker-compose.producer.yml logs sentinel-producer --tail 50"
```
