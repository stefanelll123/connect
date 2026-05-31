#!/bin/bash
# =============================================================================
# Hub bootstrap: postgres + redis + hardhat (Anvil) + discovery + governance
#                + otel-collector
#
# Terraform templatefile variables (replaced before this script runs on EC2):
#   ${aws_region}  ${git_repo_url}  ${git_token}  ${github_repository}
#   ${postgres_password}  ${redis_password}  ${secret_storage_master_key}
#   ${hardhat_private_key}  ${sentinel_passphrase}  ${discovery_admin_api_key}
#   ${ssm_prefix}
# =============================================================================

set -euo pipefail
exec > >(tee /var/log/connect-bootstrap.log | logger -t connect-hub) 2>&1

echo "=== Connect Load-Test Hub Bootstrap — $(date -u) ==="

# ── 0. Install system dependencies ──────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  git curl unzip python3 python3-pip python3-venv \
  ca-certificates gnupg lsb-release awscli jq

# Install Docker Engine
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker

echo "✓ Docker $(docker --version) installed"

# ── 1. Clone repository ──────────────────────────────────────────────────────
GIT_TOKEN="${git_token}"
GIT_REPO_URL="${git_repo_url}"

if [ -n "$GIT_TOKEN" ]; then
  CLONE_URL="https://$GIT_TOKEN@$${GIT_REPO_URL#https://}"
else
  CLONE_URL="$GIT_REPO_URL"
fi

git clone --depth 1 "$CLONE_URL" /opt/connect
echo "✓ Repository cloned to /opt/connect"

# ── 2. Write environment file ────────────────────────────────────────────────
# Written by Terraform; bash does NOT further expand this heredoc (single-quoted EOF).
mkdir -p /opt/connect/deploy
cat > /opt/connect/.env.loadtest << 'ENVEOF'
POSTGRES_PASSWORD=${postgres_password}
REDIS_PASSWORD=${redis_password}
SECRET_STORAGE_MASTER_KEY=${secret_storage_master_key}
HARDHAT_PRIVATE_KEY=${hardhat_private_key}
SENTINEL_PASSPHRASE=${sentinel_passphrase}
DISCOVERY_ADMIN_API_KEY=${discovery_admin_api_key}
GITHUB_REPOSITORY=${github_repository}
IMAGE_TAG=loadtest
ENVEOF

chmod 600 /opt/connect/.env.loadtest
echo "✓ Environment file written"

# ── 3. Write hub Docker Compose file ────────────────────────────────────────
# All template variables below have been replaced by Terraform before this
# script runs on EC2. The heredoc is single-quoted so bash will not
# re-expand anything.
cat > /opt/connect/docker-compose.hub.yml << 'COMPOSEEOF'
x-healthcheck-defaults: &hc
  interval: 10s
  timeout: 5s
  retries: 10
  start_period: 30s

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: sentinel_user
      POSTGRES_PASSWORD: ${postgres_password}
      POSTGRES_DB: sentinel_db
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      <<: *hc
      test: ["CMD-SHELL", "pg_isready -U sentinel_user -d sentinel_db"]

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes --requirepass ${redis_password}
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      <<: *hc
      test: ["CMD-SHELL", "redis-cli -a ${redis_password} ping | grep PONG"]

  hardhat:
    image: ghcr.io/foundry-rs/foundry:latest
    user: "0:0"
    entrypoint: ""
    command: >
      anvil
        --host 0.0.0.0
        --port 8545
        --chain-id 31337
        --block-time 1
        --steps-tracing
        --allow-origin "*"
        --state /data/anvil-state.json
        --state-interval 60
    ports:
      - "8545:8545"
    volumes:
      - hardhat_data:/data
    healthcheck:
      <<: *hc
      test: ["CMD", "cast", "chain-id", "--rpc-url", "http://127.0.0.1:8545"]

  otel-collector:
    image: otel/opentelemetry-collector-contrib:0.100.0
    command: ["--config=/etc/otelcol-contrib/config.yaml"]
    volumes:
      - ./deploy/otel-collector-config.yaml:/etc/otelcol-contrib/config.yaml:ro
    ports:
      - "4317:4317"
      - "4318:4318"
    healthcheck:
      disable: true

  governance:
    build:
      context: .
      dockerfile: services/governance/Dockerfile
    environment:
      BLOCKCHAIN_RPC_URL: http://hardhat:8545
      GOVERNANCE_DB_PATH: /data/governance.db
    ports:
      - "8080:8080"
    volumes:
      - governance_data:/data
    depends_on:
      hardhat:
        condition: service_healthy
    healthcheck:
      <<: *hc
      test: ["CMD-SHELL", "curl -sf http://localhost:8080/health || exit 1"]

  discovery:
    build:
      context: .
      dockerfile: services/discovery/Dockerfile
    environment:
      DATABASE_URL: postgresql+asyncpg://sentinel_user:${postgres_password}@postgres:5432/sentinel_db
      REDIS_URL: redis://:${redis_password}@redis:6379/0
      BLOCKCHAIN_RPC_URL: http://hardhat:8545
      BLOCKCHAIN_CHAIN_ID: "31337"
      BLOCKCHAIN_INTEGRATION: "true"
      DISCOVERY_ENV: loadtest
      DISCOVERY_HOST: "0.0.0.0"
      DISCOVERY_PORT: "8000"
      AUTH_MODE: dev
      DISCOVERY_ADMIN_API_KEY: ${discovery_admin_api_key}
      SECRET_STORAGE_MASTER_KEY: ${secret_storage_master_key}
      OTEL_EXPORTER_OTLP_ENDPOINT: http://otel-collector:4318
      OTEL_ENABLED: "true"
      DEPLOYMENT_ENVIRONMENT: loadtest
      ALLOWED_CORS_ORIGINS: '["*"]'
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      hardhat:
        condition: service_healthy
      otel-collector:
        condition: service_started
    healthcheck:
      <<: *hc
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/live')"]
      start_period: 60s

volumes:
  postgres_data:
  redis_data:
  hardhat_data:
  governance_data:
COMPOSEEOF

echo "✓ Hub docker-compose.hub.yml written"

# ── 4. Build Docker images ───────────────────────────────────────────────────
cd /opt/connect
DOCKER_BUILDKIT=1 docker compose -f docker-compose.hub.yml build \
  --build-arg BUILDKIT_INLINE_CACHE=1 \
  2>&1 | tee /var/log/connect-build.log
echo "✓ Images built"

# ── 5. Start infrastructure services first ──────────────────────────────────
docker compose -f docker-compose.hub.yml up -d postgres redis hardhat

echo "Waiting for postgres..."
until docker compose -f docker-compose.hub.yml exec -T postgres \
    pg_isready -U sentinel_user -d sentinel_db 2>/dev/null; do
  sleep 3
done

echo "Waiting for hardhat..."
until docker compose -f docker-compose.hub.yml exec -T hardhat \
    cast chain-id --rpc-url http://localhost:8545 2>/dev/null; do
  sleep 3
done
echo "✓ Infrastructure services healthy"

# ── 6. Deploy smart contracts ────────────────────────────────────────────────
python3 -m venv /opt/connect-venv
/opt/connect-venv/bin/pip install -q asyncpg httpx "web3>=7.0"

cd /opt/connect
BLOCKCHAIN_RPC_URL=http://localhost:8545 \
DATABASE_URL="postgresql+asyncpg://sentinel_user:${postgres_password}@localhost:5432/sentinel_db" \
POSTGRES_PASSWORD="${postgres_password}" \
HARDHAT_PRIVATE_KEY="${hardhat_private_key}" \
  /opt/connect-venv/bin/python scripts/seed.py --chain-only
echo "✓ Contracts deployed"

# ── 7. Write contract addresses to SSM ───────────────────────────────────────
AWS_REGION="${aws_region}"
SSM_PREFIX="${ssm_prefix}"

/opt/connect-venv/bin/python3 - << 'PYEOF'
import json, subprocess, os, sys

region = os.environ["AWS_DEFAULT_REGION"] if "AWS_DEFAULT_REGION" in os.environ else "${aws_region}"
ssm_prefix = "${ssm_prefix}"

try:
    data = json.load(open("/opt/connect/contracts/deployments/local.json"))
except FileNotFoundError:
    print("ERROR: contracts/deployments/local.json not found — seed.py --chain-only may have failed", file=sys.stderr)
    sys.exit(1)

for name, info in data["contracts"].items():
    subprocess.run([
        "aws", "ssm", "put-parameter",
        "--name", f"{ssm_prefix}/contract/{name}",
        "--value", info["address"],
        "--type", "String",
        "--overwrite",
        "--region", "${aws_region}",
    ], check=True)
    print(f"  SSM: {ssm_prefix}/contract/{name} = {info['address']}")

print("✓ Contract addresses written to SSM")
PYEOF

# ── 8. Start remaining hub services ─────────────────────────────────────────
docker compose -f docker-compose.hub.yml up -d otel-collector governance discovery

echo "Waiting for discovery to be ready..."
until curl -sf http://localhost:8000/health/live > /dev/null 2>&1; do
  sleep 5
done
echo "✓ Discovery service healthy"

# ── 9. Seed database (Phase 2 of seed.py) ────────────────────────────────────
cd /opt/connect

# Read contract addresses from local.json and export them for seed.py
ISSUER_REGISTRY=$(jq -r '.contracts.IssuerRegistry.address' contracts/deployments/local.json)
TRUST_POLICY_REGISTRY=$(jq -r '.contracts.TrustPolicyRegistry.address' contracts/deployments/local.json)
STATUS_REGISTRY=$(jq -r '.contracts.StatusRegistry.address' contracts/deployments/local.json)
SERVICE_REGISTRY=$(jq -r '.contracts.ServiceRegistry.address' contracts/deployments/local.json)

BLOCKCHAIN_RPC_URL=http://localhost:8545 \
DATABASE_URL="postgresql+asyncpg://sentinel_user:${postgres_password}@localhost:5432/sentinel_db" \
POSTGRES_PASSWORD="${postgres_password}" \
DISCOVERY_URL=http://localhost:8000 \
DISCOVERY_ADMIN_API_KEY="${discovery_admin_api_key}" \
HARDHAT_PRIVATE_KEY="${hardhat_private_key}" \
CONTRACT_ISSUER_REGISTRY=$ISSUER_REGISTRY \
CONTRACT_TRUST_POLICY_REGISTRY=$TRUST_POLICY_REGISTRY \
CONTRACT_STATUS_REGISTRY=$STATUS_REGISTRY \
CONTRACT_SERVICE_REGISTRY=$SERVICE_REGISTRY \
  /opt/connect-venv/bin/python scripts/seed.py --skip-chain
echo "✓ Database seeded"

# ── 10. Issue a load-test credential and write to SSM ───────────────────────
# This VC JWT is read by the load test scripts (Option A from the plan).
VC_JWT=$( \
  curl -sf -X POST http://localhost:8000/api/v1/credentials/issue \
    -H "X-API-Key: ${discovery_admin_api_key}" \
    -H "Content-Type: application/json" \
    -d '{"subject_id":"load-test-consumer","credential_type":"ServiceAccessCredential","claims":{}}' \
  | jq -r '.credential' \
)

if [ -z "$VC_JWT" ] || [ "$VC_JWT" = "null" ]; then
  echo "WARNING: Could not issue load-test VC. Load tests will need a manually seeded credential."
else
  aws ssm put-parameter \
    --name "${ssm_prefix}/load_test/vc_jwt" \
    --value "$VC_JWT" \
    --type "SecureString" \
    --overwrite \
    --region "${aws_region}"
  echo "✓ Load-test VC JWT written to SSM: ${ssm_prefix}/load_test/vc_jwt"
fi

# ── 11. Write governance contract addresses to discovery env ─────────────────
# Restart discovery with contract addresses now that they are known.
# Append contract addresses to the compose file env section dynamically.
docker compose -f docker-compose.hub.yml exec -T discovery sh -c \
  "kill -HUP 1" 2>/dev/null || \
  docker compose -f docker-compose.hub.yml restart discovery

echo "Waiting for discovery restart..."
sleep 10
until curl -sf http://localhost:8000/health/live > /dev/null 2>&1; do sleep 3; done
echo "✓ Discovery restarted"

# ── 12. Signal hub ready ──────────────────────────────────────────────────────
aws ssm put-parameter \
  --name "${ssm_prefix}/hub_ready" \
  --value "1" \
  --type "String" \
  --overwrite \
  --region "${aws_region}"

echo "=== Hub bootstrap complete — $(date -u) ==="
echo "Services:"
docker compose -f docker-compose.hub.yml ps
