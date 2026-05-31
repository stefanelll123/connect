#!/bin/bash
# =============================================================================
# Consumer bootstrap: sentinel-consumer + Python load-test tooling
#
# Terraform templatefile variables:
#   ${aws_region}  ${git_repo_url}  ${git_token}  ${github_repository}
#   ${hub_private_ip}  ${postgres_password}  ${redis_password}
#   ${secret_storage_master_key}  ${sentinel_passphrase}  ${ssm_prefix}
# =============================================================================

set -euo pipefail
exec > >(tee /var/log/connect-bootstrap.log | logger -t connect-consumer) 2>&1

echo "=== Connect Load-Test Consumer Bootstrap — $(date -u) ==="

# ── 0. Install system dependencies ──────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  git curl python3 python3-pip python3-venv \
  ca-certificates gnupg lsb-release awscli jq

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker

echo "✓ Docker installed"

# ── 1. Clone repository ──────────────────────────────────────────────────────
GIT_TOKEN="${git_token}"
GIT_REPO_URL="${git_repo_url}"

if [ -n "$GIT_TOKEN" ]; then
  CLONE_URL="https://$GIT_TOKEN@$${GIT_REPO_URL#https://}"
else
  CLONE_URL="$GIT_REPO_URL"
fi

git clone --depth 1 "$CLONE_URL" /opt/connect
echo "✓ Repository cloned"

# ── 2. Wait for the hub to be ready ──────────────────────────────────────────
echo "Waiting for hub to signal ready via SSM..."
until aws ssm get-parameter \
    --name "${ssm_prefix}/hub_ready" \
    --region "${aws_region}" > /dev/null 2>&1; do
  echo "  hub not ready yet, retrying in 15s..."
  sleep 15
done
echo "✓ Hub is ready"

# ── 3. Read contract addresses from SSM ────────────────────────────────────
ISSUER_REGISTRY=$(aws ssm get-parameter \
  --name "${ssm_prefix}/contract/IssuerRegistry" \
  --region "${aws_region}" \
  --query "Parameter.Value" --output text)
TRUST_POLICY_REGISTRY=$(aws ssm get-parameter \
  --name "${ssm_prefix}/contract/TrustPolicyRegistry" \
  --region "${aws_region}" \
  --query "Parameter.Value" --output text)
STATUS_REGISTRY=$(aws ssm get-parameter \
  --name "${ssm_prefix}/contract/StatusRegistry" \
  --region "${aws_region}" \
  --query "Parameter.Value" --output text)
SERVICE_REGISTRY=$(aws ssm get-parameter \
  --name "${ssm_prefix}/contract/ServiceRegistry" \
  --region "${aws_region}" \
  --query "Parameter.Value" --output text)

echo "✓ Contract addresses retrieved from SSM"

# ── 4. Write environment file ────────────────────────────────────────────────
cat > /opt/connect/.env.consumer << 'ENVEOF'
POSTGRES_PASSWORD=${postgres_password}
REDIS_PASSWORD=${redis_password}
SECRET_STORAGE_MASTER_KEY=${secret_storage_master_key}
SENTINEL_PASSPHRASE=${sentinel_passphrase}
GITHUB_REPOSITORY=${github_repository}
IMAGE_TAG=loadtest
ENVEOF
chmod 600 /opt/connect/.env.consumer

cat > /opt/connect/.env.contracts << ENVEOF
CONTRACT_ISSUER_REGISTRY=$ISSUER_REGISTRY
CONTRACT_TRUST_POLICY_REGISTRY=$TRUST_POLICY_REGISTRY
CONTRACT_STATUS_REGISTRY=$STATUS_REGISTRY
CONTRACT_SERVICE_REGISTRY=$SERVICE_REGISTRY
ENVEOF

echo "✓ Environment files written"

# ── 5. Write consumer Docker Compose file ────────────────────────────────────
cat > /opt/connect/docker-compose.consumer.yml << 'COMPOSEEOF'
x-healthcheck-defaults: &hc
  interval: 10s
  timeout: 5s
  retries: 10
  start_period: 30s

services:
  sentinel-consumer:
    build:
      context: .
      dockerfile: services/sentinel/Dockerfile
    environment:
      SENTINEL_ROLE: consumer
      SERVICE_ID: loadtest-sentinel-consumer
      SENTINEL_ENV: loadtest
      SENTINEL_HOME: /data
      SENTINEL_PASSPHRASE: ${sentinel_passphrase}
      DATABASE_URL: postgresql+asyncpg://sentinel_user:${postgres_password}@${hub_private_ip}:5432/sentinel_db
      REDIS_URL: redis://:${redis_password}@${hub_private_ip}:6379/2
      BLOCKCHAIN_RPC_URL: http://${hub_private_ip}:8545
      BLOCKCHAIN_CHAIN_ID: "31337"
      DISCOVERY_URL: http://${hub_private_ip}:8000
      SECRET_STORAGE_MASTER_KEY: ${secret_storage_master_key}
      SENTINEL_SECRET_BACKEND: local
      SECRET_STORAGE_PATH: /data/secrets
      SERVICE_NAME: sentinel-consumer
      SERVICE_VERSION: "0.1.0"
      OTEL_EXPORTER_OTLP_ENDPOINT: http://${hub_private_ip}:4318
      OTEL_ENABLED: "true"
      DEPLOYMENT_ENVIRONMENT: loadtest
    ports:
      - "8080:8080"
    volumes:
      - sentinel_consumer_data:/data
    healthcheck:
      <<: *hc
      test: ["CMD-SHELL", "curl -sf http://localhost:8080/health"]

volumes:
  sentinel_consumer_data:
COMPOSEEOF

echo "✓ docker-compose.consumer.yml written"

# ── 6. Build images ──────────────────────────────────────────────────────────
cd /opt/connect
DOCKER_BUILDKIT=1 docker compose \
  -f docker-compose.consumer.yml \
  build 2>&1 | tee /var/log/connect-build.log
echo "✓ Images built"

# ── 7. Start services ────────────────────────────────────────────────────────
docker compose \
  -f docker-compose.consumer.yml \
  --env-file .env.contracts \
  up -d --wait
echo "✓ Consumer sentinel started"

# ── 8. Install load-test Python tooling ──────────────────────────────────────
python3 -m venv /opt/load-test-venv
/opt/load-test-venv/bin/pip install -q \
  locust httpx PyJWT cryptography boto3 statistics

# Copy load tests from repo to a convenient location
cp -r /opt/connect/tests/load /opt/load-tests
chown -R ubuntu:ubuntu /opt/load-tests

echo "✓ Load test tooling installed at /opt/load-tests"
echo "  Activate venv: source /opt/load-test-venv/bin/activate"

# ── 9. Write load test configuration ─────────────────────────────────────────
# This file is sourced by run_load_tests.sh and read by the Locust file.
# Hub private IP is used here for best latency (within-VPC traffic).
cat > /opt/load-tests/.env << 'LTEOF'
export PRODUCER_URL=http://${hub_private_ip}:8080
export CONSUMER_URL=http://localhost:8080
export DISCOVERY_URL=http://${hub_private_ip}:8000
export AWS_DEFAULT_REGION=${aws_region}
export SSM_PREFIX=${ssm_prefix}
LTEOF

echo "=== Consumer bootstrap complete — $(date -u) ==="
docker compose -f docker-compose.consumer.yml ps
echo ""
echo "To run load tests:"
echo "  source /opt/load-tests/.env"
echo "  source /opt/load-test-venv/bin/activate"
echo "  cd /opt/load-tests && bash run_load_tests.sh"
