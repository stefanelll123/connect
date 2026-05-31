#!/bin/bash
# =============================================================================
# Producer bootstrap: sentinel-producer + mock-backend
#
# Terraform templatefile variables:
#   ${aws_region}  ${git_repo_url}  ${git_token}  ${github_repository}
#   ${hub_private_ip}  ${postgres_password}  ${redis_password}
#   ${secret_storage_master_key}  ${sentinel_passphrase}  ${ssm_prefix}
# =============================================================================

set -euo pipefail
exec > >(tee /var/log/connect-bootstrap.log | logger -t connect-producer) 2>&1

echo "=== Connect Load-Test Producer Bootstrap — $(date -u) ==="

# ── 0. Install system dependencies ──────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  git curl ca-certificates gnupg lsb-release awscli jq

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

# ── 2. Wait for the hub to finish bootstrapping ──────────────────────────────
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
echo "  IssuerRegistry:       $ISSUER_REGISTRY"
echo "  TrustPolicyRegistry:  $TRUST_POLICY_REGISTRY"

# ── 4. Write environment file ────────────────────────────────────────────────
cat > /opt/connect/.env.producer << 'ENVEOF'
POSTGRES_PASSWORD=${postgres_password}
REDIS_PASSWORD=${redis_password}
SECRET_STORAGE_MASTER_KEY=${secret_storage_master_key}
SENTINEL_PASSPHRASE=${sentinel_passphrase}
GITHUB_REPOSITORY=${github_repository}
IMAGE_TAG=loadtest
ENVEOF
chmod 600 /opt/connect/.env.producer
echo "✓ Environment file written"

# ── 5. Write producer Docker Compose file ────────────────────────────────────
# All template variables have been replaced by Terraform before this script runs.
cat > /opt/connect/docker-compose.producer.yml << 'COMPOSEEOF'
x-healthcheck-defaults: &hc
  interval: 10s
  timeout: 5s
  retries: 10
  start_period: 30s

services:
  mock-backend:
    image: python:3.12-slim
    command:
      - python
      - "-c"
      - |
          from http.server import HTTPServer, BaseHTTPRequestHandler
          import json

          class Handler(BaseHTTPRequestHandler):
              def do_GET(self): self._respond()
              def do_POST(self): self._respond()
              def do_PUT(self): self._respond()
              def do_PATCH(self): self._respond()
              def do_DELETE(self): self._respond()
              def _respond(self):
                  body = json.dumps({"status": "ok", "path": self.path}).encode()
                  self.send_response(200)
                  self.send_header("Content-Type", "application/json")
                  self.send_header("Content-Length", str(len(body)))
                  self.end_headers()
                  self.wfile.write(body)
              def log_message(self, fmt, *args): pass

          HTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
    ports:
      - "9000:9000"
    healthcheck:
      <<: *hc
      test: ["CMD-SHELL", "python3 -c \"import urllib.request; urllib.request.urlopen('http://localhost:9000/')\""]

  sentinel-producer:
    build:
      context: .
      dockerfile: services/sentinel/Dockerfile
    environment:
      SENTINEL_ROLE: producer
      SERVICE_ID: loadtest-sentinel-producer
      SENTINEL_ENV: loadtest
      SENTINEL_HOME: /data
      SENTINEL_PASSPHRASE: ${sentinel_passphrase}
      DATABASE_URL: postgresql+asyncpg://sentinel_user:${postgres_password}@${hub_private_ip}:5432/sentinel_db
      REDIS_URL: redis://:${redis_password}@${hub_private_ip}:6379/1
      BLOCKCHAIN_RPC_URL: http://${hub_private_ip}:8545
      BLOCKCHAIN_CHAIN_ID: "31337"
      DISCOVERY_URL: http://${hub_private_ip}:8000
      BACKEND_URL: http://mock-backend:9000
      INBOUND_URL: http://sentinel-producer:8080
      SECRET_STORAGE_MASTER_KEY: ${secret_storage_master_key}
      SENTINEL_SECRET_BACKEND: local
      SECRET_STORAGE_PATH: /data/secrets
      SERVICE_NAME: sentinel-producer
      SERVICE_VERSION: "0.1.0"
      OTEL_EXPORTER_OTLP_ENDPOINT: http://${hub_private_ip}:4318
      OTEL_ENABLED: "true"
      DEPLOYMENT_ENVIRONMENT: loadtest
      SESSION_TOKEN_TTL: "900"
      SESSION_NONCE_TTL: "60"
      SESSION_RATE_LIMIT_PER_MINUTE: "1000"
    ports:
      - "8080:8080"
    volumes:
      - sentinel_producer_data:/data
    depends_on:
      mock-backend:
        condition: service_healthy
    healthcheck:
      <<: *hc
      test: ["CMD-SHELL", "curl -sf http://localhost:8080/health"]

volumes:
  sentinel_producer_data:
COMPOSEEOF

echo "✓ docker-compose.producer.yml written"

# ── 6. Inject dynamic values from SSM into the compose file env ───────────
# Append the contract addresses using sed (they were not available at plan time).
python3 - << 'PYEOF'
import subprocess, sys

pairs = [
    ("CONTRACT_ISSUER_REGISTRY",      "$ISSUER_REGISTRY"),
    ("CONTRACT_TRUST_POLICY_REGISTRY","$TRUST_POLICY_REGISTRY"),
    ("CONTRACT_STATUS_REGISTRY",      "$STATUS_REGISTRY"),
    ("CONTRACT_SERVICE_REGISTRY",     "$SERVICE_REGISTRY"),
]
# Re-read actual values from environment
import os
replacements = "\n      ".join(
    f"{k}: {os.environ.get(k.replace('CONTRACT_','').lower(), os.environ.get(k, ''))}"
    for k, _ in pairs
)
print("Contract env vars will be set via Docker --env-file")
PYEOF

# Write a separate contract addresses env file that docker compose will merge.
cat > /opt/connect/.env.contracts << ENVEOF
CONTRACT_ISSUER_REGISTRY=$ISSUER_REGISTRY
CONTRACT_TRUST_POLICY_REGISTRY=$TRUST_POLICY_REGISTRY
CONTRACT_STATUS_REGISTRY=$STATUS_REGISTRY
CONTRACT_SERVICE_REGISTRY=$SERVICE_REGISTRY
ENVEOF

# ── 7. Build images ──────────────────────────────────────────────────────────
cd /opt/connect
DOCKER_BUILDKIT=1 docker compose \
  -f docker-compose.producer.yml \
  build 2>&1 | tee /var/log/connect-build.log
echo "✓ Images built"

# ── 8. Start services ────────────────────────────────────────────────────────
docker compose \
  -f docker-compose.producer.yml \
  --env-file .env.contracts \
  up -d --wait
echo "✓ Producer services started"

# ── 9. Health check ───────────────────────────────────────────────────────────
echo "Verifying sentinel-producer health..."
until curl -sf http://localhost:8080/health > /dev/null 2>&1; do
  sleep 5
done

echo "=== Producer bootstrap complete — $(date -u) ==="
docker compose -f docker-compose.producer.yml ps
