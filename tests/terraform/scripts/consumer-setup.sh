#!/bin/bash
# =============================================================================
# Consumer setup script — all heavy orchestration for the consumer EC2 node.
# Called by user_data/consumer.sh after Docker and the repo are ready.
#
# Expected env vars (from /opt/connect/.env.consumer):
#   HUB_PRIVATE_IP, CONSUMER_PRIVATE_IP, DOCKER_HUB_USERNAME, IMAGE_TAG,
#   POSTGRES_PASSWORD, REDIS_PASSWORD, SECRET_STORAGE_MASTER_KEY,
#   SENTINEL_PASSPHRASE, AWS_DEFAULT_REGION, SSM_PREFIX
# =============================================================================
set -euo pipefail
exec >> /var/log/connect-bootstrap.log 2>&1

echo "--- consumer-setup.sh start: $(date -u) ---"

# ── Load env file ─────────────────────────────────────────────────────────────
set -a
# shellcheck source=/dev/null
source /opt/connect/.env.consumer
set +a

# ── Wait for hub to be ready (polls SSM) ─────────────────────────────────────
echo "Waiting for hub-ready flag in SSM (/$SSM_PREFIX/status/hub-ready)..."
MAX_RETRIES=120
for i in $(seq 1 "$MAX_RETRIES"); do
  HUB_READY=$(aws ssm get-parameter \
    --region "$AWS_DEFAULT_REGION" \
    --name "/$SSM_PREFIX/status/hub-ready" \
    --query "Parameter.Value" --output text 2>/dev/null || echo "")
  if [ "$HUB_READY" = "true" ]; then
    echo "✓ Hub is ready"
    break
  fi
  echo "  Hub not ready yet (attempt $i/$MAX_RETRIES)..."
  sleep 10
  if [ "$i" -eq "$MAX_RETRIES" ]; then
    echo "ERROR: Hub did not signal ready within $(( MAX_RETRIES * 10 ))s" >&2
    exit 1
  fi
done

# ── Read contract addresses from SSM ─────────────────────────────────────────
echo "Reading contract addresses from SSM..."
CONTRACT_ISSUER_REGISTRY=$(aws ssm get-parameter \
  --region "$AWS_DEFAULT_REGION" \
  --name "/$SSM_PREFIX/contract/issuer_registry" \
  --with-decryption --query "Parameter.Value" --output text)
CONTRACT_TRUST_POLICY_REGISTRY=$(aws ssm get-parameter \
  --region "$AWS_DEFAULT_REGION" \
  --name "/$SSM_PREFIX/contract/trust_policy_registry" \
  --with-decryption --query "Parameter.Value" --output text)
CONTRACT_STATUS_REGISTRY=$(aws ssm get-parameter \
  --region "$AWS_DEFAULT_REGION" \
  --name "/$SSM_PREFIX/contract/status_registry" \
  --with-decryption --query "Parameter.Value" --output text)
CONTRACT_SERVICE_REGISTRY=$(aws ssm get-parameter \
  --region "$AWS_DEFAULT_REGION" \
  --name "/$SSM_PREFIX/contract/service_registry" \
  --with-decryption --query "Parameter.Value" --output text)
echo "  IssuerRegistry    → $CONTRACT_ISSUER_REGISTRY"
echo "  ServiceRegistry   → $CONTRACT_SERVICE_REGISTRY"

# ── Read enrollment token from SSM ────────────────────────────────────────────
ENROLLMENT_TOKEN_CONSUMER=$(aws ssm get-parameter \
  --region "$AWS_DEFAULT_REGION" \
  --name "/$SSM_PREFIX/enrollment/consumer" \
  --with-decryption --query "Parameter.Value" --output text)
echo "✓ Enrollment token retrieved"

# ── Append contract addresses and enrollment token to env file ────────────────
cat >> /opt/connect/.env.consumer << EXTRAENV
CONTRACT_ISSUER_REGISTRY=$CONTRACT_ISSUER_REGISTRY
CONTRACT_TRUST_POLICY_REGISTRY=$CONTRACT_TRUST_POLICY_REGISTRY
CONTRACT_STATUS_REGISTRY=$CONTRACT_STATUS_REGISTRY
CONTRACT_SERVICE_REGISTRY=$CONTRACT_SERVICE_REGISTRY
ENROLLMENT_TOKEN_CONSUMER=$ENROLLMENT_TOKEN_CONSUMER
EXTRAENV

# ── Pull images ───────────────────────────────────────────────────────────────
echo "Pulling Docker images..."
docker pull "$DOCKER_HUB_USERNAME/connect-sentinel:$IMAGE_TAG"
docker pull locustio/locust:latest
echo "✓ Images pulled"

# ── Start services ────────────────────────────────────────────────────────────
COMPOSE_FILE=/opt/connect/tests/terraform/compose/consumer.yml
echo "Starting consumer services..."
docker compose -f "$COMPOSE_FILE" --env-file /opt/connect/.env.consumer up -d

# ── Wait for sentinel-consumer to be healthy ──────────────────────────────────
echo "Waiting for sentinel-consumer to become healthy..."
MAX_RETRIES=30
for i in $(seq 1 "$MAX_RETRIES"); do
  status=$(docker inspect \
    --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' \
    "$(docker compose -f "$COMPOSE_FILE" ps -q sentinel-consumer 2>/dev/null | head -1)" \
    2>/dev/null || echo "not-found")
  if [ "$status" = "healthy" ]; then
    echo "✓ sentinel-consumer is healthy"
    break
  fi
  echo "  status=$status (attempt $i/$MAX_RETRIES)"
  sleep 10
  if [ "$i" -eq "$MAX_RETRIES" ]; then
    echo "ERROR: sentinel-consumer did not become healthy" >&2
    exit 1
  fi
done

# ── Signal consumer readiness ─────────────────────────────────────────────────
aws ssm put-parameter --region "$AWS_DEFAULT_REGION" --overwrite \
  --name "/$SSM_PREFIX/status/consumer-ready" --value "true" --type String
echo "✓ consumer-ready flag written to SSM"

echo "=== consumer-setup.sh DONE: $(date -u) ==="
echo "  Sentinel consumer : http://$CONSUMER_PRIVATE_IP:8080/health/live"
echo "  Locust UI         : http://$CONSUMER_PRIVATE_IP:8089"
