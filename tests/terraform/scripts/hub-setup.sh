#!/bin/bash
# =============================================================================
# Hub setup script — all heavy orchestration for the hub EC2 instance.
# Called by user_data/hub.sh after Docker, Node.js, and the repo are ready.
#
# Expected env vars (set by user_data/hub.sh via /opt/connect/.env.hub):
#   HUB_PUBLIC_IP, HUB_PRIVATE_IP, DOCKER_HUB_USERNAME, IMAGE_TAG,
#   POSTGRES_PASSWORD, REDIS_PASSWORD, SECRET_STORAGE_MASTER_KEY,
#   HARDHAT_PRIVATE_KEY, SENTINEL_PASSPHRASE, DISCOVERY_ADMIN_API_KEY,
#   AWS_DEFAULT_REGION, SSM_PREFIX
# =============================================================================
set -euo pipefail
exec >> /var/log/connect-bootstrap.log 2>&1

echo "--- hub-setup.sh start: $(date -u) ---"

# ── Load env file ─────────────────────────────────────────────────────────────
set -a
# shellcheck source=/dev/null
source /opt/connect/.env.hub
set +a

COMPOSE_FILE=/opt/connect/tests/terraform/compose/hub.yml
COMPOSE="docker compose -f $COMPOSE_FILE --env-file /opt/connect/.env.hub"

# ── Helper: wait for a docker-compose service to be healthy ───────────────────
wait_healthy() {
  local svc="$1"
  local retries="${2:-30}"
  local sleep_sec="${3:-10}"
  echo "Waiting for $svc to be healthy..."
  for i in $(seq 1 "$retries"); do
    status=$(docker inspect \
      --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' \
      "$(docker compose -f $COMPOSE_FILE ps -q "$svc" 2>/dev/null | head -1)" 2>/dev/null || true)
    if [ "$status" = "healthy" ] || [ "$status" = "no-healthcheck" ]; then
      echo "  $svc is $status"
      return 0
    fi
    echo "  $svc status=$status (attempt $i/$retries)"
    sleep "$sleep_sec"
  done
  echo "ERROR: $svc did not become healthy in time" >&2
  exit 1
}

# ── Patch Keycloak realm JSON with real public IP ─────────────────────────────
# Replace localhost:3000 redirect/origin URIs with the hub's public IP.
REALM_JSON=/opt/connect/deploy/keycloak/discovery-realm.json
echo "Patching Keycloak realm JSON with HUB_PUBLIC_IP=$HUB_PUBLIC_IP ..."
sed -i \
  -e "s|http://localhost:3000|http://$HUB_PUBLIC_IP:3000|g" \
  -e "s|http://localhost:8001|http://$HUB_PUBLIC_IP:8001|g" \
  "$REALM_JSON"
echo "✓ Keycloak realm JSON patched"

# ── Pull images ───────────────────────────────────────────────────────────────
echo "Pulling Docker images..."
docker pull "$DOCKER_HUB_USERNAME/connect-discovery:$IMAGE_TAG"
docker pull "$DOCKER_HUB_USERNAME/connect-governance:$IMAGE_TAG"
docker pull postgres:15-alpine
docker pull redis:7-alpine
docker pull ghcr.io/foundry-rs/foundry:latest
docker pull hashicorp/vault:1.16
docker pull "otel/opentelemetry-collector-contrib:0.100.0"
docker pull quay.io/keycloak/keycloak:24.0
docker pull otterscan/otterscan:latest
docker pull python:3.12-slim
echo "✓ Images pulled"

# ── Write initial env with placeholder contract addresses ─────────────────────
# Contract addresses will be filled in after deployment; we need discovery and
# governance to start first so we can deploy against the running hardhat node.
cat >> /opt/connect/.env.hub << 'CONTRACTENV'
CONTRACT_ISSUER_REGISTRY=0x0000000000000000000000000000000000000000
CONTRACT_TRUST_POLICY_REGISTRY=0x0000000000000000000000000000000000000000
CONTRACT_STATUS_REGISTRY=0x0000000000000000000000000000000000000000
CONTRACT_SERVICE_REGISTRY=0x0000000000000000000000000000000000000000
JWT_ISSUER_DID=
JWT_ISSUER_KEY_ID=
CONTRACTENV

# ── Start infrastructure services (postgres, redis, hardhat, vault, otel) ────
echo "Starting infrastructure services..."
$COMPOSE up -d postgres redis hardhat vault otel-collector mock-backend
wait_healthy postgres 30 10
wait_healthy redis 30 10
wait_healthy hardhat 30 10
wait_healthy vault 20 5
echo "✓ Infrastructure services healthy"

# ── Deploy smart contracts ────────────────────────────────────────────────────
echo "Deploying smart contracts..."
cd /opt/connect/contracts
npm ci --silent
npx hardhat run scripts/deploy/deploy-local.ts --network localhost
echo "✓ Contracts deployed"

# ── Parse contract addresses from deployment output ───────────────────────────
DEPLOYMENT_JSON=/opt/connect/contracts/deployments/local.json
ISSUER_REGISTRY=$(jq -r '.contracts.IssuerRegistry.address' "$DEPLOYMENT_JSON")
TRUST_POLICY_REGISTRY=$(jq -r '.contracts.TrustPolicyRegistry.address' "$DEPLOYMENT_JSON")
STATUS_REGISTRY=$(jq -r '.contracts.StatusRegistry.address' "$DEPLOYMENT_JSON")
SERVICE_REGISTRY=$(jq -r '.contracts.ServiceRegistry.address' "$DEPLOYMENT_JSON")

echo "  IssuerRegistry        → $ISSUER_REGISTRY"
echo "  TrustPolicyRegistry   → $TRUST_POLICY_REGISTRY"
echo "  StatusRegistry        → $STATUS_REGISTRY"
echo "  ServiceRegistry       → $SERVICE_REGISTRY"

# ── Push contract addresses to SSM ───────────────────────────────────────────
echo "Writing contract addresses to SSM..."
aws ssm put-parameter --region "$AWS_DEFAULT_REGION" --overwrite \
  --name "/$SSM_PREFIX/contract/issuer_registry" --value "$ISSUER_REGISTRY" --type SecureString
aws ssm put-parameter --region "$AWS_DEFAULT_REGION" --overwrite \
  --name "/$SSM_PREFIX/contract/trust_policy_registry" --value "$TRUST_POLICY_REGISTRY" --type SecureString
aws ssm put-parameter --region "$AWS_DEFAULT_REGION" --overwrite \
  --name "/$SSM_PREFIX/contract/status_registry" --value "$STATUS_REGISTRY" --type SecureString
aws ssm put-parameter --region "$AWS_DEFAULT_REGION" --overwrite \
  --name "/$SSM_PREFIX/contract/service_registry" --value "$SERVICE_REGISTRY" --type SecureString
echo "✓ Contract addresses written to SSM"

# ── Update env file with real contract addresses ─────────────────────────────
sed -i \
  -e "s|CONTRACT_ISSUER_REGISTRY=.*|CONTRACT_ISSUER_REGISTRY=$ISSUER_REGISTRY|" \
  -e "s|CONTRACT_TRUST_POLICY_REGISTRY=.*|CONTRACT_TRUST_POLICY_REGISTRY=$TRUST_POLICY_REGISTRY|" \
  -e "s|CONTRACT_STATUS_REGISTRY=.*|CONTRACT_STATUS_REGISTRY=$STATUS_REGISTRY|" \
  -e "s|CONTRACT_SERVICE_REGISTRY=.*|CONTRACT_SERVICE_REGISTRY=$SERVICE_REGISTRY|" \
  /opt/connect/.env.hub

# ── Start keycloak (long start_period) ────────────────────────────────────────
echo "Starting Keycloak..."
$COMPOSE up -d keycloak
# Don't block on Keycloak health — it takes up to 2 minutes; discovery and
# governance can start concurrently.

# ── Start governance service ──────────────────────────────────────────────────
echo "Starting governance service..."
$COMPOSE up -d governance
wait_healthy governance 20 10
echo "✓ Governance service healthy"

# ── Bootstrap governance roles ────────────────────────────────────────────────
echo "Bootstrapping governance roles..."
docker compose -f "$COMPOSE_FILE" exec -T governance \
  python3 /scripts/bootstrap_governance.py
echo "✓ Governance roles bootstrapped"

# ── Start discovery service ───────────────────────────────────────────────────
echo "Starting discovery service..."
$COMPOSE up -d discovery
wait_healthy discovery 30 10
echo "✓ Discovery service healthy"

# ── Issue enrollment tokens for producer and consumer sentinels ───────────────
echo "Issuing enrollment tokens..."

# Get a short-lived operator JWT from the local_jwt dev-token endpoint
ADMIN_JWT=$(curl -sf \
  -X POST "http://localhost:8201/api/v1/auth/dev-token" \
  -H "Content-Type: application/json" \
  -d "{\"sub\": \"bootstrap\", \"roles\": [\"operator\"], \"actor_type\": \"ADMIN\"}" \
  | jq -r '.access_token')

if [ -z "$ADMIN_JWT" ] || [ "$ADMIN_JWT" = "null" ]; then
  echo "ERROR: Failed to obtain admin JWT from discovery dev-token endpoint" >&2
  exit 1
fi
echo "  Admin JWT obtained"

ENROLL_TOKEN_PRODUCER=$(curl -sf \
  -X POST "http://localhost:8201/api/v1/sentinels/enrollments" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"service_id": "aws-sentinel-producer", "role": "producer", "env": "loadtest", "expires_in_seconds": 3600}' \
  | jq -r '.token')

ENROLL_TOKEN_CONSUMER=$(curl -sf \
  -X POST "http://localhost:8201/api/v1/sentinels/enrollments" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"service_id": "aws-sentinel-consumer", "role": "consumer", "env": "loadtest", "expires_in_seconds": 3600}' \
  | jq -r '.token')

echo "  Producer token issued (first 8 chars): ${ENROLL_TOKEN_PRODUCER:0:8}..."
echo "  Consumer token issued (first 8 chars): ${ENROLL_TOKEN_CONSUMER:0:8}..."

# ── Push enrollment tokens to SSM ─────────────────────────────────────────────
aws ssm put-parameter --region "$AWS_DEFAULT_REGION" --overwrite \
  --name "/$SSM_PREFIX/enrollment/producer" --value "$ENROLL_TOKEN_PRODUCER" --type SecureString
aws ssm put-parameter --region "$AWS_DEFAULT_REGION" --overwrite \
  --name "/$SSM_PREFIX/enrollment/consumer" --value "$ENROLL_TOKEN_CONSUMER" --type SecureString
echo "✓ Enrollment tokens written to SSM"

# ── Start remaining services ──────────────────────────────────────────────────
echo "Starting remaining hub services (otterscan, keycloak)..."
$COMPOSE up -d otterscan
echo "✓ All hub services started"

# ── Signal readiness to producer + consumer nodes ────────────────────────────
aws ssm put-parameter --region "$AWS_DEFAULT_REGION" --overwrite \
  --name "/$SSM_PREFIX/status/hub-ready" --value "true" --type String
echo "✓ hub-ready flag written to SSM"

echo "=== hub-setup.sh DONE: $(date -u) ==="
echo ""
echo "Service endpoints:"
echo "  Discovery API : http://$HUB_PUBLIC_IP:8201/api/v1"
echo "  Keycloak      : http://$HUB_PUBLIC_IP:8001"
echo "  Governance UI : http://$HUB_PUBLIC_IP:8080"
echo "  Otterscan     : http://$HUB_PUBLIC_IP:5100"
echo "  OTel metrics  : http://$HUB_PUBLIC_IP:8889/metrics"
