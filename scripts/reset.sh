#!/usr/bin/env bash
# reset.sh — Destroy all Docker Compose state and restart a clean environment.
#
# Usage:
#   bash scripts/reset.sh
#   bash scripts/reset.sh --env-file /path/to/.env.local
#
# Environment:
#   COMPOSE_ENV_FILE — path to the env file (default: .env.local)
#
# Completes within 120 seconds (after images are built).
# FOR LOCAL DEVELOPMENT ONLY. Never run this in production.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="${COMPOSE_ENV_FILE:-"$ROOT_DIR/.env.local"}"
MAX_WAIT=120
POLL_INTERVAL=5
SEED_SCRIPT="$SCRIPT_DIR/seed.py"

# Parse --env-file argument
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file) ENV_FILE="$2"; shift 2 ;;
    --env-file=*) ENV_FILE="${1#*=}"; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "[reset] $*"; }
die()  { echo "[reset] ERROR: $*" >&2; exit 1; }
ok()   { echo "[reset] ✓ $*"; }

compose_args=()
if [[ -f "$ENV_FILE" ]]; then
  compose_args+=(--env-file "$ENV_FILE")
  log "Env file: $ENV_FILE"
else
  log "Warning: $ENV_FILE not found — relying on shell environment"
fi

run_compose() { docker compose "${compose_args[@]}" "$@"; }

# ---------------------------------------------------------------------------
# Step 1: tear down
# ---------------------------------------------------------------------------
log "Tearing down existing environment (all volumes will be removed) …"
run_compose down --volumes --remove-orphans
ok "Torn down."

# ---------------------------------------------------------------------------
# Step 2: start
# ---------------------------------------------------------------------------
log "Starting services …"
run_compose up -d
ok "Services started."

# ---------------------------------------------------------------------------
# Step 3: wait for core infrastructure to be healthy
# ---------------------------------------------------------------------------
log "Waiting for infrastructure (postgres, redis, hardhat) to be healthy (max ${MAX_WAIT}s) …"

wait_for_service_healthy() {
  local svc="$1"
  local waited=0
  while true; do
    health=$(docker compose "${compose_args[@]}" ps --format json "$svc" 2>/dev/null \
      | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        row = json.loads(line)
        print(row.get('Health', row.get('Status', 'unknown')).lower())
        break
    except Exception:
        pass
print('unknown')
" 2>/dev/null || echo "unknown")

    case "$health" in
      healthy) return 0 ;;
      exited|dead) die "Service '$svc' exited unexpectedly." ;;
    esac

    if [[ $waited -ge $MAX_WAIT ]]; then
      die "Service '$svc' did not become healthy within ${MAX_WAIT}s."
    fi
    sleep "$POLL_INTERVAL"
    waited=$((waited + POLL_INTERVAL))
    log "  Waiting for $svc (${waited}s elapsed) …"
  done
}

for svc in postgres redis hardhat vault otel-collector; do
  log "  Waiting for $svc …"
  wait_for_service_healthy "$svc"
  ok "$svc healthy."
done

# ---------------------------------------------------------------------------
# Step 4: seed
# ---------------------------------------------------------------------------
log "Running seed script …"

# Source env file so seed.py has access to POSTGRES_PASSWORD, HARDHAT_PRIVATE_KEY, etc.
if [[ -f "$ENV_FILE" ]]; then
  set -o allexport
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +o allexport
fi

if ! command -v python3 &>/dev/null; then
  die "python3 not found — install Python 3.11+ and try again."
fi

cd "$ROOT_DIR"
python3 "$SEED_SCRIPT"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
ok "Reset complete in ${SECONDS}s."
log "Run 'docker compose ps' to verify service status."
log "Discovery UI: http://localhost:8000"
log "Forge/Anvil:  http://localhost:8545"
