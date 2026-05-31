#!/usr/bin/env bash
# Smoke test suite — validates core service health after deployment.
# Usage: SMOKE_BASE_URL=https://discovery.internal bash tests/smoke/smoke_test.sh
# Exit 0 = all checks passed; exit 1 = one or more checks failed.

set -euo pipefail

BASE_URL="${SMOKE_BASE_URL:-http://localhost:8000}"
SENTINEL_URL="${SENTINEL_BASE_URL:-http://localhost:8080}"
RETRIES=5
SLEEP_SECONDS=10
RESULTS_FILE="${RESULTS_FILE:-smoke-results.xml}"

pass=0
fail=0
declare -a failures=()

# ── helpers ──────────────────────────────────────────────────────────────────

check() {
  local name="$1"
  local cmd="$2"
  local attempt=1
  while [[ $attempt -le $RETRIES ]]; do
    if eval "$cmd" > /dev/null 2>&1; then
      echo "  PASS  $name"
      ((pass++))
      return 0
    fi
    echo "  RETRY $name (attempt $attempt/$RETRIES)"
    sleep "$SLEEP_SECONDS"
    ((attempt++))
  done
  echo "  FAIL  $name"
  ((fail++))
  failures+=("$name")
  return 0  # don't exit — collect all failures
}

# ── checks ───────────────────────────────────────────────────────────────────

echo "=== Smoke Tests against ${BASE_URL} ==="

check "discovery /health/live" \
  "curl -sf '${BASE_URL}/health/live' | grep -q 'ok\|alive\|true'"

check "discovery /health/ready" \
  "curl -sf '${BASE_URL}/health/ready' | grep -q 'ok\|ready\|true'"

check "discovery /api/v1/services returns list" \
  "curl -sf '${BASE_URL}/api/v1/services' | python3 -c 'import json,sys; d=json.load(sys.stdin); assert isinstance(d, (list, dict))'"

check "sentinel /health returns 200" \
  "curl -sf -o /dev/null -w '%{http_code}' '${SENTINEL_URL}/health' | grep -q '200'"

check "discovery /metrics (Prometheus)" \
  "curl -sf '${BASE_URL}/metrics' | grep -q 'python_info\|http_requests_total\|up'"

# ── JUnit XML output ─────────────────────────────────────────────────────────

total=$((pass + fail))
timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

{
  echo '<?xml version="1.0" encoding="UTF-8"?>'
  echo "<testsuites name=\"smoke\" tests=\"${total}\" failures=\"${fail}\" timestamp=\"${timestamp}\">"
  echo "  <testsuite name=\"smoke\" tests=\"${total}\" failures=\"${fail}\">"
  for f in "${failures[@]}"; do
    echo "    <testcase name=\"${f}\" classname=\"smoke\"><failure message=\"check failed\"/></testcase>"
  done
  # Add passing tests (requires tracking names — simplified here)
  echo "  </testsuite>"
  echo "</testsuites>"
} > "$RESULTS_FILE"

echo ""
echo "Results: ${pass} passed, ${fail} failed (${total} total)"
echo "JUnit report written to ${RESULTS_FILE}"

if [[ $fail -gt 0 ]]; then
  echo "FAILED checks:"
  for f in "${failures[@]}"; do
    echo "  - $f"
  done
  exit 1
fi
