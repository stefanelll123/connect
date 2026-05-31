#!/usr/bin/env bash
# =============================================================================
# run_load_tests.sh — Automated load test runner for §5.2 experiments
#
# Prerequisites:
#   source /opt/load-tests/.env          # sets PRODUCER_URL, DISCOVERY_URL, etc.
#   source /opt/load-test-venv/bin/activate
#   pip install -r requirements.txt      # if not already done
#
# Results are written to ./results/ as Locust CSV files and one
# revocation_timing.csv.  All output is also tee'd to results/run.log.
#
# Usage:
#   bash run_load_tests.sh               # all experiments
#   EXPERIMENTS="a b" bash run_load_tests.sh   # subset
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

LOG="$RESULTS_DIR/run.log"
exec > >(tee "$LOG") 2>&1

echo "========================================================"
echo "  Connect Load Test Suite — $(date -u)"
echo "========================================================"
echo "  PRODUCER_URL  : ${PRODUCER_URL:?Set PRODUCER_URL}"
echo "  DISCOVERY_URL : ${DISCOVERY_URL:?Set DISCOVERY_URL}"
echo "  Results dir   : $RESULTS_DIR"
echo ""

# Default to all experiments unless overridden
EXPERIMENTS="${EXPERIMENTS:-a b c}"

# ── Shared Locust flags ───────────────────────────────────────────────────────
COMMON_FLAGS=(
  --host "$PRODUCER_URL"
  --headless
  --loglevel WARNING
)

# ── Experiment (a): Phase A vs Phase B latency ────────────────────────────────
# 50 virtual users, 5 min each, 5 users/s ramp-up.
# Results: latency distribution (P50/P95/P99) for each phase.

run_experiment_a() {
  echo ""
  echo "────────────────────────────────────────────────────────"
  echo "Experiment (a) — Phase A latency (N=50 users, T=300s)"
  echo "────────────────────────────────────────────────────────"
  locust -f "$SCRIPT_DIR/locustfile.py" PhaseAUser \
    "${COMMON_FLAGS[@]}" \
    -u 50 -r 5 -t 300s \
    --csv "$RESULTS_DIR/phase_a" \
    --html "$RESULTS_DIR/phase_a.html"
  echo "✓ Phase A results: $RESULTS_DIR/phase_a_*.csv"

  echo ""
  echo "Experiment (a) — Phase B latency (N=50 users, T=300s)"
  locust -f "$SCRIPT_DIR/locustfile.py" PhaseBUser \
    "${COMMON_FLAGS[@]}" \
    -u 50 -r 5 -t 300s \
    --csv "$RESULTS_DIR/phase_b" \
    --html "$RESULTS_DIR/phase_b.html"
  echo "✓ Phase B results: $RESULTS_DIR/phase_b_*.csv"
}

# ── Experiment (b): Throughput-vs-concurrency sweep ─────────────────────────
# Ramp from 10 to 200 concurrent users in steps, 90 s each step.
# For each level, record achieved req/s and P95 latency.

run_experiment_b() {
  echo ""
  echo "────────────────────────────────────────────────────────"
  echo "Experiment (b) — Throughput-vs-concurrency sweep"
  echo "────────────────────────────────────────────────────────"

  CONCURRENCY_LEVELS=(10 25 50 75 100 150 200)

  for USERS in "${CONCURRENCY_LEVELS[@]}"; do
    echo ""
    echo "  → $USERS concurrent users (90s)..."
    locust -f "$SCRIPT_DIR/locustfile.py" ThroughputUser \
      "${COMMON_FLAGS[@]}" \
      -u "$USERS" -r "$((USERS / 5 + 1))" -t 90s \
      --csv "$RESULTS_DIR/throughput_${USERS}u" \
      2>/dev/null
    echo "  ✓ Done — results: $RESULTS_DIR/throughput_${USERS}u_*.csv"

    # Brief cool-down between levels to let the sentinel drain its queue.
    sleep 10
  done

  # Merge per-level stats into a summary CSV for easy plotting.
  echo ""
  echo "Writing concurrency sweep summary..."
  python3 - << 'PYEOF'
import csv, glob, os, sys

results_dir = os.environ.get("RESULTS_DIR", "./results")
out = []
for level_csv in sorted(glob.glob(f"{results_dir}/throughput_*u_stats.csv")):
    users = int(os.path.basename(level_csv).split("_")[1].rstrip("u"))
    with open(level_csv) as f:
        rows = list(csv.DictReader(f))
    # Sum aggregated row
    agg = next((r for r in rows if r.get("Name", "") == "Aggregated"), None)
    if agg:
        out.append({
            "users": users,
            "requests": agg.get("Request Count", ""),
            "failures": agg.get("Failure Count", ""),
            "rps": agg.get("Requests/s", ""),
            "p50_ms": agg.get("50%", ""),
            "p95_ms": agg.get("95%", ""),
            "p99_ms": agg.get("99%", ""),
        })

if out:
    summary_path = f"{results_dir}/concurrency_sweep_summary.csv"
    with open(summary_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=out[0].keys())
        writer.writeheader()
        writer.writerows(out)
    print(f"✓ Concurrency sweep summary: {summary_path}")
    # Print as table
    print(f"\n{'Users':>8} {'Req/s':>8} {'P50':>8} {'P95':>8} {'P99':>8} {'Failures':>10}")
    print("-" * 55)
    for row in out:
        print(f"{row['users']:>8} {row['rps']:>8} {row['p50_ms']:>8} {row['p95_ms']:>8} {row['p99_ms']:>8} {row['failures']:>10}")
PYEOF
}

# ── Experiment (c): Revocation propagation timing ────────────────────────────

run_experiment_c() {
  echo ""
  echo "────────────────────────────────────────────────────────"
  echo "Experiment (c) — Revocation propagation timing (N=${N_RUNS:-20} runs)"
  echo "────────────────────────────────────────────────────────"
  RESULTS_DIR="$RESULTS_DIR" \
    N_RUNS="${N_RUNS:-20}" \
    POLL_INTERVAL_MS="${POLL_INTERVAL_MS:-250}" \
    python3 "$SCRIPT_DIR/revocation_timing.py"
}

# ── Dispatch ─────────────────────────────────────────────────────────────────
for EXP in $EXPERIMENTS; do
  case "$EXP" in
    a) run_experiment_a ;;
    b) run_experiment_b ;;
    c) run_experiment_c ;;
    *) echo "Unknown experiment: $EXP (valid: a b c)" ;;
  esac
done

echo ""
echo "========================================================"
echo "  All experiments complete — $(date -u)"
echo "  Results: $RESULTS_DIR"
echo "========================================================"
