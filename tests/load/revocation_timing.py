"""
Revocation propagation timing — Experiment (c) from §5.2.

Measures the elapsed time from the moment a credential is revoked at the
Discovery service until the producer sentinel begins denying requests that
carry that credential (the Δ-bounded propagation window).

Algorithm per run:
  1. Issue a fresh ServiceAccessCredential via Discovery admin API.
  2. Verify the sentinel grants PERMIT with this credential (sanity check).
  3. Record t_revoke = now(); call Discovery /credentials/{id}/revoke.
  4. Poll the producer sentinel at high frequency with the revoked credential.
  5. Record t_deny = time of the first DENY (non-PERMIT) response.
  6. propagation_ms = t_deny - t_revoke.

Repeat for N_RUNS to collect a distribution; print P50 / P95 / P99.

Usage:
  # From the consumer EC2 instance after sourcing /opt/load-tests/.env:
  source /opt/load-tests/.env
  source /opt/load-test-venv/bin/activate
  python revocation_timing.py

  # Override defaults:
  N_RUNS=20 POLL_INTERVAL_MS=200 python revocation_timing.py

Environment variables:
  PRODUCER_URL              — producer sentinel base URL
  DISCOVERY_URL             — discovery service base URL
  DISCOVERY_ADMIN_API_KEY   — admin key for issuing / revoking credentials
  N_RUNS                    — number of measurement runs (default: 20)
  POLL_INTERVAL_MS          — polling interval in milliseconds (default: 250)
  MAX_WAIT_S                — give-up timeout per run in seconds (default: 120)
  DELTA_WINDOW_S            — expected upper bound Δ from the paper (default: 600)
  RESULTS_DIR               — directory to write results CSV (default: ./results)
"""
from __future__ import annotations

import csv
import os
import statistics
import sys
import time
import uuid
from pathlib import Path

import httpx

PRODUCER_URL = os.environ.get("PRODUCER_URL", "http://localhost:8080")
DISCOVERY_URL = os.environ.get("DISCOVERY_URL", "http://localhost:8000")
ADMIN_API_KEY = os.environ.get("DISCOVERY_ADMIN_API_KEY", "")
N_RUNS = int(os.environ.get("N_RUNS", "20"))
POLL_INTERVAL_S = int(os.environ.get("POLL_INTERVAL_MS", "250")) / 1000.0
MAX_WAIT_S = int(os.environ.get("MAX_WAIT_S", "120"))
DELTA_WINDOW_S = int(os.environ.get("DELTA_WINDOW_S", "600"))
RESULTS_DIR = Path(os.environ.get("RESULTS_DIR", "./results"))


def _admin_headers() -> dict[str, str]:
    return {"X-API-Key": ADMIN_API_KEY, "Content-Type": "application/json"}


def _issue_credential(client: httpx.Client) -> tuple[str, str]:
    """Issue a fresh ServiceAccessCredential. Returns (credential_id, vc_jwt)."""
    subject_id = f"revocation-test-{uuid.uuid4().hex[:8]}"
    resp = client.post(
        f"{DISCOVERY_URL}/api/v1/credentials/issue",
        headers=_admin_headers(),
        json={
            "subject_id": subject_id,
            "credential_type": "ServiceAccessCredential",
            "claims": {},
        },
    )
    resp.raise_for_status()
    body = resp.json()
    credential_id = body.get("id") or body.get("credential_id")
    vc_jwt = body.get("credential")
    if not credential_id or not vc_jwt:
        raise ValueError(f"Unexpected credential issue response: {body}")
    return credential_id, vc_jwt


def _revoke_credential(client: httpx.Client, credential_id: str) -> None:
    """Revoke a credential by ID via the Discovery admin API."""
    resp = client.post(
        f"{DISCOVERY_URL}/api/v1/credentials/{credential_id}/revoke",
        headers=_admin_headers(),
    )
    resp.raise_for_status()


def _sentinel_request(client: httpx.Client, vc_jwt: str) -> str:
    """Send a Phase A request; returns the decision string or 'ERROR'."""
    nonce = str(uuid.uuid4())
    try:
        resp = client.post(
            f"{PRODUCER_URL}/api/v1/request",
            headers={
                "X-Sentinel-VC": vc_jwt,
                "X-Request-ID": nonce,
                "X-Nonce": nonce,
                "X-Timestamp": str(int(time.time())),
                "Content-Type": "application/json",
            },
            json={"target": "/api/probe", "method": "GET"},
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.json().get("decision", "UNKNOWN")
        return f"HTTP_{resp.status_code}"
    except httpx.RequestError:
        return "ERROR"


def run_single_measurement(
    discovery_client: httpx.Client,
    sentinel_client: httpx.Client,
    run_index: int,
) -> float | None:
    """
    Execute one revocation timing run.
    Returns propagation time in seconds, or None if the sentinel never denied.
    """
    print(f"\n  Run {run_index + 1}/{N_RUNS}:")

    # Step 1: Issue a fresh credential.
    credential_id, vc_jwt = _issue_credential(discovery_client)
    print(f"    Issued credential: {credential_id}")

    # Step 2: Sanity-check — must be PERMIT before revocation.
    decision = _sentinel_request(sentinel_client, vc_jwt)
    if decision != "PERMIT":
        print(f"    SKIP — pre-revocation decision was {decision!r} (expected PERMIT)")
        return None

    # Step 3: Revoke the credential.
    t_revoke = time.perf_counter()
    _revoke_credential(discovery_client, credential_id)
    print(f"    Revoked at t=0")

    # Step 4: Poll until DENY.
    deadline = t_revoke + MAX_WAIT_S
    poll_count = 0
    while time.perf_counter() < deadline:
        decision = _sentinel_request(sentinel_client, vc_jwt)
        poll_count += 1
        if decision != "PERMIT":
            t_deny = time.perf_counter()
            propagation_s = t_deny - t_revoke
            print(
                f"    DENY received after {propagation_s:.3f}s "
                f"(decision={decision!r}, polls={poll_count})"
            )
            return propagation_s
        time.sleep(POLL_INTERVAL_S)

    print(f"    TIMEOUT — sentinel still PERMITting after {MAX_WAIT_S}s")
    return None


def main() -> None:
    if not ADMIN_API_KEY:
        print("ERROR: DISCOVERY_ADMIN_API_KEY is not set.", file=sys.stderr)
        sys.exit(1)

    print("=" * 60)
    print("Revocation Propagation Timing — Experiment (c)")
    print("=" * 60)
    print(f"  Producer URL    : {PRODUCER_URL}")
    print(f"  Discovery URL   : {DISCOVERY_URL}")
    print(f"  Runs            : {N_RUNS}")
    print(f"  Poll interval   : {POLL_INTERVAL_S * 1000:.0f} ms")
    print(f"  Max wait        : {MAX_WAIT_S} s")
    print(f"  Δ (paper bound) : {DELTA_WINDOW_S} s")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = RESULTS_DIR / "revocation_timing.csv"

    measurements_s: list[float] = []
    skipped = 0

    with httpx.Client(timeout=15) as dc, httpx.Client(timeout=15) as sc:
        with csv_path.open("w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["run", "propagation_s", "status"])
            writer.writeheader()

            for i in range(N_RUNS):
                try:
                    result = run_single_measurement(dc, sc, i)
                except Exception as exc:
                    print(f"  Run {i + 1} ERROR: {exc}")
                    writer.writerow({"run": i + 1, "propagation_s": "", "status": "error"})
                    skipped += 1
                    continue

                if result is None:
                    writer.writerow({"run": i + 1, "propagation_s": "", "status": "timeout_or_skip"})
                    skipped += 1
                else:
                    writer.writerow({"run": i + 1, "propagation_s": f"{result:.3f}", "status": "ok"})
                    measurements_s.append(result)

    # ── Summary ──────────────────────────────────────────────────────────────
    n = len(measurements_s)
    print("\n" + "=" * 60)
    print("Results")
    print("=" * 60)
    print(f"  Successful runs : {n} / {N_RUNS}  (skipped/timeout: {skipped})")

    if n == 0:
        print("  No valid measurements — check service health and API key.")
        sys.exit(1)

    sorted_ms = sorted(measurements_s)
    p50 = sorted_ms[int(n * 0.50)]
    p95 = sorted_ms[min(int(n * 0.95), n - 1)]
    p99 = sorted_ms[min(int(n * 0.99), n - 1)]
    mean = statistics.mean(measurements_s)
    stdev = statistics.stdev(measurements_s) if n > 1 else 0.0

    print(f"  Mean            : {mean:.3f} s")
    print(f"  Stdev           : {stdev:.3f} s")
    print(f"  P50             : {p50:.3f} s")
    print(f"  P95             : {p95:.3f} s")
    print(f"  P99             : {p99:.3f} s")
    print(f"  Min             : {sorted_ms[0]:.3f} s")
    print(f"  Max             : {sorted_ms[-1]:.3f} s")
    print(f"\n  CSV written to  : {csv_path}")

    within_delta = sum(1 for s in measurements_s if s <= DELTA_WINDOW_S)
    pct_within = 100.0 * within_delta / n
    print(
        f"\n  Within Δ={DELTA_WINDOW_S}s bound : "
        f"{within_delta}/{n} runs ({pct_within:.0f}%)"
    )

    if p99 > DELTA_WINDOW_S:
        print(
            f"\n  WARNING: P99 ({p99:.1f}s) exceeds the paper's Δ bound "
            f"({DELTA_WINDOW_S}s). Investigate revocation cache TTL settings."
        )
    else:
        print(
            f"\n  ✓ P99 ({p99:.1f}s) is within the Δ={DELTA_WINDOW_S}s bound."
        )


if __name__ == "__main__":
    main()
