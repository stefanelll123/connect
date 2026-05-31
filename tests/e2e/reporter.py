"""E2E test reporter — collects latency metrics from pytest results and writes
a structured JSON + Markdown summary report.

Usage (called automatically by pytest plugin hook, or directly):
  python tests/e2e/reporter.py [--input results.json] [--output-dir reports/]
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class TestMetrics:
    name: str
    passed: bool
    duration_s: float
    extra: dict = field(default_factory=dict)


def percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = int(math.ceil(p / 100 * len(sorted_vals))) - 1
    return sorted_vals[max(0, min(idx, len(sorted_vals) - 1))]


def build_report(metrics: list[TestMetrics]) -> dict:
    durations = sorted(m.duration_s for m in metrics)
    passed = [m for m in metrics if m.passed]
    failed = [m for m in metrics if not m.passed]

    latency_ms = [d * 1000 for d in durations]

    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "summary": {
            "total": len(metrics),
            "passed": len(passed),
            "failed": len(failed),
            "success_rate": len(passed) / len(metrics) if metrics else 0,
        },
        "latency_ms": {
            "p50": round(percentile(latency_ms, 50), 1),
            "p95": round(percentile(latency_ms, 95), 1),
            "p99": round(percentile(latency_ms, 99), 1),
            "max": round(max(latency_ms, default=0), 1),
        },
        "slo": {
            "request_permit_p95_ms": 200,
            "time_to_containment_s": 30,
            "time_to_deny_s": 15,
        },
        "failed_tests": [m.name for m in failed],
        "test_details": [
            {
                "name": m.name,
                "passed": m.passed,
                "duration_s": round(m.duration_s, 3),
                **m.extra,
            }
            for m in metrics
        ],
    }


def render_markdown(report: dict) -> str:
    s = report["summary"]
    lat = report["latency_ms"]
    slo = report["slo"]
    ts = report["generated_at"]

    status_icon = "✅" if s["failed"] == 0 else "❌"

    lines = [
        f"# E2E Test Report {status_icon}",
        f"",
        f"Generated: {ts}",
        f"",
        f"## Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total tests | {s['total']} |",
        f"| Passed | {s['passed']} |",
        f"| Failed | {s['failed']} |",
        f"| Success rate | {s['success_rate']:.1%} |",
        f"",
        f"## Latency",
        f"",
        f"| Percentile | Value | SLO |",
        f"|------------|-------|-----|",
        f"| p50 | {lat['p50']}ms | — |",
        f"| p95 | {lat['p95']}ms | < {slo['request_permit_p95_ms']}ms {'✅' if lat['p95'] < slo['request_permit_p95_ms'] else '❌'} |",
        f"| p99 | {lat['p99']}ms | — |",
        f"| max | {lat['max']}ms | — |",
    ]

    if report["failed_tests"]:
        lines += ["", "## Failed Tests", ""]
        for name in report["failed_tests"]:
            lines.append(f"- ❌ `{name}`")

    return "\n".join(lines) + "\n"


def load_pytest_json(path: Path) -> list[TestMetrics]:
    """Parse pytest-json-report output file."""
    data = json.loads(path.read_text())
    results = []
    for test in data.get("tests", []):
        results.append(
            TestMetrics(
                name=test.get("nodeid", "unknown"),
                passed=test.get("outcome") == "passed",
                duration_s=test.get("call", {}).get("duration", 0),
            )
        )
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="E2E test reporter")
    parser.add_argument("--input", default="e2e-results.json", help="pytest-json-report input file")
    parser.add_argument("--output-dir", default=".", help="Directory to write report files")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    metrics = load_pytest_json(input_path)
    report = build_report(metrics)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_out = out_dir / "test-report.json"
    md_out = out_dir / "test-report.md"

    json_out.write_text(json.dumps(report, indent=2))
    md_out.write_text(render_markdown(report))

    print(f"Report written to {json_out} and {md_out}")

    if report["summary"]["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
