"""Repeatable Python-versus-Go attack-path engine benchmark.

This is intentionally offline. It measures the correlated graph phase over the
same normalized inventory for both implementations, never AWS API latency. The
fixture mirrors a common large-account shape: many least-privilege identities,
each with an exact S3 ARN grant. Python's reference engine visits every target
for every identity; Go resolves literal grants through graph indexes.

Examples
--------
    .\\.venv\\Scripts\\python.exe scripts\\benchmark_graph_engines.py \
      --sizes 250 500 1000 2000 4000 --runs 9 --json-out .benchmarks\\graph.json

The result includes:
  * Python graph build and detection
  * Go graph build and detection from a pre-built identical snapshot
  * Go end-to-end, including snapshot construction and process transport

The script asserts full operator-visible issue parity before timing. It does
not benchmark production AWS calls, SQLite persistence, the web API, or the
frontend. Those are separate performance concerns.
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import platform
import shutil
import statistics
import sys
import time
import tracemalloc
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, TypeVar

from odineyes.inventory import graph_engine
from odineyes.inventory.issues import analyze as analyze_python
from odineyes.inventory.schema import NormalizedAsset

T = TypeVar("T")
ACCOUNT = "123456789012"
REGION = "us-east-1"


@dataclass(frozen=True)
class Timing:
    runs: int
    min_ms: float
    p50_ms: float
    p95_ms: float
    max_ms: float
    mean_ms: float


def _binary() -> str:
    configured = os.environ.get(graph_engine.ENV_BINARY, "").strip()
    candidates = [configured] if configured else []
    candidates.extend((
        "scanner-go/bin/odineyes-graph.exe",
        "scanner-go/bin/odineyes-graph",
        shutil.which(graph_engine.DEFAULT_BINARY) or "",
    ))
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate).resolve())
    raise SystemExit(
        "Go graph engine not found. Build scanner-go/cmd/odineyes-graph or set "
        f"{graph_engine.ENV_BINARY}."
    )


def fixture(population: int) -> list[NormalizedAsset]:
    """Return ``population`` roles and ``population`` buckets.

    Every role receives one exact ARN grant. No role is admin: granting admin
    would correctly create every possible role-to-bucket edge and benchmark
    output volume, rather than the exact-grant lookup algorithm we are testing.
    A small deterministic sample of public buckets keeps detector work real.
    """
    assets: list[NormalizedAsset] = []
    bucket_arns: list[str] = []
    for index in range(population):
        name = f"tenant-data-{index:06d}"
        arn = f"arn:aws:s3:::{name}"
        bucket_arns.append(arn)
        assets.append(NormalizedAsset(
            resource_id=arn,
            cloud_provider="aws",
            account_identifier=ACCOUNT,
            asset_type="aws.s3.bucket",
            name=name,
            region=REGION,
            is_public=index % 997 == 0,
            encryption_enabled=index % 2 == 0,
            tags={"Environment": "production" if index % 5 == 0 else "staging"},
        ))

    for index, bucket_arn in enumerate(bucket_arns):
        role_arn = f"arn:aws:iam::{ACCOUNT}:role/app-{index:06d}"
        assets.append(NormalizedAsset(
            resource_id=role_arn,
            cloud_provider="aws",
            account_identifier=ACCOUNT,
            asset_type="aws.iam.role",
            name=f"app-{index:06d}",
            region="global",
            properties={
                "policy_analysis_complete": True,
                "s3_read_resources": [bucket_arn],
                "trust_principals": [f"arn:aws:iam::{ACCOUNT}:root"],
                # Exercise the direct IAM detector without inflating graph
                # edges. The cadence remains stable at every size.
                "privesc_actions": ["iam:PutRolePolicy"] if index % 701 == 0 else [],
            },
        ))
    return assets


def fingerprint(issues: list[Any]) -> list[tuple[Any, ...]]:
    """Stable, operator-visible result projection used for parity assertions."""
    return sorted(
        (
            issue.issue_type,
            issue.resource_id,
            issue.severity,
            round(issue.risk_score, 1),
            round(issue.confidence, 2),
            json.dumps(issue.path, sort_keys=True, separators=(",", ":")),
            issue.title,
            issue.why,
            issue.remediation,
            json.dumps(issue.compliance, sort_keys=True, separators=(",", ":")),
            json.dumps(issue.related, sort_keys=True, separators=(",", ":")),
            json.dumps(issue.evidence, sort_keys=True, separators=(",", ":")),
            issue.scoring,
        )
        for issue in issues
    )


def percentile(samples: list[float], fraction: float) -> float:
    ordered = sorted(samples)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower, upper = int(position), min(int(position) + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def time_function(operation: Callable[[], T], *, runs: int, expected: Any) -> Timing:
    # Warm imports, bytecode and the Go executable before collecting samples.
    for _ in range(2):
        assert operation() == expected

    samples: list[float] = []
    for _ in range(runs):
        gc.collect()
        started = time.perf_counter_ns()
        actual = operation()
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        assert actual == expected, "engine output changed between benchmark runs"
        samples.append(elapsed_ms)

    return Timing(
        runs=runs,
        min_ms=round(min(samples), 3),
        p50_ms=round(statistics.median(samples), 3),
        p95_ms=round(percentile(samples, 0.95), 3),
        max_ms=round(max(samples), 3),
        mean_ms=round(statistics.fmean(samples), 3),
    )


def python_peak_bytes(operation: Callable[[], Any]) -> int:
    """Measure Python heap peak once without distorting latency samples."""
    gc.collect()
    tracemalloc.start()
    operation()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak


def run_population(population: int, configured_runs: int) -> dict[str, Any]:
    assets = fixture(population)
    snapshot = graph_engine.build_snapshot(assets)
    python_issues = analyze_python(assets)
    go_issues = [graph_engine._issue_from_dict(item) for item in graph_engine.run_go_engine(snapshot)["issues"]]
    expected = fingerprint(python_issues)
    if expected != fingerprint(go_issues):
        raise RuntimeError(f"parity failed for population={population}")

    # Larger populations receive fewer repetitions so an intensive suite still
    # completes on ordinary developer laptops and the t3.micro release host.
    runs = configured_runs if population <= 1_000 else max(3, configured_runs // 3)

    def python_operation() -> list[tuple[Any, ...]]:
        return fingerprint(analyze_python(assets))

    def go_core_operation() -> list[tuple[Any, ...]]:
        result = graph_engine.run_go_engine(snapshot)
        return fingerprint([graph_engine._issue_from_dict(item) for item in result["issues"]])

    def go_end_to_end_operation() -> list[tuple[Any, ...]]:
        built = graph_engine.build_snapshot(assets)
        result = graph_engine.run_go_engine(built)
        return fingerprint([graph_engine._issue_from_dict(item) for item in result["issues"]])

    python_timing = time_function(python_operation, runs=runs, expected=expected)
    go_core_timing = time_function(go_core_operation, runs=runs, expected=expected)
    go_e2e_timing = time_function(go_end_to_end_operation, runs=runs, expected=expected)

    return {
        "roles": population,
        "buckets": population,
        "assets": len(assets),
        "issues": len(python_issues),
        "python_graph_detect": asdict(python_timing),
        "go_graph_detect": asdict(go_core_timing),
        "go_end_to_end": asdict(go_e2e_timing),
        "go_core_speedup_vs_python_p50": round(
            python_timing.p50_ms / go_core_timing.p50_ms, 2
        ),
        "go_e2e_speedup_vs_python_p50": round(
            python_timing.p50_ms / go_e2e_timing.p50_ms, 2
        ),
        "python_peak_tracemalloc_bytes": python_peak_bytes(python_operation),
        "parity": True,
    }


def markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Python vs Go graph detection benchmark",
        "",
        "The fixture has one exact S3 ARN grant per IAM role. All runs passed "
        "full operator-visible issue parity before timing.",
        "",
        "| Assets | Python p50 | Go core p50 | Go E2E p50 | Core speedup | E2E speedup |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for row in result["results"]:
        lines.append(
            "| {assets} | {python:.3f} ms | {go_core:.3f} ms | {go_e2e:.3f} ms | "
            "{core:.2f}x | {e2e:.2f}x |".format(
                assets=row["assets"],
                python=row["python_graph_detect"]["p50_ms"],
                go_core=row["go_graph_detect"]["p50_ms"],
                go_e2e=row["go_end_to_end"]["p50_ms"],
                core=row["go_core_speedup_vs_python_p50"],
                e2e=row["go_e2e_speedup_vs_python_p50"],
            )
        )
    lines.extend((
        "",
        "Go core excludes evidence/snapshot preparation. Go E2E includes that "
        "same Python preparation plus subprocess transport, which is the real "
        "production choice. Python heap peak is measured with tracemalloc; it "
        "is not comparable to Go process RSS.",
    ))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=[250, 500, 1_000, 2_000, 4_000])
    parser.add_argument("--runs", type=int, default=9)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    args = parser.parse_args()
    if args.runs < 3 or any(size < 1 for size in args.sizes):
        raise SystemExit("--runs must be at least 3 and every --sizes value must be positive")

    os.environ[graph_engine.ENV_BINARY] = _binary()
    result = {
        "fixture": "exact_iam_s3_grants",
        "python": sys.version,
        "platform": platform.platform(),
        "go_binary": os.environ[graph_engine.ENV_BINARY],
        "runs": args.runs,
        "results": [run_population(size, args.runs) for size in args.sizes],
    }
    rendered = markdown(result)
    print(rendered)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
