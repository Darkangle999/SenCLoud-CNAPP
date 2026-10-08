"""Run CloudTrail log detections via Tailpipe + Powerpipe (Turbot's
tailpipe-mod-aws-cloudtrail-log-detections). Same shape as steampipe_runner.py,
same Powerpipe JSON tree, different engine underneath:

  * Steampipe = live FDW over the AWS API (point-in-time config posture).
  * Tailpipe   = CloudTrail *log* ingestion into DuckDB (event history) — needs
    a collect step before each run, and needs the client's role to read the
    CloudTrail S3 bucket (a materially different, more sensitive grant than the
    read-only Describe/List calls the rest of the collector uses).

Output maps to RuntimeEvent rows (append-only threat signal, same table the
eBPF sensor writes to), not the Compliance tab — these are event detections
(MITRE ATT&CK), not CIS control pass/fail.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import Any

from odineyes.core.steampipe_runner import _dim, _iter_json

logger = logging.getLogger(__name__)

_MOD_DIR = os.environ.get("ODINEYES_TAILPIPE_MOD_DIR", "/opt/tailpipe/aws-cloudtrail-log-detections")
_BENCHMARK = "aws_cloudtrail_log_detections.benchmark.mitre_attack_v161"
_PARTITION = os.environ.get("ODINEYES_TAILPIPE_PARTITION", "aws_cloudtrail_log.cloudtrail_log")
_TIMEOUT = int(os.environ.get("ODINEYES_TAILPIPE_TIMEOUT", "600"))


def available() -> bool:
    """True if both tailpipe and powerpipe are on PATH."""
    return shutil.which("tailpipe") is not None and shutil.which("powerpipe") is not None


def run(region: str | None, profile: str | None, since: str = "24h",
        timeout: int = _TIMEOUT) -> list[dict]:
    """Collect the last ``since`` window of CloudTrail logs, run the MITRE
    ATT&CK detection benchmark, return a list of RuntimeEvent-shaped dicts.

    Raises on no usable output — caller decides whether that's fatal or just
    "nothing to report this cycle" (distinguish via ``available()`` first)."""
    env = _env(region, profile)
    _collect(since, env, timeout)
    out = _run_benchmark(env, timeout)
    events: list[dict] = []
    for doc in _iter_json(out):
        events.extend(_to_events(doc))
    return events


def _collect(since: str, env: dict, timeout: int) -> None:
    """Ingest CloudTrail logs into Tailpipe's local DuckDB. Requires the
    client's assumed role to have s3:GetObject on the CloudTrail log bucket —
    call out to the operator before enabling this, it's not part of the
    default read-only Describe/List grant."""
    args = ["tailpipe", "collect", _PARTITION, "--from", since]
    proc = subprocess.run(  # noqa: S603 — fixed args, since is a controlled duration string
        args, capture_output=True, text=True, timeout=timeout, env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"tailpipe collect failed (exit={proc.returncode}): {(proc.stderr or '')[:300]}")


def _run_benchmark(env: dict, timeout: int) -> str:
    args = ["powerpipe", "benchmark", "run", _BENCHMARK, "--output", "json"]
    cwd = _MOD_DIR if os.path.isdir(_MOD_DIR) else None
    proc = subprocess.run(  # noqa: S603 — fixed args
        args, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd,
    )
    out = (proc.stdout or "").strip()
    if not out:
        raise RuntimeError(
            f"powerpipe produced no JSON (exit={proc.returncode}): {(proc.stderr or '')[:300]}"
        )
    return out


def _env(region: str | None, profile: str | None) -> dict:
    env = os.environ.copy()
    if profile:
        env["AWS_PROFILE"] = profile
    if region:
        env["AWS_REGION"] = region
    return env


# ── pure mapping (offline-testable) ──────────────────────────────

def _to_events(raw: dict) -> list[dict]:
    """Powerpipe detection-benchmark JSON -> RuntimeEvent-shaped dicts.
    Every alarm result is one event; ``ok``/``skip`` produce nothing (there's
    no "control passed" concept worth persisting for event detections)."""
    out: list[dict] = []

    def walk(g: dict) -> None:
        for sub in g.get("groups", []) or []:
            walk(sub)
        for ctl in g.get("controls", []) or []:
            tags = ctl.get("tags") or {}
            severity = ctl.get("severity") or tags.get("severity") or "medium"
            technique = tags.get("mitre_attack_ids") or tags.get("mitre_attack_id")
            for r in ctl.get("results", []) or []:
                if r.get("status") != "alarm":
                    continue
                out.append({
                    "event_type": f"cloudtrail:{ctl.get('control_id', 'unknown')}",
                    "severity": _map_severity(severity),
                    "resource_id": r.get("resource"),
                    "summary": r.get("reason") or ctl.get("title", ""),
                    "region": _dim(r, "region"),
                    "account": _dim(r, "account_id"),
                    "mitre_attack_id": technique,
                })

    for g in raw.get("groups", []) or []:
        walk(g)
    return out


def _map_severity(s: Any) -> str:
    s = str(s or "medium").lower()
    return s if s in ("critical", "high", "medium", "low", "info") else "medium"


if __name__ == "__main__":
    # Offline self-check: a tiny detection-mod-shaped tree maps to RuntimeEvent dicts.
    fixture = {
        "groups": [{
            "group_id": "aws_cloudtrail_log_detections.benchmark.mitre_attack_v161",
            "title": "MITRE ATT&CK",
            "groups": [{
                "group_id": "aws_cloudtrail_log_detections.benchmark.initial_access",
                "title": "Initial Access",
                "controls": [{
                    "control_id": "detect_console_login_without_mfa",
                    "title": "Console logins without MFA",
                    "severity": "high",
                    "tags": {"mitre_attack_ids": "T1078"},
                    "results": [
                        {"status": "alarm", "resource": "arn:aws:iam::111:user/bob",
                         "reason": "console login without MFA",
                         "dimensions": [{"key": "account_id", "value": "111"},
                                        {"key": "region", "value": "us-east-1"}]},
                        {"status": "ok", "resource": "arn:aws:iam::111:user/alice"},
                    ],
                }],
            }],
        }],
    }
    events = _to_events(fixture)
    assert len(events) == 1, events
    e = events[0]
    assert e["event_type"] == "cloudtrail:detect_console_login_without_mfa"
    assert e["severity"] == "high" and e["mitre_attack_id"] == "T1078"
    assert e["resource_id"] == "arn:aws:iam::111:user/bob"
    assert e["account"] == "111" and e["region"] == "us-east-1"
    print("tailpipe_runner self-check OK: alarm -> RuntimeEvent mapping correct")
