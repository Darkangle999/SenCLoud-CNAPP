"""Checkov integration for IaC scanning (gap analysis §4.8 — shift-left).

Odineyes ships its own small in-tree IaC scanner (`iac/scanner.py`). Checkov
(bridgecrewio/checkov) is the mature, broad option — thousands of policies
across Terraform, CloudFormation, Kubernetes, Helm, ARM, Dockerfile, etc.

This wraps the `checkov` CLI as a subprocess (same pattern as
`steampipe_runner`/Trivy) and normalizes its JSON into the same finding dict
shape as `iac/scanner.scan()`, so the API and UI consume one format regardless
of engine. Checkov is an optional dependency — `available()` is False when the
binary isn't installed, and callers fall back to the in-tree scanner.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Optional

logger = logging.getLogger(__name__)

_SEV = {"critical", "high", "medium", "low"}
# Extension → checkov framework, for scanning a single pasted file.
_EXT_HINT = {
    ".tf": "terraform", ".json": "cloudformation", ".yaml": "cloudformation",
    ".yml": "cloudformation", ".template": "cloudformation",
}


def _checkov_cmd() -> Optional[list[str]]:
    """The invocation for checkov, or None if not installed. Prefers the console
    script, falls back to `python -m checkov`."""
    exe = shutil.which("checkov")
    if exe:
        return [exe]
    try:
        subprocess.run([sys.executable, "-m", "checkov", "--version"],
                       capture_output=True, timeout=20, check=True)
        return [sys.executable, "-m", "checkov"]
    except Exception:  # noqa: BLE001 — not installed / not importable
        return None


def available() -> bool:
    return _checkov_cmd() is not None


def _normalize(failed: dict[str, Any], framework: str) -> dict[str, Any]:
    """One checkov failed_check → the finding dict shape `iac/scanner` emits."""
    sev = str(failed.get("severity") or "").lower()   # OSS often has no severity
    resource = failed.get("resource") or ""
    return {
        "check_id": failed.get("check_id") or failed.get("bc_check_id") or "",
        "title": failed.get("check_name") or "",
        "severity": sev if sev in _SEV else "medium",
        "resource": resource,
        "resource_type": resource.split(".")[0] if "." in resource else framework,
        "why": failed.get("check_name") or "",
        "remediation": failed.get("guideline") or "",
        "compliance": {},
        "related": [],
        "engine": "checkov",
        "file": failed.get("file_path"),
        "lines": failed.get("file_line_range"),
    }


def parse_output(stdout: str) -> list[dict[str, Any]]:
    """Normalize checkov `-o json` stdout (a single object, or a list of
    per-framework objects) into finding dicts. Pure — the unit-testable core."""
    data = json.loads(stdout)
    blocks = data if isinstance(data, list) else [data]
    findings: list[dict[str, Any]] = []
    for b in blocks:
        if not isinstance(b, dict):
            continue
        fw = b.get("check_type") or "iac"
        for fc in (b.get("results") or {}).get("failed_checks", []):
            findings.append(_normalize(fc, fw))
    return findings


def _result(findings: list[dict[str, Any]], fmt: Optional[str]) -> dict[str, Any]:
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (rank.get(f["severity"], 9), f["check_id"], f["resource"]))
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {
        "engine": "checkov",
        "format": fmt,
        "findings": findings,
        "total": len(findings),
        "by_severity": by_sev,
    }


def _run(args: list[str], fmt: Optional[str]) -> dict[str, Any]:
    cmd = _checkov_cmd()
    if cmd is None:
        raise RuntimeError("checkov is not installed")
    # checkov exits 1 when it finds failures — that's success for us, not an error.
    proc = subprocess.run(cmd + args + ["-o", "json", "--compact", "--quiet"],
                          capture_output=True, text=True, timeout=600)
    out = proc.stdout.strip()
    if not out:
        raise RuntimeError(f"checkov produced no output (exit {proc.returncode}): {proc.stderr[:400]}")
    return _result(parse_output(out), fmt)


def scan_dir(path: str) -> dict[str, Any]:
    """Scan a directory tree of IaC (the CI/repo case)."""
    return _run(["-d", path], None)


def scan_content(content: str, filename: Optional[str] = None) -> dict[str, Any]:
    """Scan a single pasted template (the API case). Writes to a temp file with a
    best-guess extension so checkov picks the right framework parser."""
    ext = os.path.splitext(filename or "")[1].lower()
    if ext not in _EXT_HINT:
        ext = ".tf" if "resource \"" in content else ".json"
    with tempfile.TemporaryDirectory() as d:
        fp = os.path.join(d, f"iac{ext}")
        with open(fp, "w", encoding="utf-8") as fh:
            fh.write(content)
        return _run(["-f", fp], _EXT_HINT.get(ext))


if __name__ == "__main__":
    # Offline self-check of the pure parser against a sample checkov JSON payload
    # (no checkov install, no subprocess).
    sample = json.dumps({
        "check_type": "terraform",
        "results": {"failed_checks": [
            {"check_id": "CKV_AWS_18", "check_name": "Ensure S3 has access logging",
             "resource": "aws_s3_bucket.data", "severity": "LOW",
             "file_path": "/main.tf", "file_line_range": [1, 5],
             "guideline": "https://docs.bridgecrew.io/CKV_AWS_18"},
            {"check_id": "CKV_AWS_20", "check_name": "Ensure S3 is not public",
             "resource": "aws_s3_bucket.data", "file_path": "/main.tf"},  # no severity
        ]},
    })
    fs = parse_output(sample)
    assert len(fs) == 2, fs
    assert fs[0]["engine"] == "checkov"
    assert fs[0]["check_id"] == "CKV_AWS_18" and fs[0]["severity"] == "low"
    assert fs[1]["severity"] == "medium", "missing severity must default to medium"
    assert fs[1]["resource_type"] == "aws_s3_bucket"
    res = _result(fs, "terraform")
    assert res["total"] == 2 and res["by_severity"] == {"low": 1, "medium": 1}
    print("checkov_runner self-check OK")
