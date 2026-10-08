"""Trivy integration for IaC scanning — the shift-left alternative to Checkov.

Odineyes ships its own small in-tree IaC scanner (`iac/scanner.py`) and wraps
Checkov (`iac/checkov_runner.py`). Trivy (aquasecurity/trivy) is the other
mature option: its ``trivy config`` subcommand runs built-in misconfiguration
policies across Terraform, CloudFormation, Kubernetes, Helm, Dockerfile and
ARM, with no external DB download needed (the policies are embedded in the
binary).

This wraps the ``trivy config`` CLI as a subprocess (same pattern as
`checkov_runner`) and normalizes its JSON into the same finding dict shape as
`iac/scanner.scan()`, so the API and UI consume one format regardless of
engine. Trivy is an optional dependency — `available()` is False when the
binary isn't installed, and callers fall back to the in-tree scanner.

Trivy `config` differs from Checkov: it exits 0 even when findings are
present (use `--exit-code` to change that), and emits a JSON array of per-file
results, each carrying a ``Misconfigurations`` list whose FAIL entries carry
``ID``, ``Title``, ``Description``, ``Resolution`` and ``Causes`` (resource
address + file/line).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any, Optional

logger = logging.getLogger(__name__)

_SEV = {"critical", "high", "medium", "low"}
# Extension → trivy framework hint. trivy config auto-detects by content, so
# this only guides the temp-file suffix for a single pasted template.
_EXT_HINT = {
    ".tf": "terraform", ".json": "cloudformation", ".yaml": "cloudformation",
    ".yml": "cloudformation", ".template": "cloudformation",
}


def available() -> bool:
    """Whether the trivy binary exists on PATH (the `config` engine is part
    of the same binary, so a present binary is sufficient)."""
    return shutil.which("trivy") is not None


def _base_cmd() -> list[str]:
    return ["trivy", "config", "--quiet", "--format", "json"]


def _normalize(misconfig: dict[str, Any], target: str, fw: str) -> dict[str, Any]:
    """One trivy FAIL misconfiguration → the finding dict shape `iac/scanner`
    emits (plus the trivy engine marker and file/line provenance)."""
    sev = str(misconfig.get("Severity") or "").lower()
    cause = (misconfig.get("Causes") or [{}])[0] or {}
    resource = str(cause.get("Resource") or "")
    occurrences = cause.get("Occurrences") or []
    occ = (occurrences[0] if occurrences else {}) or {}
    line = occ.get("LineNumber")
    file_path = occ.get("Filename") or target
    lines = [line] if line is not None else []

    # A misconfiguration can fail on a later cause too; if the first occurrence
    # has no line, surface the first occurrence that does.
    for o in occurrences[1:]:
        if o.get("LineNumber") is not None and not lines:
            first = o.get("Filename") or file_path
            if first:
                file_path = first
            lines = [o.get("LineNumber")]

    return {
        "check_id": misconfig.get("ID") or "",
        "title": misconfig.get("Title") or "",
        "severity": sev if sev in _SEV else "medium",
        "resource": resource,
        "resource_type": resource.split(".")[0] if "." in resource else (misconfig.get("Type") or fw or "iac"),
        "why": misconfig.get("Description") or misconfig.get("Message") or "",
        "remediation": misconfig.get("Resolution") or "",
        "compliance": {},
        "related": [],
        "engine": "trivy",
        "file": file_path,
        "lines": lines,
    }


def parse_output(stdout: str) -> list[dict[str, Any]]:
    """Normalize `trivy config --format json` stdout (an array of per-file
    results) into finding dicts. Only FAIL misconfigurations are findings.
    Pure — the unit-testable core."""
    data = json.loads(stdout)
    results = data if isinstance(data, list) else [data]
    findings: list[dict[str, Any]] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        fw = r.get("Type") or "iac"
        target = r.get("Target") or ""
        for mc in r.get("Misconfigurations") or []:
            if not isinstance(mc, dict):
                continue
            status = mc.get("Status")
            if status and str(status).upper() != "FAIL":
                continue
            findings.append(_normalize(mc, target, fw))
    return findings


def _result(findings: list[dict[str, Any]], fmt: Optional[str]) -> dict[str, Any]:
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (rank.get(f["severity"], 9), f["check_id"], f["resource"]))
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {
        "engine": "trivy",
        "format": fmt,
        "findings": findings,
        "total": len(findings),
        "by_severity": by_sev,
    }


def _run(args: list[str], fmt: Optional[str]) -> dict[str, Any]:
    if not available():
        raise RuntimeError("trivy is not installed")
    # trivy config exits 0 even with findings, so any stdout is a valid result.
    proc = subprocess.run(_base_cmd() + args, capture_output=True, text=True, timeout=600)
    out = proc.stdout.strip()
    if not out:
        raise RuntimeError(f"trivy produced no output (exit {proc.returncode}): {proc.stderr[:400]}")
    try:
        return _result(parse_output(out), fmt)
    except json.JSONDecodeError as e:  # pragma: no cover - defensive
        raise RuntimeError(f"trivy JSON parse failed (exit {proc.returncode}): {e}") from e


def scan_dir(path: str) -> dict[str, Any]:
    """Scan a directory tree of IaC (the CI/repo case)."""
    return _run([path], None)


def scan_content(content: str, filename: Optional[str] = None) -> dict[str, Any]:
    """Scan a single pasted template (the API case). Writes to a temp file with
    a best-guess extension so trivy's auto-detect picks the framework."""
    ext = os.path.splitext(filename or "")[1].lower()
    if ext not in _EXT_HINT:
        ext = ".tf" if 'resource "' in content else ".json"
    with tempfile.TemporaryDirectory() as d:
        fp = os.path.join(d, f"iac{ext}")
        with open(fp, "w", encoding="utf-8") as fh:
            fh.write(content)
        return _run([fp], _EXT_HINT.get(ext))


if __name__ == "__main__":
    # Offline self-check of the pure parser against a sample trivy config JSON
    # payload (no trivy install, no subprocess).
    sample = json.dumps([
        {
            "Target": "/main.tf",
            "Class": "config",
            "Type": "terraform",
            "Misconfigurations": [
                {
                    "Type": "Terraform",
                    "ID": "AVD-AWS-0086",
                    "Title": "S3 bucket has public ACL",
                    "Description": "Bucket ACL grants public access.",
                    "Resolution": "Remove the public ACL.",
                    "Severity": "CRITICAL",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0086",
                    "Status": "FAIL",
                    "Causes": [
                        {"Resource": "aws_s3_bucket.data",
                         "Occurrences": [{"Filename": "/main.tf", "LineNumber": 4}]},
                    ],
                },
                {
                    "Type": "Terraform",
                    "ID": "AVD-AWS-0020",
                    "Title": "S3 logs",
                    "Description": "Buckets should have logging.",
                    "Severity": "MEDIUM",
                    "Status": "PASS",  # not a finding
                    "Causes": [{"Resource": "aws_s3_bucket.logs", "Occurrences": []}],
                },
            ],
        },
    ])
    fs = parse_output(sample)
    assert len(fs) == 1, fs
    assert fs[0]["engine"] == "trivy"
    assert fs[0]["check_id"] == "AVD-AWS-0086" and fs[0]["severity"] == "critical"
    assert fs[0]["resource"] == "aws_s3_bucket.data"
    assert fs[0]["resource_type"] == "aws_s3_bucket"
    assert fs[0]["file"] == "/main.tf" and fs[0]["lines"] == [4]
    res = _result(fs, "terraform")
    assert res["total"] == 1 and res["by_severity"] == {"critical": 1}
    print("trivy_runner self-check OK")
