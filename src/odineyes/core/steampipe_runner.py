"""Run the AWS compliance benchmarks via Powerpipe (data from Steampipe).

As of aws-compliance mod v1.13.0 the benchmarks are **Powerpipe** mods (``mod.pp``),
and ``steampipe check`` is deprecated. So the stack is:

  * Steampipe runs as a **service** (Postgres FDW exposing the AWS API as tables).
  * Powerpipe runs the benchmarks against it: ``powerpipe benchmark run <id>
    --output json`` from the mod directory.

We map Powerpipe's JSON into the exact shape the Compliance tab consumes
(``compliance[fw] = {name, version, score, passing, total, controls[]}``), so no
frontend change is needed. Design: docs/STEAMPIPE_COMPLIANCE_DESIGN.md.

Why subprocess (not querying the DB directly): ``_parse`` is a pure function we
can unit-test offline (the Windows dev box has no binary). ``powerpipe benchmark
run`` exits non-zero when controls alarm — so we parse stdout, never gate on the
exit code.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

# Framework request-id -> powerpipe/steampipe benchmark id (bare; namespaced when run).
BENCHMARKS: dict[str, str] = {
    "CIS": "cis_v300",
    "PCI-DSS": "pci_dss_v321",
    "NIST": "nist_800_53_rev_5",
    "SOC2": "soc_2",
    "FSBP": "foundational_security",
}

# Display name/version per framework (UI only).
FRAMEWORK_META: dict[str, tuple[str, str | None]] = {
    "CIS": ("CIS AWS Foundations Benchmark", "v3.0.0"),
    "PCI-DSS": ("PCI DSS", "v3.2.1"),
    "NIST": ("NIST 800-53", "rev5"),
    "SOC2": ("SOC 2", None),
    "FSBP": ("AWS Foundational Security Best Practices", None),
}

_BENCH_PREFIX = "aws_compliance.benchmark."
# Where the mod is cloned (install-steampipe.sh). Powerpipe runs `benchmark run`
# from here so it loads the local mod.
_MOD_DIR = os.environ.get("ODINEYES_STEAMPIPE_MOD_DIR", "/opt/steampipe/aws-compliance")
_TIMEOUT = int(os.environ.get("ODINEYES_STEAMPIPE_TIMEOUT", "600"))  # per benchmark


def available() -> bool:
    """True if both powerpipe and steampipe are on PATH."""
    return shutil.which("powerpipe") is not None and shutil.which("steampipe") is not None


def run(frameworks: list[str], region: str | None, profile: str | None,
        timeout: int = _TIMEOUT) -> dict:
    """Run all requested benchmarks via Powerpipe; return ``{compliance, findings}``.

    All benchmarks go in **one** ``powerpipe benchmark run`` invocation: the
    frameworks share most underlying queries and Powerpipe runs each shared query
    once per invocation, so 5 frameworks cost ~1.5x a single one instead of 5x
    (measured: CIS 70s, CIS+SOC2 80s). ``--output json`` emits one JSON document
    per benchmark, concatenated — we stream-parse them.

    Raises on no usable output so the caller can fall back to the Python engine.
    """
    keys = [f for f in frameworks if f in BENCHMARKS]
    if not keys:
        raise ValueError(f"no benchmarks for frameworks={frameworks!r}")

    _ensure_service(region, profile)
    out = _run_benchmarks([BENCHMARKS[k] for k in keys], region, profile, timeout)

    compliance: dict[str, Any] = {}
    findings: list[dict] = []
    for doc in _iter_json(out):
        compliance.update(_parse(doc, keys))
        findings.extend(_findings(doc))

    if not compliance:
        raise RuntimeError("powerpipe produced no scored frameworks")
    return {"compliance": compliance, "findings": findings}


def _ensure_service(region: str | None, profile: str | None) -> None:
    """Start the steampipe service if it isn't already (idempotent)."""
    env = _env(region, profile)
    try:
        subprocess.run(["steampipe", "service", "start"],  # noqa: S603/S607 fixed args
                       capture_output=True, text=True, timeout=120, env=env)
    except Exception as e:
        logger.warning("steampipe service start failed (may already be up): %s", e)


def _run_benchmarks(bench_ids: list[str], region: str | None, profile: str | None,
                    timeout: int) -> str:
    """One powerpipe invocation for all benchmarks. Returns raw stdout (one JSON
    document per benchmark, concatenated). powerpipe exits non-zero when controls
    alarm — so we parse stdout, never gate on the exit code."""
    args = ["powerpipe", "benchmark", "run"]
    args += [f"{_BENCH_PREFIX}{b}" for b in bench_ids]
    args += ["--output", "json"]
    cwd = _MOD_DIR if os.path.isdir(_MOD_DIR) else None
    proc = subprocess.run(  # noqa: S603 — args are a fixed list, ids allow-listed
        args, capture_output=True, text=True, timeout=timeout, env=_env(region, profile), cwd=cwd,
    )
    out = (proc.stdout or "").strip()
    if not out:
        raise RuntimeError(
            f"powerpipe produced no JSON (exit={proc.returncode}): {(proc.stderr or '')[:300]}"
        )
    return out


def _iter_json(text: str):
    """Yield each JSON document from a stream of concatenated objects
    (``powerpipe benchmark run a b`` emits one root per benchmark)."""
    dec = json.JSONDecoder()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        obj, end = dec.raw_decode(text, i)  # JSONDecodeError -> caller falls back
        yield obj
        i = end


def _env(region: str | None, profile: str | None) -> dict:
    env = os.environ.copy()
    if profile:
        env["AWS_PROFILE"] = profile
    if region:
        env["AWS_REGION"] = region
    return env


# ── pure mapping (offline-testable) ──────────────────────────────

def _parse(raw: dict, requested: list[str]) -> dict:
    """Powerpipe benchmark JSON -> {fw: {name, version, score, passing, total, controls}}.

    ``raw`` is one ``powerpipe benchmark run`` root: a wrapper whose ``groups``
    hold the benchmark group(s)."""
    by_bench = {bid: fw for fw, bid in BENCHMARKS.items()}
    out: dict[str, Any] = {}
    for group in raw.get("groups", []) or []:
        fw = by_bench.get(_strip(group.get("group_id", ""), _BENCH_PREFIX))
        if fw is None or fw not in requested:
            continue
        controls: list[dict] = []
        _collect(group, group.get("title", fw), controls)
        passing = sum(1 for c in controls if c["state"] == "pass")
        total = sum(1 for c in controls if c["state"] in ("pass", "fail"))
        name, version = FRAMEWORK_META.get(fw, (fw, None))
        out[fw] = {
            "name": name,
            "version": version,
            "score": round(passing / total * 100) if total else 0,
            "passing": passing,
            "total": total,
            "controls": controls,
        }
    return out


def _collect(group: dict, section: str, acc: list[dict]) -> None:
    """Walk a benchmark group to its leaf controls; section = parent group title."""
    for sub in group.get("groups", []) or []:
        _collect(sub, sub.get("title", section), acc)
    for ctl in group.get("controls", []) or []:
        c = _counts(ctl)
        if c["alarm"] or c["error"]:
            state = "fail"
        elif c["ok"]:
            state = "pass"
        else:
            state = "not_assessed"
        acc.append({
            "id": _ctl_id(ctl.get("control_id", "")),
            "title": ctl.get("title", ""),
            "section": section,
            "state": state,
        })


def _findings(raw: dict) -> list[dict]:
    """Every alarm/error result -> a fail finding (the tab's findings come from
    the same source)."""
    out: list[dict] = []

    def walk(g: dict) -> None:
        for sub in g.get("groups", []) or []:
            walk(sub)
        for ctl in g.get("controls", []) or []:
            cid = _ctl_id(ctl.get("control_id", ""))
            sev = ctl.get("severity") or (ctl.get("tags") or {}).get("severity") or "medium"
            for r in ctl.get("results", []) or []:
                if r.get("status") in ("alarm", "error"):
                    out.append({
                        "control_id": cid,
                        "resource": r.get("resource"),
                        "reason": r.get("reason"),
                        "severity": sev,
                        "state": "fail",
                        "region": _dim(r, "region"),
                        "account": _dim(r, "account_id"),
                    })

    for g in raw.get("groups", []) or []:
        walk(g)
    return out


def _counts(ctl: dict) -> dict:
    """Status counts for one control. Powerpipe nests group summaries under
    ``status`` but control summaries are flat; fall back to counting ``results``."""
    keys = ("alarm", "ok", "error", "info", "skip")
    s = ctl.get("summary") or {}
    if "status" in s and isinstance(s["status"], dict):
        s = s["status"]
    if any(k in s for k in keys):
        return {k: int(s.get(k, 0) or 0) for k in keys}
    c = dict.fromkeys(keys, 0)
    for r in ctl.get("results", []) or []:
        st = r.get("status")
        if st in c:
            c[st] += 1
    return c


def _dim(result: dict, key: str) -> str | None:
    for d in result.get("dimensions", []) or []:
        if d.get("key") == key:
            return d.get("value")
    return None


def _ctl_id(s: str) -> str:
    for p in ("aws_compliance.", "control."):
        if s.startswith(p):
            s = s[len(p):]
    return s


def _strip(s: str, prefix: str) -> str:
    return s[len(prefix):] if s.startswith(prefix) else s


if __name__ == "__main__":
    # Offline self-check: a tiny powerpipe-shaped tree maps to the contract.
    fixture = {
        "group_id": "aws_compliance.benchmark.cis_v300",  # wrapper root
        "title": "AWS CIS v3.0.0",
        "summary": {"status": {"alarm": 1, "ok": 1, "info": 0, "skip": 0, "error": 1}},
        "groups": [{
            "group_id": "aws_compliance.benchmark.cis_v300",
            "title": "AWS CIS v3.0.0",
            "summary": {"status": {"alarm": 1, "ok": 1, "info": 0, "skip": 0, "error": 1}},
            "groups": [{
                "group_id": "aws_compliance.benchmark.cis_v300_1",
                "title": "1 IAM",
                "controls": [
                    {"control_id": "control.cis_v300_1_1", "title": "Contact details",
                     "severity": "low",
                     "summary": {"alarm": 1, "ok": 0, "error": 0, "info": 0, "skip": 0},
                     "results": [{"status": "alarm", "resource": "a", "reason": "bad",
                                  "dimensions": [{"key": "account_id", "value": "111"},
                                                 {"key": "region", "value": "us-east-1"}]}]},
                    {"control_id": "control.cis_v300_1_2", "title": "MFA root",
                     "summary": {"alarm": 0, "ok": 3, "error": 0, "info": 0, "skip": 0},
                     "results": [{"status": "ok", "resource": "root"}]},
                    {"control_id": "control.cis_v300_1_3", "title": "Manual review",
                     "results": [{"status": "skip", "resource": "x"}]},
                    {"control_id": "control.cis_v300_1_4", "title": "Errored control",
                     "summary": {"alarm": 0, "ok": 0, "error": 1, "info": 0, "skip": 0},
                     "results": [{"status": "error", "resource": "e", "reason": "denied"}]},
                ],
            }],
        }],
    }
    comp = _parse(fixture, ["CIS"])
    cis = comp["CIS"]
    assert cis["name"] == "CIS AWS Foundations Benchmark" and cis["version"] == "v3.0.0"
    assert cis["passing"] == 1 and cis["total"] == 3, cis           # pass:1_2 fail:1_1,1_4 na:1_3
    assert cis["score"] == 33, cis
    states = {c["id"]: c["state"] for c in cis["controls"]}
    assert states == {"cis_v300_1_1": "fail", "cis_v300_1_2": "pass",
                      "cis_v300_1_3": "not_assessed", "cis_v300_1_4": "fail"}, states
    assert all(c["section"] == "1 IAM" for c in cis["controls"])
    finds = _findings(fixture)
    assert {f["control_id"] for f in finds} == {"cis_v300_1_1", "cis_v300_1_4"}, finds
    a = next(f for f in finds if f["control_id"] == "cis_v300_1_1")
    assert a["account"] == "111" and a["region"] == "us-east-1"
    print("steampipe_runner (powerpipe) self-check OK: mapping + findings correct")
