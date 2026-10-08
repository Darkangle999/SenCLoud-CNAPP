#!/usr/bin/env python3
"""Ultimate end-to-end test: does every plan module reflect in the website?

Plants vulnerable resources, triggers a scan through the website's OWN API
(POST /api/inventory/scan-all), then reads back the exact endpoints the React
app consumes — through the vite proxy when it's up — and asserts each module of
the plan actually surfaces. Proves the full chain browser → proxy → backend →
DB → engine, not just the database.

    python scripts/e2e_website_test.py            # verify current account against the website
    python scripts/e2e_website_test.py --deploy    # plant the lab first, then verify
    python scripts/e2e_website_test.py --deploy --with-rds   # include the costly RDS path
    python scripts/e2e_website_test.py --destroy   # tear the lab down

Modules checked (per plan): inventory (P1), findings/rules (P2), attack-paths +
risk scoring (P3-4), compliance/CSPM, and fleet orchestration. Multi-cloud is
reported as skipped unless azure/gcp accounts are registered.

Exit code is non-zero if any module fails to reflect.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, "src")

import redteam_lab as lab  # noqa: E402  (resource deploy/destroy + expected maps)

ACCOUNT_REGION = "us-east-1"
# Try the vite proxy first (proves the browser's real path), fall back to backend.
BASES = ["http://localhost:5173", "http://localhost:8000"]


# ── HTTP ────────────────────────────────────────────────────────

def _req(method, base, path, body=None, timeout=600):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"} if data else {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read() or b"{}")


def pick_base():
    for b in BASES:
        try:
            urllib.request.urlopen(b + "/api/inventory/summary", timeout=5)
            return b
        except urllib.error.HTTPError:
            return b                      # reachable, just returned an error code
        except urllib.error.URLError:
            continue
    print("  No server reachable on :5173 or :8000. Start backend + (optionally) vite:")
    print("    PYTHONPATH=src uvicorn odineyes.api.server:app --port 8000")
    print("    (cd frontend && npm run dev)")
    sys.exit(2)


# ── module checks ───────────────────────────────────────────────

class Report:
    def __init__(self):
        self.rows = []           # (module, ok, detail)

    def add(self, module, ok, detail):
        self.rows.append((module, ok, detail))

    def render(self):
        print("\n  ── Website reflection — module coverage ──────────────────────")
        for module, ok, detail in self.rows:
            print(f"   {'PASS' if ok else 'MISS'}  {module:22} {detail}")
        passed = sum(1 for _, ok, _ in self.rows if ok)
        print("  ──────────────────────────────────────────────────────────────")
        print(f"   {passed}/{len(self.rows)} modules reflect in the website"
              + ("   ✅" if passed == len(self.rows) else "   ⚠ gaps above"))
        return passed == len(self.rows)


def verify(base, region, deployed, deployed_rds, deployed_redshift):
    from odineyes.inventory import rules as rules_mod
    from odineyes.inventory import issues as issues_mod

    rep = Report()
    print(f"  Verifying against {base}\n")

    # 0. Fleet orchestration — trigger the scan the way the website would.
    print("  POST /api/inventory/scan-all  (collect → persist → rules → paths, live AWS)…")
    try:
        _, scan = _req("POST", base, "/api/inventory/scan-all",
                       {"provider": "aws", "region": region, "max_workers": 4})
        completed = scan.get("completed", 0)
        rep.add("fleet orchestration", completed >= 1,
                f"{completed}/{scan.get('accounts',0)} account(s) completed, {scan.get('failed',0)} failed")
    except Exception as e:  # noqa: BLE001
        rep.add("fleet orchestration", False, f"scan-all failed: {e}")
        scan = {}

    # 1. Inventory (P1) — assets ingested + typed.
    _, summ = _req("GET", base, "/api/inventory/summary")
    by_type = summ.get("by_type", {})
    want_types = {"aws.ec2.instance", "aws.ec2.security_group", "aws.iam.role", "aws.s3.bucket"}
    present = want_types & set(by_type)
    rep.add("inventory (P1)", summ.get("total_assets", 0) > 0 and len(present) >= 3,
            f"{summ.get('total_assets',0)} assets, {len(by_type)} types, public={summ.get('public_assets',0)}")

    # 2. Findings / rules (P2) — which rules fired vs the full catalogue.
    catalogue_rules = set(rules_mod.COMPLIANCE)
    _, f = _req("GET", base, "/api/inventory/findings?status=open")
    fired_rules = {x["rule_id"] for x in f.get("items", [])}
    rep.add("findings / rules (P2)", len(fired_rules) > 0,
            f"{f.get('total',0)} open · rules firing: {len(fired_rules)}/{len(catalogue_rules)} "
            f"({', '.join(sorted(fired_rules)) or 'none'})")

    # 3. Attack paths / issues (P3-4).
    catalogue_issues = set(issues_mod.COMPLIANCE)
    _, iss = _req("GET", base, "/api/inventory/issues?status=open")
    _, isum = _req("GET", base, "/api/inventory/issues/summary")
    fired_issues = {x["issue_type"] for x in iss.get("items", [])}
    rep.add("attack paths (P3-4)", len(fired_issues) > 0,
            f"{iss.get('total',0)} open · types: {len(fired_issues)}/{len(catalogue_issues)} "
            f"({', '.join(sorted(fired_issues)) or 'none'})")

    # 4. Risk scoring — scores populated + ranked (not all equal).
    _, page = _req("GET", base, "/api/inventory?page_size=200")
    scores = sorted({a["risk_score"] for a in page.get("items", []) if a.get("risk_score", 0) > 0})
    rep.add("risk scoring (P3-4)", len(scores) >= 2 and isum.get("max_risk", 0) > 0,
            f"max={isum.get('max_risk',0)} · {len(scores)} distinct non-zero tiers {scores[:6]}")

    # 5. Compliance / CSPM — framework scores from the live engine.
    try:
        _, c = _req("GET", base, f"/api/live/cspm?region={region}", timeout=180)
        fws = c.get("compliance", {})
        scored = [f"{k} {v['score']}%" for k, v in fws.items()]
        rep.add("compliance / CSPM", len(fws) > 0,
                f"pass_rate={c.get('summary',{}).get('pass_rate')}% · " + ", ".join(scored))
    except Exception as e:  # noqa: BLE001
        rep.add("compliance / CSPM", False, f"/api/live/cspm failed: {e} (needs AWS creds)")

    # 6. Per-detection reflection of the planted lab — only meaningful when the
    # lab was actually deployed this run (otherwise those resources aren't there).
    expected = {}
    if deployed:
        expected = dict(lab.EXPECTED)
        if deployed_rds:
            expected |= lab.EXPECTED_RDS
        if deployed_redshift:
            expected |= lab.EXPECTED_REDSHIFT
    if expected:
        print("\n  ── Planted-vuln reflection (each lab resource → its detection) ──")
        miss = 0
        for label, exp in expected.items():
            marks = []
            for r in exp["rules"]:
                hit = r in fired_rules; miss += 0 if hit else 1
                marks.append(f"{'✓' if hit else '✗'} rule {r}")
            for t in exp["issues"]:
                hit = t in fired_issues; miss += 0 if hit else 1
                marks.append(f"{'✓' if hit else '✗'} path {t}")
            print(f"   {'PASS' if all('✓' in m for m in marks) else 'MISS'}  {label}")
            for m in marks:
                print(f"          {m}")
        tot = sum(len(e["rules"]) + len(e["issues"]) for e in expected.values())
        print(f"   planted detections: {tot - miss}/{tot} reflect in the website")

    ok = rep.render()

    # Multi-cloud note (informational, not a failure).
    _, accts = _req("GET", base, "/api/inventory/accounts")
    provs = {a["provider"] for a in accts.get("items", [])}
    extra = provs - {"aws"}
    print(f"\n  multi-cloud: providers registered = {sorted(provs)}"
          + (f" (azure/gcp present: {sorted(extra)})" if extra else " (aws only — azure/gcp need creds)"))
    return ok


# ── orchestration ───────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="End-to-end website reflection test")
    ap.add_argument("--deploy", action="store_true", help="plant the lab before verifying")
    ap.add_argument("--with-rds", action="store_true")
    ap.add_argument("--with-redshift", action="store_true")
    ap.add_argument("--destroy", action="store_true", help="tear the lab down and exit")
    ap.add_argument("--region", default=ACCOUNT_REGION)
    ap.add_argument("--base", default=None, help="override server base URL")
    a = ap.parse_args()

    if a.destroy:
        lab.destroy(a.region)
        return

    if a.deploy:
        lab.deploy(a.region, a.with_rds, a.with_redshift)
        print("\n  Waiting 90s for EC2/RDS to settle before scanning…")
        time.sleep(90)

    base = a.base or pick_base()
    ok = verify(base, a.region, a.deploy, a.with_rds, a.with_redshift)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
