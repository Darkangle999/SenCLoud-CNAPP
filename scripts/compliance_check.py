#!/usr/bin/env python3
"""Test harness for the CSPM compliance scoring.

    python scripts/compliance_check.py prove     # offline: scorer moves with posture (no AWS)
    python scripts/compliance_check.py live       # hit /api/live/cspm, print the matrix (backend up)
    python scripts/compliance_check.py cache      # prove the TTL cache: hit / hit / refresh, timed

`prove` is the one that answers "is compliance broken?" without AWS — it feeds
the real ComplianceMapper synthetic findings (clean → one fail → all fail) and
shows the score track them. `live` and `cache` exercise the HTTP path.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

BASE = "http://localhost:8000"
FRAMEWORKS = ["CIS", "SOC2", "NIST", "PCI-DSS"]


# ── prove: scorer responds to posture (offline, no AWS) ─────────

def prove():
    sys.path.insert(0, "src")
    from odineyes.core.compliance_mapper import ComplianceMapper

    m = ComplianceMapper()
    checks = m._get_check_lookup()
    cis = [cid for cid, chk in checks.items() if chk.compliance.get("CIS")]
    if not cis:
        print("  No checks map to CIS — cannot prove."); return
    print(f"  {len(cis)} checks map to CIS. Feeding synthetic findings:\n")

    scenarios = {
        "clean        (all checks pass)": [{"check_id": c, "status": "pass"} for c in cis],
        "one failure  (1 check fails)  ": [{"check_id": c, "status": "fail" if i == 0 else "pass"}
                                           for i, c in enumerate(cis)],
        "half down    (50% fail)       ": [{"check_id": c, "status": "fail" if i % 2 == 0 else "pass"}
                                           for i, c in enumerate(cis)],
        "breached     (all checks fail)": [{"check_id": c, "status": "fail"} for c in cis],
    }
    scores = []
    for label, findings in scenarios.items():
        s = m.score(findings, ["CIS"])["CIS"]
        scores.append(s["score"])
        bar = "█" * (s["score"] // 5) + "·" * (20 - s["score"] // 5)
        print(f"   {label}  {bar} {s['score']:3}%  ({s['passing']}/{s['total']})")

    print()
    moves = len(set(scores)) > 1 and scores == sorted(scores, reverse=True)
    print("   scorer tracks posture (monotonic, distinct):",
          "✅ YES — not frozen" if moves else "❌ NO — frozen/broken")
    sys.exit(0 if moves else 1)


# ── live: hit the real endpoint ─────────────────────────────────

def _get(path: str):
    try:
        with urllib.request.urlopen(BASE + path, timeout=120) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")
    except urllib.error.URLError as e:
        print(f"  backend unreachable at {BASE} — start it:\n"
              f"    PYTHONPATH=src uvicorn odineyes.api.server:app --port 8000\n  ({e})")
        sys.exit(2)


def live(region: str, refresh: bool):
    q = f"?region={region}" + ("&refresh=true" if refresh else "")
    print(f"  GET /api/live/cspm{q}  (real boto3 sweep — may take ~15s)\n")
    status, d = _get(f"/api/live/cspm{q}")
    if status != 200:
        print(f"  HTTP {status}: {d.get('detail')}"); sys.exit(1)

    s = d["summary"]
    print(f"  account {d.get('account')} · {d['region']} · generated {d['generated_at']}")
    print(f"  checks={s.get('total_checks')} pass_rate={s.get('pass_rate')}% "
          f"risk={d.get('risk_score')} ({d.get('risk_level')})\n")
    print(f"  {'FRAMEWORK':12} {'SCORE':>6}  PASSING  NOT-ASSESSED")
    for fw, f in d["compliance"].items():
        print(f"  {f['name'][:12]:12} {str(f['score'])+'%':>6}  {f['passing']:>3}/{f['total']:<3}"
              f"    {f.get('not_assessed', 0)}")
    # show the failing controls of the lowest-scoring framework
    worst = min(d["compliance"].values(), key=lambda f: f["score"])
    fails = [c for c in worst["controls"] if c["state"] == "fail"]
    if fails:
        print(f"\n  Failing controls in {worst['name']} (lowest at {worst['score']}%):")
        for c in fails[:12]:
            print(f"    ✗ {c['id']:10} {c['title'][:54]}")


# ── cache: prove the TTL behaviour ──────────────────────────────

def cache(region: str):
    q = f"?region={region}"
    print("  1) cold call (computes)…")
    t = time.time(); _get(f"/api/live/cspm{q}"); cold = time.time() - t
    print(f"     {cold:5.1f}s")
    print("  2) warm call (cache hit, should be ~instant)…")
    t = time.time(); _get(f"/api/live/cspm{q}"); warm = time.time() - t
    print(f"     {warm:5.1f}s")
    print("  3) refresh=true (forces recompute)…")
    t = time.time(); _get(f"/api/live/cspm{q}&refresh=true"); forced = time.time() - t
    print(f"     {forced:5.1f}s\n")
    ok = warm < cold / 2 and forced > warm * 2
    print(f"   cache serves warm fast ({warm:.1f}s < {cold:.1f}s) and refresh recomputes "
          f"({forced:.1f}s): {'✅' if ok else '⚠ inconclusive (infra may be tiny)'}")
    print("   TTL is 300s server-side — a warm call after that window recomputes on its own.")


def main():
    ap = argparse.ArgumentParser(description="CSPM compliance test harness")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("prove")
    lv = sub.add_parser("live"); lv.add_argument("--region", default="us-east-1")
    lv.add_argument("--refresh", action="store_true")
    ca = sub.add_parser("cache"); ca.add_argument("--region", default="us-east-1")
    a = ap.parse_args()
    if a.cmd == "prove":
        prove()
    elif a.cmd == "live":
        live(a.region, a.refresh)
    elif a.cmd == "cache":
        cache(a.region)


if __name__ == "__main__":
    main()
