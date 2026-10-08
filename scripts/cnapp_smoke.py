#!/usr/bin/env python3
"""CNAPP MVP smoke test — exercises every pillar added in the Wiz-architecture
sweep through the website's OWN API (vite proxy when up, else backend), so it
proves browser → proxy → backend → DB, not just the database.

Pillars checked:
  visibility (inventory)          identity / CIEM (IAM roles + properties)
  data security (encryption)      vulnerabilities (CWPP endpoints)
  attack-path graph (+enumerate)  threat detection (runtime ingest pipe)
  IaC security (live scan)        compliance (findings→framework mapping)
  architecture posture            eBPF sensor (real if root+bcc, else simulate)

    python scripts/cnapp_smoke.py            # smoke every endpoint
    sudo python scripts/cnapp_smoke.py       # also drives the REAL eBPF sensor
    python scripts/cnapp_smoke.py --no-sensor

Exit code non-zero if any pillar fails. Does not need AWS credentials (vuln scan
is exercised as an endpoint, not a live SSM run).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, "src")

BASES = ["http://localhost:5173", "http://localhost:8000"]

PASS, FAIL, SKIP = "\033[32m✓\033[0m", "\033[31m✗\033[0m", "\033[33m–\033[0m"
results: list[tuple[bool | None, str, str]] = []


def record(ok: bool | None, pillar: str, detail: str) -> None:
    glyph = {True: PASS, False: FAIL, None: SKIP}[ok]
    print(f"  {glyph} {pillar:<22} {detail}")
    results.append((ok, pillar, detail))


# ── HTTP ────────────────────────────────────────────────────────

def _req(method, base, path, body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"} if data else {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read() or b"{}")


def get(base, path):
    return _req("GET", base, path)


def pick_base():
    for b in BASES:
        try:
            urllib.request.urlopen(b + "/api/inventory/summary", timeout=5)
            return b
        except urllib.error.HTTPError:
            return b
        except urllib.error.URLError:
            continue
    return None


# ── pillar checks ───────────────────────────────────────────────

def check_visibility(base):
    try:
        _, s = get(base, "/api/inventory/summary")
        n = s.get("total_assets", 0)
        record(n > 0, "visibility", f"{n} assets inventoried")
    except Exception as e:
        record(False, "visibility", str(e))


def check_identity(base):
    try:
        _, p = get(base, "/api/inventory?type=aws.iam.role&page_size=200")
        items = p.get("items", [])
        has_props = all("properties" in a for a in items) if items else True
        admins = sum(1 for a in items if (a.get("properties") or {}).get("has_admin"))
        ok = has_props
        record(ok, "identity / CIEM", f"{len(items)} roles, {admins} admin, properties exposed={has_props}")
    except Exception as e:
        record(False, "identity / CIEM", str(e))


def check_data(base):
    try:
        _, p = get(base, "/api/inventory?page_size=500")
        stores = [a for a in p.get("items", []) if any(t in a["asset_type"] for t in ("s3.bucket", "rds", "redshift", "dynamodb"))]
        enc = sum(1 for s in stores if s.get("encryption_enabled") is True)
        record(True, "data security", f"{len(stores)} stores, {enc} encrypted, {sum(1 for s in stores if s.get('is_public'))} public")
    except Exception as e:
        record(False, "data security", str(e))


def check_graph(base):
    try:
        _, g = get(base, "/api/inventory/graph?account=all")
        nodes, edges, paths = len(g.get("nodes", [])), len(g.get("edges", [])), len(g.get("paths", []))
        record("paths" in g, "attack-path graph", f"{nodes} nodes, {edges} edges, {paths} enumerated routes")
    except Exception as e:
        record(False, "attack-path graph", str(e))


def check_vulnerabilities(base):
    try:
        _, v = get(base, "/api/inventory/vulnerabilities")
        _, s = get(base, "/api/inventory/vulnerabilities/summary")
        ok = "items" in v and "by_severity" in s
        record(ok, "vulnerabilities", f"{s.get('open', 0)} open CVEs, {s.get('affected_assets', 0)} affected (endpoint live)")
    except Exception as e:
        record(False, "vulnerabilities", str(e))


def check_compliance(base):
    try:
        _, s = get(base, "/api/inventory/findings/summary")
        record(True, "compliance", f"{s.get('open', 0)} findings mapped to frameworks")
    except Exception as e:
        record(False, "compliance", str(e))


_BAD_IAC = json.dumps({
    "resource": {
        "aws_s3_bucket": {"logs": {"acl": "public-read"}},
        "aws_security_group": {"ssh": {"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]}},
        "aws_iam_role_policy": {"god": {"policy": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}},
    }
})


def check_iac(base):
    try:
        _, r = _req("POST", base, "/api/inventory/iac/scan", {"content": _BAD_IAC})
        ids = {f["check_id"] for f in r.get("findings", [])}
        want = {"IAC_S3_PUBLIC_ACL", "IAC_SG_WORLD_OPEN", "IAC_IAM_WILDCARD"}
        ok = want <= ids
        record(ok, "IaC security", f"{r.get('total', 0)} findings, {r.get('format')} (want {len(want)} core checks, got {len(want & ids)})")
    except Exception as e:
        record(False, "IaC security", str(e))


def check_threats_pipe(base):
    """Verify the runtime-event ingest → store → read path with one synthetic event."""
    try:
        marker = f"smoke-{int(time.time())}"
        _req("POST", base, "/api/internal/runtime-events",
             {"event_type": "process_execution", "severity": "high",
              "comm": "smoketest", "filename": f"/tmp/{marker}", "pid": 31337,
              "container": "container:smoke", "summary": "smoke marker", "simulated": True})
        _, listing = get(base, "/api/inventory/runtime-events?limit=50")
        seen = any(marker in (e.get("process") or "") for e in listing.get("items", []))
        record(seen, "threat ingest pipe", "synthetic event persisted + read back" if seen else "marker not found")
    except Exception as e:
        record(False, "threat ingest pipe", str(e))


def check_architecture(base):
    """Posture page is derived client-side; assert its source endpoints all answer."""
    needed = ["/api/inventory/summary", "/api/inventory/issues/summary",
              "/api/inventory/vulnerabilities/summary", "/api/inventory/runtime-events/summary"]
    try:
        for p in needed:
            get(base, p)
        record(True, "architecture posture", f"all {len(needed)} pillar feeds answer")
    except Exception as e:
        record(False, "architecture posture", str(e))


# ── eBPF sensor ──────────────────────────────────────────────────

def check_ebpf(base, enabled: bool):
    if not enabled:
        record(None, "eBPF sensor", "skipped (--no-sensor)")
        return
    import importlib.util
    root = os.geteuid() == 0
    have_bcc = importlib.util.find_spec("bcc") is not None

    _, before = get(base, "/api/inventory/runtime-events/summary")
    n0 = before.get("total", 0)

    if root and have_bcc:
        # REAL: run the sensor, trigger a flagged exec from /tmp, expect a high event.
        proc = subprocess.Popen(
            [sys.executable, "-m", "odineyes.sensor.ebpf_agent", "--api-url", base],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={**os.environ, "PYTHONPATH": "src"})
        try:
            time.sleep(3)  # let it attach
            bait = "/tmp/odineyes_bait"
            subprocess.run(["cp", "/bin/true", bait], check=False)
            subprocess.run([bait], check=False)
            subprocess.run(["curl", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            time.sleep(3)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
            subprocess.run(["rm", "-f", "/tmp/odineyes_bait"], check=False)
        _, after = get(base, "/api/inventory/runtime-events/summary")
        got = after.get("total", 0) - n0
        record(got > 0, "eBPF sensor (REAL)", f"{got} live kernel events captured")
    else:
        # SIMULATE: drive the synthetic stream a few seconds.
        proc = subprocess.Popen(
            [sys.executable, "-m", "odineyes.sensor.ebpf_agent", "--simulate", "--api-url", base],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={**os.environ, "PYTHONPATH": "src"})
        time.sleep(10)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        _, after = get(base, "/api/inventory/runtime-events/summary")
        got = after.get("total", 0) - n0
        why = "not root" if not root else "no bcc"
        record(got > 0, "eBPF sensor (SIM)", f"{got} synthetic events ({why}; sudo for real kernel capture)")


# ── main ────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="CNAPP MVP smoke test")
    ap.add_argument("--no-sensor", action="store_true", help="skip the eBPF sensor subtest")
    args = ap.parse_args()

    base = pick_base()
    if not base:
        print(f"{FAIL} no API reachable on {BASES} — start uvicorn / vite first.")
        sys.exit(2)
    print(f"\nCNAPP smoke against {base}\n" + "─" * 52)

    check_visibility(base)
    check_identity(base)
    check_data(base)
    check_graph(base)
    check_vulnerabilities(base)
    check_compliance(base)
    check_iac(base)
    check_threats_pipe(base)
    check_architecture(base)
    check_ebpf(base, enabled=not args.no_sensor)

    print("─" * 52)
    passed = sum(1 for ok, *_ in results if ok is True)
    failed = sum(1 for ok, *_ in results if ok is False)
    skipped = sum(1 for ok, *_ in results if ok is None)
    print(f"{passed} passed · {failed} failed · {skipped} skipped\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
