# Odineyes CSPM MVP — Implementation Plan

> Goal: surface the existing CSPM rule engine in the web product, Wiz-style.
> CSPM = "is your cloud configured correctly?" — misconfiguration detection +
> compliance scoring. Today the engine exists but the web UI never runs it.

---

## 1. Problem statement

The repo contains two disconnected halves:

| Half | What it does | Surfaced in web UI? |
|------|--------------|---------------------|
| **`core/` CSPM engine** | `CheckRegistry` (~39 AWS checks → pass/fail, severity, remediation, framework map), `RiskEngine`, `SuppressionEngine`, `ComplianceMapper` + `FRAMEWORKS` | **No** — CLI `ScanEngine` only |
| **`api/server.py` + React** | `/api/live/*`: collect → graph → DSPM → attack-paths | Yes |

Consequence: the web product shows attack-path topology and data-sensitivity,
but **zero misconfiguration findings and zero compliance posture score** — the
two things that define CSPM. The Dashboard's "Issues by severity" widget counts
`attack_paths`, not config findings. Nav has no Findings or Compliance view.

**MVP = bridge the halves.** Run the real boto3 `ScanEngine` from the live API,
return findings + per-framework compliance scores, and add the UI to show them.

---

## 2. Scope (this MVP)

In scope:
1. Backend endpoint `/api/live/cspm` — runs `ScanEngine` against the live account.
2. Compliance scoring — new method on `ComplianceMapper` (does not exist yet).
3. **Findings** page — misconfiguration list with filters + remediation.
4. **Compliance** page — framework score cards + section drilldown.
5. Dashboard rewire — posture score + real misconfig severity counts.
6. `api.ts` types + a dedicated `useCspm` hook (keeps graph scan independent).

Out of scope (Phase 2, noted §8):
- Contextual severity adjustment (graph-aware up/down grading).
- Finding lifecycle persistence (NEW→OPEN→RESOLVED across scans).
- Event-driven re-evaluation (CloudTrail → EventBridge).
- Multi-cloud (Azure/GCP) — AWS only for MVP.

---

## 3. Backend changes

### 3.1 New endpoint — `src/odineyes/api/server.py`

```
GET /api/live/cspm?region=us-east-1&profile=<opt>&frameworks=CIS,SOC2,NIST,PCI-DSS
```

Runs the real check engine (decision: **real boto3 ScanEngine**, not derived
from the in-memory graph). Separate from `/api/live/scan` so the graph dashboard
is never blocked by the slower full check sweep.

Handler outline:

```python
import io, re
from odineyes.core.engine import ScanEngine
from odineyes.core.compliance_mapper import ComplianceMapper, FRAMEWORKS

_cspm_cache: dict = {}
_CSPM_CACHE_MAX = 32                     # bound the cache; clear when exceeded

# Input allow-lists — never pass unvalidated strings to boto3 / shell-adjacent paths.
_REGION_RE = re.compile(r"^[a-z]{2}-[a-z]+-\d{1,2}$")
_PROFILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

def _run_cspm(region, profile, frameworks):
    engine = ScanEngine(
        providers=["aws"],
        regions=[region],
        profile=profile or "default",
        compliance_frameworks=frameworks,
        parallel=True,
        threads=10,
    )
    results = engine.run(quiet=True)            # findings + summary + risk_score
    compliance = ComplianceMapper().score(      # NEW method, see 3.2
        results["findings"], frameworks)
    return {
        "account": results["scan_metadata"].get("account"),   # add to metadata
        "region": region,
        "summary": results["summary"],          # by_severity/category, pass_rate
        "risk_score": results["risk_score"],
        "risk_level": results["risk_level"],
        "findings": results["findings"],
        "compliance": compliance,
        "generated_at": results["scan_metadata"]["end_time"],
    }

@app.get("/api/live/cspm")
def live_cspm(region="us-east-1", profile=None, frameworks="CIS,SOC2,NIST,PCI-DSS",
              refresh=False):
    # Validate every caller-supplied string before it reaches boto3.
    if not _REGION_RE.match(region):
        raise HTTPException(status_code=400, detail="Invalid region")
    if profile is not None and not _PROFILE_RE.match(profile):
        raise HTTPException(status_code=400, detail="Invalid profile")
    # Whitelist framework ids against FRAMEWORKS; cap to bound work.
    fw = [f.strip() for f in frameworks.split(",") if f.strip() in FRAMEWORKS][:16]
    if not fw:
        raise HTTPException(status_code=400, detail="No valid frameworks requested")

    key = f"{region}:{profile}:{','.join(sorted(fw))}"
    if refresh or key not in _cspm_cache:
        try:
            result = _run_cspm(region, profile, fw)
        except Exception as e:
            # Log detail server-side; return a generic message so credentials /
            # internal state never leak to the client.
            logger.error(f"CSPM scan failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="CSPM scan failed")
        if len(_cspm_cache) >= _CSPM_CACHE_MAX:
            _cspm_cache.clear()
        _cspm_cache[key] = result
    return _cspm_cache[key]
```

Notes:
- `ScanEngine.run()` prints rich tables to a `Console`; pass `quiet=True` and a
  throwaway `Console(file=io.StringIO())` into `ScanEngine.__init__(console=…)`
  so nothing leaks to server stdout.
- `engine.run()` may take seconds (39 checks × boto3). In-memory cache mirrors the
  existing `_live_cache` pattern, bounded at `_CSPM_CACHE_MAX`. `refresh=true` busts it.
- **Validation (gap-closed):** region/profile pass regex allow-lists, frameworks
  are whitelisted against `FRAMEWORKS` — all reject with **400**, never reach boto3.
- **Error shape (contract):** failures return `{"detail": "CSPM scan failed"}`
  (generic, no leak). The frontend renders `response.detail` verbatim.
- **No mock layer:** on failure the UI shows the honest error — there is no mock
  fallback anywhere (see §4.1).
- `scan_metadata` currently has no `account`; add `account`/`principal` via
  `sts:GetCallerIdentity` in `ScanEngine.run()` (small addition) or omit for MVP.

### 3.2 New scoring method — `core/compliance_mapper.py`

`ComplianceMapper` has `FRAMEWORKS` (control → {title, section, level}) and
`map_finding`, but **no scoring**. Add:

```python
def score(self, findings, frameworks):
    """Per-framework compliance score from findings.

    A control PASSES if every check mapped to it passed (no failing finding).
    A control FAILS if any mapped check produced a fail finding.
    Controls with no mapped check that ran = 'not_assessed' (excluded from %).
    """
    checks = self._get_check_lookup()
    # control -> set of check_ids mapped to it, per framework
    out = {}
    for fw_id in frameworks:
        fw = FRAMEWORKS.get(fw_id)
        if not fw:
            continue
        # build control -> mapped check_ids
        ctrl_checks = {}
        for cid, chk in checks.items():
            for ctrl in chk.compliance.get(fw_id, []):
                ctrl_checks.setdefault(ctrl, set()).add(cid)
        # per-control pass/fail from findings
        fail_checks = {f["check_id"] for f in findings
                       if f.get("status") == "fail"}
        ran_checks = {f["check_id"] for f in findings}
        sections = {}
        passing = total = not_assessed = 0
        controls_out = []
        for ctrl, meta in fw["controls"].items():
            mapped = ctrl_checks.get(ctrl, set())
            assessed = mapped & ran_checks
            if not assessed:
                state = "not_assessed"
            elif mapped & fail_checks:
                state = "fail"
            else:
                state = "pass"
            sec = meta.get("section", "Other")
            s = sections.setdefault(sec, {"passing": 0, "total": 0})
            if state in ("pass", "fail"):
                total += 1; s["total"] += 1
                if state == "pass":
                    passing += 1; s["passing"] += 1
            else:
                not_assessed += 1
            controls_out.append({
                "id": ctrl, "title": meta["title"], "section": sec,
                "state": state, "checks": sorted(mapped),
            })
        for s in sections.values():
            s["pct"] = round(s["passing"] / s["total"] * 100) if s["total"] else 0
        out[fw_id] = {
            "name": fw["name"], "version": fw.get("version"),
            "score": round(passing / total * 100) if total else 0,
            "passing": passing, "total": total, "not_assessed": not_assessed,
            "sections": sections, "controls": controls_out,
        }
    return out
```

Design call: only ~44 checks exist, so most controls map to **no** check →
`not_assessed`, excluded from the denominator. Score reflects *assessed* controls
only. Surface `not_assessed` count in the UI so the gap is honest.

**Scoring universe = curated controls ∪ check-mapped controls.** `score()`
iterates the union of (a) the controls hand-listed in `FRAMEWORKS` and (b) every
control any check's `compliance` map references — not just the curated list.
Otherwise a check whose control isn't hand-listed has its pass/fail silently
discarded (this was a real bug: 44 checks reached 37 CIS controls but only 11
were curated, so 26 controls' results were dropped and the score read an
inflated 55% over a cherry-picked window instead of ~21% over the real assessed
set). Check-only controls get a stub `{title: <id>, section: "Other"}`; controls
with no check that ran fall through to `not_assessed` as before.

---

## 4. Frontend changes

### 4.1 `api.ts` — new types + fetch

```ts
export interface CspmFinding {
  check_id: string; name: string; description: string
  category: string; severity: Severity; status: 'pass'|'fail'|'error'|'skip'
  resource_id: string; resource_type: string; region: string
  message: string; remediation: string; remediation_url: string
  compliance_mappings: Record<string, string[]>; risk_score: number
}
export interface ComplianceControl {
  id: string; title: string; section: string
  state: 'pass'|'fail'|'not_assessed'; checks: string[]
}
export interface FrameworkScore {
  name: string; version: string; score: number
  passing: number; total: number; not_assessed: number   // produced by score()
  sections: Record<string, { passing: number; total: number; pct: number }>
  controls: ComplianceControl[]
}
export interface CspmScan {
  account?: string; region: string
  summary: { by_severity: Record<string,number>; pass_rate: number; /* … */ }
  risk_score: number; risk_level: string
  findings: CspmFinding[]
  compliance: Record<string, FrameworkScore>
  generated_at: string
}
export async function fetchCspmScan(region, opts?): Promise<CspmScan> { /* mirror fetchLiveScan; NO mock fallback */ }
```

**No mock layer.** `fetchCspmScan` returns live data or throws an `ApiError`
carrying `response.detail`; the UI renders that error verbatim. There is no
`mockCspmScan` — backend-off shows the honest error state, not fake data.

### 4.2 New hook — `hooks/useCspm.tsx`

Mirror `useScan` (context + region + refresh) but **separate provider**, so the
heavy check sweep loads independently of the graph scan. Wrap `<App/>` in both
providers. Pages that need findings call `useCspm()`. On fetch failure the hook
exposes the `ApiError` for an honest error state — no mock fallback.

### 4.3 Findings page — `pages/Findings.tsx` (route `/findings`)

- Table: Check ID · Resource · Category · Severity chip · Message · Risk.
- Filter bar: severity, category, framework, status (fail-only default).
- Row click → side drawer: full description, remediation, `remediation_url`,
  compliance mappings as framework chips.
- Status column: MVP shows `fail`/`pass` only (lifecycle is Phase 2).
- Reuse `severityColor()` from `api.ts` and existing card/table CSS in `index.css`.

### 4.4 Compliance page — `pages/Compliance.tsx` (route `/compliance`)

- Grid of framework score cards: name, big `score%` ring (reuse Dashboard's
  `GaugeStat` SVG arc), `passing/total`, `not_assessed` count.
- Click card → section drilldown: per-section horizontal bars (`passing/total`,
  pct) — mirrors the spec's "Section 3 (Logging) 67% ← attention needed".
- Control table under each section: control id, title, pass/fail/not-assessed pill.

### 4.5 Dashboard rewire — `pages/Dashboard.tsx`

- "Open Issues" + "Issues by severity" + "Severity Breakdown" currently derive
  from `data.attack_paths`. Add `useCspm()` and switch the severity widgets to
  `cspm.summary.by_severity` (real misconfig counts).
- Add a **Compliance posture** card: top framework scores (e.g. CIS 81%) as rings.
- Keep attack-path topology graph as-is (complementary, not CSPM core).

### 4.6 Nav — `components/Sidebar.tsx` + `App.tsx`

- Add routes `/findings` and `/compliance` in `App.tsx`.
- Add two `LINKS` entries in `Sidebar.tsx`: Findings (`ShieldAlert`/`ListChecks`),
  Compliance (`ShieldCheck`/`ClipboardCheck` from lucide-react).
- Relabel: keep "Issues" → attack-paths, add "Findings" for CSPM misconfigs.

---

## 5. File-by-file change list

| File | Change | Type |
|------|--------|------|
| `src/odineyes/api/server.py` | `_run_cspm` + `/api/live/cspm` | new code |
| `src/odineyes/core/compliance_mapper.py` | `ComplianceMapper.score()` | new method |
| `src/odineyes/core/engine.py` | optional: add `account`/`principal` to metadata | small edit |
| `frontend/src/api.ts` | CSPM types + `fetchCspmScan` (no mock) | new code |
| `frontend/src/hooks/useCspm.tsx` | new context/hook | new file |
| `frontend/src/pages/Findings.tsx` | new page | new file |
| `frontend/src/pages/Compliance.tsx` | new page | new file |
| `frontend/src/pages/Dashboard.tsx` | wire CSPM severity + posture card | edit |
| `frontend/src/components/Sidebar.tsx` | 2 nav links | edit |
| `frontend/src/App.tsx` | 2 routes + 2nd provider | edit |
| `frontend/src/index.css` | findings table / compliance card styles | edit |
| `src/odineyes/tests/test_dspm.py` (or new) | test `score()` + endpoint | test |

---

## 6. Build / verify order

1. `ComplianceMapper.score()` + unit test (pure, no AWS) — fastest to validate.
2. `/api/live/cspm` endpoint — curl against a real profile; confirm findings +
   compliance JSON shape.
3. `api.ts` types + `fetchCspmScan` (live only, no mock).
4. `useCspm` hook + 2nd provider in `App.tsx`.
5. Compliance page (highest CSPM signal) → Findings page → Dashboard rewire.
6. **`tsc --noEmit`** — catch backend-shape ↔ TS-interface mismatch before the
   browser. (Bake into `npm run build` as `tsc --noEmit && vite build`.)
7. Sidebar nav + routes last (wires it together).

Verify: `uvicorn odineyes.api.server:app --port 8000` + `npm run dev`;
`curl 'localhost:8000/api/live/cspm?region=us-east-1'`; confirm the 400s fire
(`region=bad`, `frameworks=EVIL`); click through both pages; with the backend
off, confirm the honest error state renders (no mock fallback exists).

---

## 7. Risks / decisions

- **AWS creds + latency.** 39 checks × boto3 = multi-second scan, needs a profile.
  Mitigis: separate endpoint, bounded in-memory cache (`_CSPM_CACHE_MAX=32`),
  `refresh` to bust. No mock fallback — failure surfaces as an honest error.
- **Untrusted input.** region/profile/frameworks come from the query string —
  validated against regex allow-lists + a `FRAMEWORKS` whitelist, all 400 on
  miss, before anything reaches boto3.
- **Error leakage.** The 500 returns a generic `detail` ("CSPM scan failed");
  full exception is logged server-side only, never sent to the client.
- **Sparse control coverage.** Few checks → many controls `not_assessed`. Decision:
  exclude unassessed from the %, return the `not_assessed` count so the score
  isn't misleading.
- **Console leakage.** `ScanEngine.run()` writes rich tables — pass a
  `Console(file=io.StringIO())` into `ScanEngine.__init__(console=…)` + `quiet=True`.
- **Two scans now run** (`/scan` graph + `/cspm` checks). Independent providers so
  one slow path doesn't block the other; acceptable for MVP.

---

## 8. Phase 2 (after MVP, per spec)

- Contextual severity: use the in-memory graph to up/downgrade findings
  (open SSH + CVE + prod + admin role → CRITICAL; SG open but NACL blocks → suppress).
  Merge `/scan` graph context into `/cspm` findings.
- Finding lifecycle: persist scans, diff for NEW/OPEN/RESOLVED auto-resolution.
- Event-driven re-eval (CloudTrail → EventBridge → targeted re-check) — wiring
  already partly present (`setup_eventbridge.py` at repo root,
  `src/odineyes/core/event_listener.py`; both confirmed in repo).
- Expand check coverage to lift control-assessment ratio; add Azure/GCP.

---

## 9. Market-fit gap audit (2026-06-22)

Pillar coverage against what enterprise buyers compare on. **Skip eBPF runtime
sensor** — to be replaced by Tetragon integration later, do not invest here.

| Pillar | Module | Status | Gap to close |
|---|---|---|---|
| Asset inventory | `inventory/aws_raw_collector.py` | dynamic ~200-service sweep | sequential per-service — see §9.2; needs allowlist + ThreadPool |
| Misconfig checks | `core/check_registry.py` (~44 AWS) | covers ~⅓ of CIS 1.5 | grow to ≥80 to hit CIS L1 floor (12 IAM + 9 storage + 11 logging + 15 monitoring + 6 networking still light on monitoring) |
| Compliance | 8 frameworks + SoA + overrides + custom | **strong** | none |
| Attack paths | `inventory/issues.py` + graph spine | 5 path types, evidence trail added | add `PUBLIC_LAMBDA_URL`, `OVERPRIVILEGED_CICD_ROLE`, `EXPOSED_SECRET_PATH` (data we already collect) |
| CIEM | `cloud/aws_collector._scan_doc` privesc | role-level only | user-level access keys + inactive principals; cross-account trust drift |
| DSPM | `dspm/classifier.py` + persisted findings | regex + Aho-Corasick + entropy | **PHONE regex was broken — fixed**; needs `Asset.tags['DataClassification']` propagation to attack paths |
| IaC | `iac/` Terraform plan scanner | pre-deploy only | OPA/Rego policy passthrough is the buyer ask; today only built-in checks |
| Vuln (CWPP) | `engine/`, KEV+EPSS, CVE catalog | strong | container image scan is missing — `aquasec/trivy` shell-out is 100 LOC, biggest single-feature gap |
| Secrets | inventory enrichment | secret public-policy flag only | no secret-scanning of code/objects (out of scope: defer to git-secrets/trufflehog integration) |
| Drift | `db.models.ComplianceDrift` + snapshots | persistence in place | scheduled drift summary email/webhook missing — `apscheduler` + an alert sink, ~60 LOC |
| Remediation | `Finding.remediation_url` text | **read-only** today | one-click "create JIRA ticket" / "open PR with terraform fix" — buyer table-stakes |
| Multi-account | `core/multi_account.py` (assume-role) | exists | UI to add/edit accounts is missing (`Accounts.tsx` page + 2 API routes) |

### 9.1 Close before pitching to buyers

Ranked by ratio of buyer-perception lift to LOC:

1. **Container image scan** (trivy shell-out, parse JSON into `Vulnerability` rows). ~120 LOC. Closes the biggest visible-on-demo gap.
2. **Accounts management UI** — add/list/disable accounts via `/api/config/accounts` + `Accounts.tsx`. ~150 LOC. Multi-account is the #1 enterprise filter; the backend already supports it.
3. **Ticketing webhook** — `/api/findings/{id}/ticket` posts to a configurable JIRA/Linear webhook with finding+remediation. ~60 LOC.
4. **Three extra attack-path types** in `inventory/issues.py` (Lambda URL, CI/CD role, exposed-secret path). ~80 LOC each; reuse existing edges.
5. **OPA Rego eval** — `iac/` accepts a `.rego` policy alongside the plan JSON, shells to `opa eval`. ~70 LOC, lets buyers bring their own policies.

### 9.2 Optimization deltas worth shipping now

- **`dspm/classifier.py:110` PHONE regex** — was `[-.\s]]\d{4}` (literal `]` typo broke phone-PII detection). **Fixed** in this pass.
- **`inventory/aws_raw_collector.py` collect()** — sequential over `get_available_services()` (~200 services × N read ops). Two cuts: (a) hardcode a security-relevant service allowlist (~25 services: ec2, iam, s3, rds, lambda, ecs, eks, secretsmanager, kms, cloudtrail, cloudwatch, config, guardduty, elbv2, redshift, dynamodb, sns, sqs, apigateway, route53, efs, eventbridge, stepfunctions, sagemaker, glue) — drops API call volume ~85%; (b) wrap the outer service loop in `concurrent.futures.ThreadPoolExecutor(max_workers=10)` — boto3 sessions are thread-safe per-client. ~30 LOC change, ~5× wall-clock.
- **`core/compliance_mapper.score()`** — rebuilds `ctrl_checks` per call; cache the per-framework overlay onto the mapper instance and invalidate on `config_store` write. ~20 LOC, big win when the dashboard polls.
- **`core/config_store.load_config()`** — three full table scans per scoring call. Single `Config` cache keyed by `max(updated_at)` across the three tables; or just memoize for 5s. ~10 LOC.
- **Dynamic collector logs at DEBUG on every AccessDenied** — quiet at INFO once per service, not per call. Avoids drowning the scan log on a least-priv role.

### 9.3 Files removed this pass (dead weight)

`alerter.py`, `monitor.py`, `patch_exceptions.py`, `test_architecture.py`, `test_event.sh`, `simulate_wiz_attack_path.py`, `trigger_breach.py`, `odineyes-report.html`, `odineyes.db`, `scratch/`, `vulnerable_app/`, `frontend/src/pages/K8s.tsx` (backend route deleted in this PR; nav already stripped).

Kept under review (still wired): `aws_cspm_scan.py` (root CLI shim), `create_tenant.py` (multi-tenant bootstrap), `setup_eventbridge.py` + `setup_realtime_infra.sh` (Phase-2 EventBridge wiring per §8), `scripts/seed_*` (test data seeders), `infrastructure/main.tf`, `deploy/`.

### 9.4 Out of scope for this branch

- eBPF runtime sensor — deferred for Tetragon swap.
- Azure/GCP collectors — not until AWS coverage hits the CIS-L1 floor.
- Workload posture (KSPM) — k8s removed this PR; re-enter via Tetragon path.
