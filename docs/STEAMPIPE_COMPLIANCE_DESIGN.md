# Steampipe Compliance Backend — Design

Status: **implemented, live-validated on WSL/Ubuntu**
Date: 2026-06-24
Owner: Odineyes
Source mod: [`steampipe-mod-aws-compliance` v1.13.0](https://github.com/turbot/steampipe-mod-aws-compliance/tree/v1.13.0)

> **Revision (2026-06-24, during impl):** at v1.13.0 the aws-compliance mod is a
> **Powerpipe** mod (`mod.pp`), and `steampipe check` is deprecated. The runner
> was pivoted from `steampipe check` (Approach A) to **`powerpipe benchmark run`
> against a running steampipe service** — see D8/D9. The JSON shape is nearly
> identical, so the parser + the preserved frontend contract are unchanged.
> Confirmed live: account 123456789012, CIS v3.0.0 scored 7/51 (14%), 98 findings.

---

## Understanding Summary

- **What**: Replace Odineyes's hand-maintained compliance scoring engine
  (per-framework Python catalogs + `ComplianceMapper.score`) with Steampipe's
  `steampipe-mod-aws-compliance` v1.13.0, run as a backend and parsed into the
  existing API response shape.
- **Why**: Steampipe ships ~500 maintained SQL controls across current
  framework versions (CIS v3.0, PCI-DSS, NIST 800-53 rev5, SOC2, AWS FSBP). Our
  hand-rolled catalogs lag (CIS was v1.5.0) and cost ongoing upkeep.
- **Who**: CSPM users hitting the Compliance tab (`/api/live/cspm`) and the
  continuous-compliance snapshot path.
- **Constraints**: Linux/Ubuntu deploy only (Steampipe is a Go binary; Windows
  dev box can't run it live — parser must be offline-testable). Read-only AWS.
  No shell injection (benchmark/region/profile allow-listed, args passed as a
  list). Must preserve the exact frontend response contract.
- **Non-goals**: Not replacing the boto3 check engine that feeds
  findings → attack-path / risk (`/api/inventory`). Not a Steampipe *service*
  (Postgres long-running) — CLI subprocess only. No new frameworks beyond the
  five defaults in this pass.

## Assumptions

- A1: Steampipe + `steampipe-plugin-aws` are installed and pinned in the
  Ubuntu image; default AWS creds resolve via the standard chain.
- A2: `powerpipe benchmark run <id> --output json` emits a stable tree of
  groups → controls → results. Schema drift is mitigated by version pinning.
- A3: A full five-framework sweep is slow (minutes); cache TTL is raised and a
  generous subprocess timeout is set.
- A4: Where the binary is absent or exits non-zero, falling back to the current
  Python engine is acceptable (degraded framework versions, never a hard fail).

## Open Questions

- OQ1: Exact pinned Steampipe + plugin versions (decide at install-script time).
- OQ2: FSBP benchmark id string in v1.13.0 (`foundational_security` —
  verify against the mod at impl).

---

## Frontend Contract (must preserve)

From `frontend/src/pages/Compliance.tsx` + `types.ts`, the live tab consumes:

```
scan = {
  account, region,
  summary: { pass_rate },
  compliance: {
    <fw_key>: {
      name, version, score, passing, total,
      controls: [ { id, title, section, state } ]   // state: 'pass'|'fail'|'not_assessed'
    }
  }
}
```

Note the frontend does **not** read a `sections` object or a `not_assessed`
count field — only `control.state`. The Steampipe map can therefore be flatter
than the old `ComplianceMapper` output.

---

## Architecture

```
/api/live/cspm  ──>  _run_cspm(region, profile, frameworks)
                         │
            steampipe_runner.available()?
                ├─ yes ─> steampipe_runner.run(benchmarks, region, profile)
                │            steampipe service start (idempotent), then per fw:
                │            subprocess: powerpipe benchmark run <id> --output json
                │            -> parse JSON tree -> compliance dict (+ findings)
                └─ no  ─> _run_cspm_python()   # current ScanEngine path, unchanged
```

### Components

1. **`core/steampipe_runner.py`** (new)
   - `available() -> bool` — `shutil.which("steampipe") is not None`.
   - `BENCHMARKS: dict[str, str]` — framework key → steampipe benchmark id
     (`CIS`→`cis_v300`, `PCI-DSS`→`pci_dss_v321`, `NIST`→`nist_800_53_rev_5`,
     `SOC2`→`soc_2`, `FSBP`→`foundational_security`).
   - `run(frameworks, region, profile) -> dict` — validate frameworks against
     `BENCHMARKS` keys (allow-list), build arg list, subprocess with timeout,
     parse stdout JSON, return `{"compliance": {...}, "findings": [...]}`.
   - `_parse(raw: dict, frameworks) -> dict` — **pure**, no subprocess/AWS.
     Walks the benchmark tree → per-framework shape above. This is the unit
     under test (fixture-driven, offline — same pattern as `TrivyScanner._parse`).

2. **`api/server.py`**
   - Split current `_run_cspm` body into `_run_cspm_python`.
   - New `_run_cspm` dispatches steampipe-or-fallback, returns identical shape.
   - Keep `_cspm_cache` (TTL 300→**900s**), region/profile regex, framework
     allow-list.

3. **Deploy**
   - `scripts/install-steampipe.sh` — pinned steampipe + plugin, SHA-verified
     (mirrors `scripts/install-trivy.sh`); writes `~/.steampipe/config/aws.spc`
     (default creds + region).
   - Dockerfile invokes it (Linux image). Windows dev: no binary → parser tested
     offline, fallback path serves the tab.

---

## Data Mapping (Steampipe JSON → contract)

Per control, from its `summary.status` counts `{ok, alarm, info, skip, error}`:

| Condition                         | `control.state` |
|-----------------------------------|-----------------|
| `alarm > 0` or `error > 0`        | `fail`          |
| `ok > 0`, no alarm/error          | `pass`          |
| only `skip`/`info` (nothing run)  | `not_assessed`  |

Per framework:
- `passing` = count of controls with state `pass`.
- `total` = controls with state `pass` or `fail` (assessed; `not_assessed`
  excluded — matches "X/Y controls" + Ring semantics).
- `score` = `round(passing / total * 100)` (0 if `total == 0`).
- `controls[].section` = title of the control's parent sub-benchmark group.
- `name` / `version` = from the benchmark group title/tags (e.g. "CIS v3.0.0").

Top-level:
- `account` = from result dimensions / STS; `region` = request region.
- `summary.pass_rate` = overall passing/total across selected frameworks.

`findings[]` (so the tab's findings come from the same source): one per `alarm`
result — `{resource, reason, control_id, severity, state: 'fail'}`.

---

## Error Handling & Edge Cases

- Binary missing / `steampipe` nonzero exit / timeout → log, **fall back** to
  Python engine. Never 500 the tab on Steampipe trouble.
- `subprocess.run(args_list, timeout=600)` — args as a **list** (no shell).
  Frameworks already allow-listed; region/profile already regex-validated.
- Control `error` status (e.g. permission denied on a resource) → treated as
  `fail` and surfaced; logged at debug.
- Empty/partial benchmark (no controls returned) → framework omitted or `total=0`
  → score 0, no crash.
- JSON schema drift across steampipe versions → caught by `_parse` fixture test;
  mitigated by version pinning.

## Testing

- `tests/test_steampipe_runner.py` — feed a captured `powerpipe benchmark run ... json`
  fixture to `_parse`, assert the compliance dict matches the contract
  (state thresholds, passing/total/score, section labels). **Offline.**
- Fallback test — monkeypatch `available()` → `False`, assert `_run_cspm` uses
  `_run_cspm_python` and returns the same top-level shape.
- Live validation runs on Ubuntu (out of scope for Windows CI).

---

## Decision Log

| # | Decision | Alternatives | Why |
|---|----------|--------------|-----|
| D1 | Run Steampipe as a **backend** (ingest its results) | Port its SQL into our engine; call Steampipe as a long-running service | Keeps the maintained mod as-is; subprocess is the least moving parts. |
| D2 | **Replace** the compliance scoring engine | Keep Python catalogs, add Steampipe alongside | Single source of truth; kills catalog upkeep + version lag. Python checks stay only for findings→attack-path. |
| D3 | Default frameworks: **CIS v3.0, PCI-DSS, NIST 800-53 rev5, SOC2, AWS FSBP** | CIS-only; all mod benchmarks | Matches what users score against; `frameworks` param stays configurable. |
| D4 | ~~**Approach A**: `steampipe check --output json`~~ — **superseded by D8** | Approach B: service + Postgres query | Original pick; invalidated once the mod turned out to be Powerpipe-only. |
| D8 | Drive **`powerpipe benchmark run <id> --output json`** against a running **steampipe service**; runner loops one run per framework | Stay on `steampipe check` (impossible — mod is `mod.pp`); query the steampipe Postgres directly | At v1.13.0 the mod is a Powerpipe mod and `steampipe check` is deprecated/removed. Powerpipe is the supported runner; JSON shape ~matches so the parser barely changed. Runner calls `steampipe service start` (idempotent) first. |
| D9 | **git-clone** the mod at the tag into `MOD_DIR`; run powerpipe from there | `steampipe mod install` / `powerpipe mod install` | `mod install` resolves a dependency mod file and rejected the `@v1.13.0` tag; a plain clone + `cwd=MOD_DIR` is simpler and pins the exact tag. |
| D10 | Pin **aws plugin `1.28.0`** (mod requirement) | `aws@0.146.0` | The mod declares `require aws@1.28.0`; 0.146.0 left 7 controls errored on missing columns. |
| D5 | Tab **findings + scores both** from Steampipe | Keep findings from Python engine | One consistent source for the Compliance tab. Inventory/attack-path findings unaffected (separate path). |
| D6 | **Fallback** to Python engine when binary absent/fails | Hard-fail | Windows dev + resilience; degraded versions beat a broken tab. |
| D7 | Cache TTL **300→900s** | Keep 300s | Steampipe sweeps are minutes; avoid hammering. |

---

## Final shape preserved

`_run_cspm` returns the same `{account, region, summary, compliance, findings}`
the frontend already consumes — no frontend change required.
