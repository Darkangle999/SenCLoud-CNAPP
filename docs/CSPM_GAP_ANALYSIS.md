# Odineyes vs. the CSPM Problem Space — Capability & Gap Analysis

> Grounded against the codebase as of commit `07be9ad` (2026-07-10). Every
> "current state" claim below cites the file that implements it; every "gap"
> is something that file does not do. Where the industry framing below cites
> external sources, treat those as background context, not verified facts —
> the actionable content is the Odineyes column.

## 1. Purpose

This document maps the standard CSPM problem space onto what Odineyes
actually does today, file by file, and states plainly where the product
stops. It exists so the next planning pass starts from measured capability
instead of the mental model of what a "complete" CSPM looks like.

## 2. The five problems a CSPM exists to solve

| Problem | Example | Industry-standard response | Odineyes today |
|---|---|---|---|
| Lack of cloud visibility | Security doesn't know every account/subscription/resource | Centralized asset inventory | `inventory/aws_raw_collector.py` (554 lines, ~30+ resource ops via `OPERATIONS` registry) → `inventory/normalizers.py` → persisted `Asset` rows. AWS is deep; Azure/GCP are present but shallow (§8). |
| Misconfiguration | Public storage, disabled encryption | Detect + recommend fix | `inventory/rules.py` (21 rules) + `core/check_registry.py` (framework-mapped `BaseCheck` classes) + `iac/scanner.py` (pre-deploy). Every finding carries a `remediation` CLI string (`rules.py:80` `REMEDIATION_CLI`). |
| Configuration drift | Firewall rule changed post-approval | Continuously diff against baseline | `inventory/queries.py:928` `compliance_drift()` — persisted snapshot-to-snapshot diff, regression vs. remediation classified. Real, DB-backed. |
| Excessive permissions | Workload identity has admin | Identify risky privilege paths | `rules.py:172` `rule_public_admin_role`, `rules.py:433` `rule_public_compute_to_admin` (2-hop). No standalone CIEM/identity graph (§4). |
| Compliance monitoring | Must meet CIS/PCI/ISO/internal controls | Map config to controls, gather evidence | `core/compliance_mapper.py` + 7 catalogs (CIS, SOC2, PCI-DSS, ISO 27001, NIST 800-53, GDPR, HIPAA) + `core/soa.py` (Statement of Applicability). Real coverage, honestly labeled `not_assessed` where a control can't auto-check. |

## 3. The worked example, as implemented

The classic chain — internet-facing VM → open management port → broad IAM
role → sensitive database — is not hypothetical here. `inventory/graph.py`
builds an `AssetGraph` from persisted assets and edges
(`AssetGraph.build`, `graph.py:180`) and
`enumerate_paths(max_depth=7, max_paths=400)` (`graph.py:112`) DFS-walks it
into scored multi-hop attack paths, serialized for the frontend's Attack
Path view. This is the one area where Odineyes already does the thing most
CSPM vendors market as their differentiator — worth knowing so it isn't
accidentally rebuilt.

## 4. Gap-by-gap assessment

Each entry: what the literature means by this gap, what Odineyes has today
(file-grounded), what's actually missing, and a concrete next step.

### 4.1 Posture-only, no runtime truth
**Current state:** `sensor/tetragon_shipper.py` + `sensor/policies/` ship
real runtime telemetry (syscall/process/network events via Tetragon) into
`RuntimeEvent` rows, surfaced on the Threats/eBPF pages.
**Gap:** runtime coverage is process/syscall-level only — no correlation
back to "is the vulnerable package in this CVE actually loaded," no
network-flow-based lateral-movement detection, no live credential-usage
anomaly detection. The posture engine (rules.py) and the runtime pipeline
don't currently cross-reference each other (a runtime event doesn't
suppress or elevate a static finding).
**Recommendation:** join `RuntimeEvent` against open `Vulnerability` rows on
process/package identity to answer "is this CVE's package actually
running" — highest-leverage single addition here.
**Priority:** Medium (foundation exists; the gap is correlation, not
collection).

### 4.2 Alert overload / weak prioritization
**Current state:** `scanner/maturity.py` + `scanner/kev_client.py` +
`scanner/epss_client.py` already do exploit-maturity/KEV/EPSS-weighted
scoring for vulnerabilities. `core/suppression_engine.py` exists for
findings. Attack-path scoring (`graph.py:_path_meta`) ranks chains, not just
flat findings.
**Gap:** the *posture* rule engine (rules.py) has no equivalent
risk-weighting — every rule fires at its fixed severity regardless of
whether the resource is internet-facing, tagged prod, or holds no data.
No dedup of "same underlying issue, five findings."
**Recommendation:** extend the vuln-side maturity scoring pattern to
`Finding` — multiply severity by exposure (public/private) and DSPM
sensitivity when both are known for the same resource.
**Priority:** Medium.

### 4.3 No business/ownership context
**Current state:** `Asset`/`Finding` models carry no owner, team, or
business-criticality field; nothing reads AWS tags into ownership metadata.
**Gap:** exactly as described — no tag-to-owner mapping, no CMDB
integration, no exception-approval workflow.
**Recommendation:** lowest-effort version — ingest a configurable tag key
(e.g. `Owner`, `CostCenter`) during collection and surface it on
Finding/Asset rows; real CMDB integration is out of scope until asked for.
**Priority:** Low (no signal this is blocking current usage).

### 4.4 Identity attack paths (CIEM)
**Correction (this was materially overstated in the first draft):** CIEM is far
more built than "two hardcoded IAM patterns." The collector already walks
attached + inline policy documents per principal (`aws_raw_collector._enrich_iam_role`
via `AwsCollector._scan_doc`/`_doc_is_admin`) to derive `has_admin`,
`privesc_actions`, `trust_external`, `trust_federated`, `publicly_assumable`,
and the Issues engine (`inventory/issues.py`) turns those into real identity
attack paths: `CROSS_ACCOUNT_LATERAL` (cross-account trust exploitation),
`IAM_PRIVILEGE_ESCALATION` (privesc primitives → admin), and
`OVERPRIVILEGED_CICD_ROLE` (OIDC federation + privilege). Role-side CIEM is
genuinely strong.

**Closed since v1 (commit after `07be9ad`):** IAM **users** — previously not
collected at all (`OPERATIONS` had only `list_roles`). Now: `list_users` op +
`_enrich_iam_user` (has_admin/privesc + access-key age via
`list_access_keys`/`get_access_key_last_used` + console/MFA) + `normalize_iam_user`
+ two rules — `IAM_USER_PRIVILEGED_LONGLIVED_KEY` (privileged user with an
active key older than 90d — the leaked-long-lived-credential path roles don't
have) and `IAM_USER_CONSOLE_NO_MFA`. Tested in `test_iam_user_ciem.py`.

**Also closed:** **dormant identities** — roles + users now carry `last_used_days`
(role `get_role.RoleLastUsed`; user access-key `get_access_key_last_used` +
console `PasswordLastUsed`) and `age_days`. Rule `DORMANT_PRIVILEGED_IDENTITY`
flags a privileged role/user unused > 90d, or never used since creation.
Tested in `test_iam_user_ciem.py`.

**Gap (what actually remains):**
- **Multi-hop role chains** — A can assume B can assume admin C. `AssetGraph`
  has `CAN_ASSUME` edges but path enumeration doesn't chain role→role→admin.
- **Kubernetes-to-cloud identity mapping** (IRSA/pod-identity → IAM role).
- **Permission-level reachability** — "what resources can this identity
  actually touch," beyond the privesc/admin heuristics.
**Recommendation:** multi-hop chains + reachability are the larger,
genuinely multi-week pieces — do them only if identity risk is a stated
priority. The cheap slices (users, dormant) are done.
**Priority:** Medium (was overstated as High/largest-gap; the highest-value
pieces are already shipped).

### 4.5 Config risk vs. data risk not connected
**Current state:** `dspm/engine.py` + `dspm/stores.py` classify RDS, EBS
snapshots, DynamoDB, Secrets Manager, and SSM parameters for sensitivity;
S3 public/encryption posture is covered by `rules.py` (`rule_public_bucket`,
`rule_unencrypted_database`, etc.). `scanner/secrets_scanner.py` covers
hardcoded-secret detection.
**Gap:** DSPM sensitivity scores and posture findings live in separate
tables (`DspmFinding` vs `Finding`) with no join — a public bucket finding
doesn't know if DSPM classified that same bucket as containing PII.
**Recommendation:** add `dspm_finding_id` (nullable FK) to `Finding`, or a
query-time join on `resource_id`, so the UI can show "public + contains
customer PII" as one elevated finding instead of two unrelated rows.
**Priority:** Medium — moderate effort, directly improves prioritization
quality.

### 4.6 Multi-cloud normalization is shallow outside AWS
**Current state:** `inventory/aws_raw_collector.py` is 554 lines with a
real `OPERATIONS` registry, enrichment hooks, and global-service handling.
`inventory/azure_collector.py` and `inventory/gcp_collector.py` are 77 and
85 lines respectively — each exposes a single `collect()` method.
`check_registry.py` has exactly one Azure check (`AzureMFAEnabledCheck`,
`AzureStorageAccountHTTPSCheck`) and one GCP check
(`GCPServiceAccountKeyRotation`) versus ~10+ AWS checks plus the full
`rules.py` engine.
**Gap:** Azure/GCP are stub-depth — enough to onboard an account and show
*something*, not enough to claim parity with AWS coverage. This should be
stated plainly in any customer-facing materials until closed.
**Recommendation:** if multi-cloud is a near-term sales requirement, budget
this as its own project (mirror `aws_raw_collector.py`'s operation-registry
pattern per provider) rather than an incremental add.
**Priority:** High if multi-cloud customers are in the pipeline; otherwise
Low — don't invest ahead of demand.

### 4.7 Fast-changing/new services outpace rules
**Current state:** rule coverage is hand-authored in `rules.py` and
`check_registry.py`; no generative or config-driven rule authoring beyond
`core/policy_engine.py`'s custom-policy evaluator (lets a user define a
declarative rule against `asset_type` + `properties` without a code change).
**Gap:** the custom-policy path (`policy_engine.py:67` `evaluate()`) exists
but isn't advertised or documented as the fast-follow mechanism for new
AWS services — it's the actual answer to this gap and should be surfaced
as such rather than treated as a separate feature.
**Recommendation:** document `policy_engine.py` explicitly as "how to cover
a new service before a hardcoded rule ships" in `docs/MANUAL.md`.
**Priority:** Low (mechanism exists; this is a documentation gap, not a
code gap).

### 4.8 IaC coverage is uneven
**Current state:** `iac/scanner.py` parses Terraform/CloudFormation-ish
YAML/JSON and runs `_check_public_s3`, `_check_unencrypted_storage`,
`_check_open_sg`, `_check_wildcard_iam`, plus CloudTrail/Config checks.
Exposed via `POST /api/inventory/iac/scan` (`inventory_routes.py:746`) —
stateless, content-in/findings-out.
**Gap:** no repository integration at all — no GitHub App, no default-branch
polling, no PR-diff scanning, no mapping from a live resource back to the
IaC line that created it. It's a paste-and-scan tool, not a CI gate.
**Recommendation:** the honest next step is a GitHub Actions / pre-commit
wrapper around the existing `POST /iac/scan` endpoint (thin CI shim) before
attempting a hosted GitHub App integration — reuses the scanner as-is.
**Priority:** Medium — meaningful gap, but the core scanning logic doesn't
need to change, only the trigger surface.

### 4.9 "Continuous" isn't real-time
**Current state:** `api/server.py` runs `_inventory_monitor` and
`_compliance_monitor` on fixed intervals (`ODINEYES_SCAN_INTERVAL_MIN`,
`ODINEYES_COMPLIANCE_INTERVAL_MIN`, both off by default). Separately,
`core/event_listener.py` implements a real CloudTrail/EventBridge-via-SQS
listener for sub-second-latency targeted rescans.
**Gap:** `event_listener.py` is not imported or wired anywhere in
`api/server.py` or `inventory/monitor.py` — it is a complete, working, but
entirely orphaned module. Today "continuous" means "polling on an interval
you must manually enable," full stop.
**Recommendation:** this is the cheapest high-value fix in the whole
document — wire `EventListener` into a background task the same way
`_inventory_monitor` is wired, gated by an `ODINEYES_EVENT_DRIVEN_SCAN`
env var. The hard part (CloudTrail/SQS polling) is already written.
**Priority:** High — real capability sitting unused behind a missing
`import`.

### 4.10 Automated remediation is risky
**Current state:** every finding carries a `remediation` CLI string
(`rules.py:120` `remediation_command()`) and the findings export is
described as auditor/ticketing evidence (`inventory_routes.py:296`) — but
that export is CSV only.
**Gap:** no actual ticketing integration (no Jira/ServiceNow), no PR-based
remediation, no approval workflow. This matches the source material's own
recommendation (ticket/PR over unrestricted auto-apply) — the gap is that
even the ticket half doesn't exist yet, only the CLI-command suggestion.
**Recommendation:** don't build auto-apply. Do build a Jira/GitHub-issue
webhook off new critical/high findings — `inventory/monitor.py` already has
a generic webhook (`ODINEYES_ALERT_WEBHOOK`) that could be pointed at a
ticketing bridge instead of Slack with minimal change.
**Priority:** Medium.

### 4.11 Agentless visibility has technical boundaries
**Current state:** `cloud/agentless_scanner.py` exists for disk/snapshot
inspection; `sensor/tetragon_shipper.py` is the in-workload counterpart
(agent-based, opt-in) for anything agentless can't see.
**Gap:** no explicit documentation of *where* the agentless boundary is
(e.g. deallocated instances, encrypted-with-customer-key volumes, disk-size
limits) — a user can hit a silent gap without knowing it's expected.
**Recommendation:** document known agentless boundaries next to the
Coverage pillar UI (`GET /api/inventory/coverage`) so a `degraded` pillar
status can say *why*, not just *that*.
**Priority:** Low.

### 4.12 Compliance ≠ security (false confidence)
**Current state:** already partially addressed — `compliance_mapper.py`
explicitly marks controls it can't auto-assess as `not_assessed` rather
than silently passing them (see the code comment at
`compliance_mapper.py:26-29`). This is the correct, honest design choice
the source material recommends.
**Gap:** none structurally; the risk is narrative — nothing stops a
dashboard screenshot from being read as "we are secure" rather than "these
specific technical controls are enabled."
**Recommendation:** no code change; keep `not_assessed` visible in every
compliance UI surface rather than defaulting failing/passing views to hide
it.
**Priority:** N/A — already handled correctly, listed here for
completeness.

### 4.13 Tool sprawl / integration quality
**Current state:** Odineyes is architecturally one resource graph, one
`Finding`/`Issue`/`Vulnerability`/`DspmFinding`/`RuntimeEvent` schema, one
API surface — the opposite of sprawl by design.
**Gap:** the sprawl risk here is internal, not external: DSPM and posture
findings don't join (§4.5), runtime and vuln data don't join (§4.1),
identity checks are scattered across `rules.py` and `check_registry.py`
rather than one identity module. The symptoms of sprawl exist inside a
single codebase even without separate tools.
**Recommendation:** treat §4.1 and §4.5's join work as the fix — it's the
same "one accurate resource graph" problem the source material describes,
just internal to this repo instead of across vendor products.
**Priority:** Medium.

## 5. Roadmap summary

Status: ✅ shipped · ◐ partially shipped · ☐ open.

| # | Gap | Status | Priority | Effort | Primary files |
|---|---|---|---|---|---|
| 4.5 | DSPM ↔ posture not joined | ✅ | — | done | `inventory/finding_risk.py`, `inventory/queries.py` |
| 4.2 | Posture findings unweighted | ✅ | — | done | `inventory/finding_risk.py`, `frontend/Findings.tsx` |
| 4.4 | CIEM / identity paths | ◐ | Medium | role+user done; chains/dormant open | `aws_raw_collector.py`, `normalizers.py`, `rules.py`, `issues.py` |
| 4.9 | Event-driven scanning not wired in | ☐ | Medium | not "cheap" — needs a rescan consumer + role-fit rewrite | `api/server.py`, `core/event_listener.py` |
| 4.6 | Azure/GCP shallow | ☐ | High (if multi-cloud demand) | Large — per-provider project | `inventory/azure_collector.py`, `inventory/gcp_collector.py` |
| 4.1 | Runtime ↔ vuln correlation | ☐ | Medium | Medium | `sensor/tetragon_shipper.py`, `inventory/queries.py` |
| 4.8 | IaC has no CI/repo integration | ☐ | Medium | Small (CI shim) → Large (GitHub App) | `iac/scanner.py`, `api/inventory_routes.py` |
| 4.10 | No real ticketing integration | ☐ | Medium | Small–Medium | `inventory/monitor.py` (webhook reuse) |
| 4.13 | Internal data-model sprawl | ◐ | Medium | 4.5 done; runtime↔vuln (4.1) remains | — |
| 4.3 | No ownership/business context | ☐ | Low | Small | `aws_raw_collector.py`, `db/models.py` |
| 4.7 | New-service coverage lag | ☐ | Low | Docs only | `docs/MANUAL.md` |
| 4.11 | Agentless boundaries undocumented | ☐ | Low | Docs only | frontend Coverage pillar |
| 4.12 | Compliance false-confidence | ✅ | N/A | already correct | — |

**Shipped this pass:** 4.5 + 4.2 (findings risk-weighted + DSPM-aware, `ELEVATED`
badge) and the 4.4 user-side CIEM slice. **Correction:** 4.4 and 4.9 were both
overstated in v1 — 4.4's role-side was already strong (only users were missing),
and 4.9's EventListener is not the "cheap wire-up" claimed (it's profile-based,
single-account, blocking — needs a real consumer and a role-fit rewrite).
**Next cheap slice:** 4.4 dormant-identity flags (last-used plumbing half-wired).
