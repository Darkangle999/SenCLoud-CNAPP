# Odineyes — Project Workflow

Odineyes is a CNAPP (Cloud-Native Application Protection Platform) prototype
mapped to the Wiz cloud-security-architecture model: inventory → rules →
attack-path graph → risk → compliance, plus CWPP (vulnerabilities), runtime
threat detection (eBPF), IaC scanning, and DSPM.

**Core principle: real data only, no mock.** A pillar whose source has not
reported (no SSM vuln scan, no eBPF sensor) renders "no data"
honestly — it is never faked.

---

## 1. Data pipeline (cloud resource → finding on screen)

```
                         AWS account
                            │  register: POST /api/inventory/accounts (role_arn)
                            ▼
   ┌─────────── COLLECT ── inventory/aws_raw_collector.py
   │                        raw API dicts: EC2, S3, IAM, RDS, SG, Lambda, …
   │                            ▼
   │            NORMALIZE ── inventory/normalizers.py  (14 asset types)
   │                        → NormalizedAsset (common shape)
   │                            ▼
   │            PERSIST ──── inventory/repository.py  AssetRepository.upsert_assets
   │                        → assets table  (delta + soft-delete + asset_events
   │                          drift trail; idempotent on re-scan)
   │                            │
   │      ┌─────────────────────┼─────────────────────┬───────────────────┐
   │      ▼                     ▼                     ▼                   ▼
   │   RULES                 GRAPH                  RISK             COMPLIANCE
   │  rules.evaluate()    graph.AssetGraph.build  IssueRepository    core/compliance_
   │  (9 rules)           ├ issues.analyze()      .update_asset_risk  mapper.score()
   │  → FindingRepository │  (6 path detectors)   base×exposure×      per-framework
   │    .sync             │  → IssueRepository     blast×freshness     pass/fail
   │  → findings table    │    .sync → issues      (collateral ×0.5)  (CIS/SOC2/NIST/
   │                      └ enumerate_paths()      → asset.risk_score  PCI/HIPAA/ISO)
   │                        every attacker route
   │                        entry→crown-jewel
   ▼
  React pages  ◄── /api/inventory/*  (browser → vite proxy → FastAPI → DB)
```

### Side pillars (separate sources, same store, same UI)
| Pillar | Source | Endpoint | Store |
|---|---|---|---|
| Vulnerabilities (CWPP) | `cloud/cve_scanner.py` SSM pkg inventory → OSV | `POST /api/inventory/vulnerabilities/scan` | `vulnerabilities` |
| Threat detection | eBPF sensor (`sensor/ebpf_agent.py`) | `POST /api/internal/runtime-events` | `runtime_events` |
| IaC security | `iac/scanner.py` (offline) | `POST /api/inventory/iac/scan` | stateless |
| DSPM | live boto3 classification | `GET /api/live/dspm` | live |

---

## 2. Fleet orchestration

`POST /api/inventory/scan-all` → `inventory/orchestrator.py MultiAccountOrchestrator`:
per registered account, STS assume-role → the full collect→persist→rules→graph
pipeline, run in parallel (ThreadPool). sqlite gets a busy-timeout so parallel
writes don't lock out.

---

## 3. UI surfaces (`frontend/src/pages/`)

| Page | Pillar | Reads |
|---|---|---|
| Architecture | posture (Wiz 10 + CIA) | all summaries |
| Inventory | visibility | `/inventory` |
| Identity | IAM / CIEM | `/inventory?type=aws.iam.role` (role admin/privesc/trust flags) |
| Data | data security / DSPM | inventory encryption + `/live/dspm` |
| Findings | misconfig rules | `/findings` |
| Vulnerabilities | CWPP | `/vulnerabilities` |
| Attack paths | toxic combinations | `/graph` (canvas) + `/issues` |
| Threats | runtime | `/runtime-events` |
| IaC | pre-deploy | `/iac/scan` |
| Compliance | frameworks | `/live/cspm` |

Attack-path graph: dagre layout, real AWS service icons (`react-aws-icons`),
motion-drawn edges, route enumeration, fleet/account picker.

---

## 4. Operator workflow

```bash
# ── start ──
python -m uvicorn odineyes.api.server:app --port 8000     # backend
npm --prefix frontend run dev                                  # UI on :5173

# ── register + scan a real account ──
curl -XPOST localhost:8000/api/inventory/accounts \
  -H 'Content-Type: application/json' \
  -d '{"provider":"aws","account_identifier":"<id>","role_arn":"<arn>"}'
curl -XPOST localhost:8000/api/inventory/scan-all \
  -H 'Content-Type: application/json' \
  -d '{"provider":"aws","region":"us-east-1"}'
# → Inventory / Findings / Attack paths / Compliance populate

# ── side pillars ──
curl -XPOST localhost:8000/api/inventory/vulnerabilities/scan \
  -H 'Content-Type: application/json' -d '{"account_identifier":"<id>"}'   # CVEs
sudo ./deploy/install-sensor.sh                                # live eBPF → Threats
# IaC: paste a Terraform/CloudFormation template on the /iac page

# ── test / verify ──
python -m pytest src/odineyes/tests -q                    # ~195 unit tests
python scripts/cnapp_smoke.py                                  # 10-pillar reflection
sudo python scripts/cnapp_smoke.py                             # + REAL eBPF capture
python scripts/e2e_website_test.py --deploy                    # plant lab + full e2e
python scripts/redteam_lab.py destroy --region us-east-1       # tear lab down
```

> ⚠ `scripts/redteam_lab.py` deploys **real internet-exposed vulnerable
> resources** — run only in a throwaway/sandbox AWS account, and always
> `destroy` when done. Everything is tag/prefix-scoped (`odineyes:lab=true`).

---

## 5. eBPF runtime sensor

```
sensor/ebpf_agent.py  (BCC, root)
  attach execve tracepoint → perf buffer → enrich container from /proc/<pid>/cgroup
  → classify severity (tmp-exec/recon/downloader/shell) → POST /runtime-events
  → runtime_events table → Threats page
```
- Real path needs: Linux + root + kernel BTF + python-bcc.
- `--simulate` emits clearly-flagged synthetic events when not root / no bcc.
- Daemon: `deploy/odineyes-sensor.service` (+ `deploy/install-sensor.sh`).

---

## 6. Dev loop

```
edit → backend: pytest + pyflakes   |  frontend: tsc + vite build
     → restart uvicorn / vite HMR
     → scripts/cnapp_smoke.py  (confirm every pillar still reflects)
     → commit per feature
```

Stack: FastAPI + SQLAlchemy (sqlite/Postgres) backend · React + Vite + TypeScript
(motion, dagre, lucide, react-aws-icons) frontend · BCC eBPF sensor · optional
Neo4j projection (best-effort).
```
