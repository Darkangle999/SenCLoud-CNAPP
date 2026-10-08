# Odineyes

Odineyes is an enterprise-grade CNAPP (Cloud-Native Application Protection Platform) designed to identify, correlate, and visualize multi-hop "toxic combinations" across your AWS cloud infrastructure and source code.

## CNAPP product demo

The frontend includes an isolated demo workspace with sample cloud assets, findings,
attack paths, and compliance views. It does not require AWS credentials or the API.

```bash
cd frontend
npm ci
VITE_DEFAULT_ENVIRONMENT=demo npm run dev
```

Open the local URL printed by Vite. Use a fresh browser session if a previous
environment selection was saved. The demo data illustrates the product experience;
it is not evidence from a live cloud account.

## Quick start — AWS CSPM scan

The CLI can run AWS security checks without Neo4j or Docker. Use an AWS profile
with the read permissions needed by the checks you select.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[aws]'
.venv/bin/odineyes scan --provider aws --region us-east-1 \
  --compliance CIS --format json --output ./odineyes-report
```

Run `.venv/bin/odineyes scan --help` for profiles, filters, and output formats.

### DSPM — Data Security Posture (Wiz-style)

Every live scan classifies data stores across **S3, RDS (+snapshots), EBS
snapshots, DynamoDB, Secrets Manager and SSM**, folding the result back into the
graph so attack paths inherit **data blast-radius** (e.g. "internet → EC2 → role
→ bucket with 2.4M SSNs" is escalated to CRITICAL).

- **Store coverage** (`odineyes/dspm/stores.py`, all read-only): S3 object
  sampling; RDS instance posture (public/unencrypted/IAM-auth — row sampling
  deferred, needs DB creds); RDS + EBS snapshots (public-restore = CRITICAL);
  DynamoDB `Scan(Limit=100)` row sampling; Secrets Manager / SSM rotation posture
  + value classification opt-in via `?secrets=true`. Each scanner is guarded —
  a missing IAM permission skips that store, never crashes the scan.
- **Classification** (`odineyes/dspm/classifier.py`): regex + Luhn-validated
  cards + SSN range-exclusion + AWS keys / JWT / private keys + intl IDs, with
  column/file/path **context scoring** and schema-only column inference.
  Taxonomy: PII / PCI / PHI / CREDENTIAL → mapped to GDPR / PCI-DSS / HIPAA / SOC2.
- **Store risk** (`dspm/engine.py`): `sensitivity × exposure × controls × volume`.
  S3 objects are sampled **read-only** (`list_objects_v2` + ranged `get_object`,
  first 64 KB of prioritized objects). Buckets with no readable objects fall back
  to name/tag heuristics. Verdicts enrich `S3Bucket` nodes + `CAN_ACCESS` edges.
- **UI**: the **Data** tab in the dashboard lists stores by sensitivity with
  per-type findings, risk bars, record estimates, and compliance impact.

Still read-only — DSPM never writes, deletes, or mutates anything.

**Verify it live** (creates a throwaway PRIVATE bucket with synthetic PII, scans
it, tears it down — net-zero account change):

```bash
python scripts/seed_dspm_test.py                 # seed → scan → teardown, exits 0 on PASS
python scripts/seed_dspm_test.py --keep          # leave bucket up for the dashboard
python scripts/seed_dspm_test.py --teardown <bucket>   # clean up a kept bucket
python scripts/seed_dspm_test.py --encrypt       # SSE-S3 on → lower risk score
```

Synthetic data only (fake SSNs, Luhn-valid test cards). PASS = the seeded
`SSN` + `CREDIT_CARD` are detected and the card is checksum-`validated`.

See `LIMITATIONS.md` for exactly what is real vs demonstration.

---


## Prerequisites

Before running the platform or the tests, ensure you have the following installed:

- **Python 3.11+**
- **Neo4j 5.x** (Local or containerized Graph Database)
- **AWS CLI** (Configured with an active profile)

## Environment setup

To securely configure your environment without hardcoding secrets, create a `.env` file from the provided `.env.example`:

```bash
cp .env.example .env
```

You must configure the following variables inside `.env`:

- `ODINEYES_NEO4J_URI`: The Bolt URI to your Neo4j database (e.g., `bolt://localhost:7687`).
- `ODINEYES_NEO4J_USER`: The username for the Neo4j database (defaults to `neo4j`).
- `ODINEYES_NEO4J_PASSWORD`: The password for the Neo4j database.
- `ODINEYES_AWS_REGION`: The AWS region to poll resources from (e.g., `us-east-1`).
- `ODINEYES_AWS_PROFILE`: The AWS CLI profile to use (e.g., `default`).

## Running the full end-to-end test

The end-to-end test orchestrates a multi-layered scan utilizing the live Cloud API Poller, the local Secrets Scanner, and the OSV Client.

### Against your real AWS account (read-only)

You can run the full scan safely against your real environment. Note that **AWS calls are read-only (`describe_*` only)**. No resources are ever created or modified in AWS.

```bash
export $(cat .env | xargs)
python simulate_wiz_attack_path.py \
  --scan-path /home/$USER \
  --neo4j-uri $ODINEYES_NEO4J_URI \
  --neo4j-password $ODINEYES_NEO4J_PASSWORD
```

### Against a local test environment (no AWS needed)

If you prefer testing completely locally without querying real cloud endpoints, you can utilize the synthetic test environments:

```bash
# 1. Seed test secrets (writes dummy AWS keys to /tmp/cs_test)
python scripts/seed_test_secrets.py

# 2. Run the scanner against the seeded test data
python simulate_wiz_attack_path.py \
  --scan-path /tmp/cs_test \
  --neo4j-uri $ODINEYES_NEO4J_URI \
  --neo4j-password $ODINEYES_NEO4J_PASSWORD
```

## Application Workflow

Odineyes operates in a single, unified flow — **collect → graph → analyze → report**:

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. COLLECTION (AWS account → live inventory)                    │
├─────────────────────────────────────────────────────────────────┤
│ • EC2 instances + Security Groups + attached IAM roles          │
│ • S3 buckets (public access, policy, sensitive-name heuristic)  │
│ • IAM roles (trust, inline/managed policies, privilege escalation)
│ • RDS databases (public accessibility, SG exposure)             │
│ • All calls: describe_* / list_* / get_* (read-only)            │
│ • Graceful skip on missing permissions (no failures)            │
└─────────────────────────────────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. GRAPH BUILD (in-memory property graph)                       │
├─────────────────────────────────────────────────────────────────┤
│ Nodes: Internet, EC2, S3Bucket, IamRole, RDSDatabase, …         │
│ Edges: EXPOSED_TO, CAN_ACCESS, CAN_ASSUME, HAS_VULNERABILITY    │
│ • Pure Python (no Neo4j required)                               │
│ • Serializes to dict for JSON APIs                              │
│ • Optionally exports to Neo4j for persistence                   │
└─────────────────────────────────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. TOXIC PATH DETECTION (ToxicPathEngine)                       │
├─────────────────────────────────────────────────────────────────┤
│ Patterns: PUBLIC_COMPUTE_TO_DATA, PUBLIC_S3_EXPOSURE,           │
│           IAM_PRIVILEGE_ESCALATION, CROSS_ACCOUNT_LATERAL, …    │
│ • Contextual risk = exposure × blast radius × data-sensitivity  │
│ • Compliance mapping per finding (CIS/SOC2/NIST/PCI/ISO/HIPAA)  │
│ • De-duped, sorted by risk score                                │
└─────────────────────────────────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. OUTPUT (CLI or API)                                          │
├─────────────────────────────────────────────────────────────────┤
│ CLI:  table + JSON file (stdout + odineyes-graph.json)     │
│ API:  GET /api/live/scan → {account, graph, attack_paths, …}   │
│ Dashboard: React UI connects to API, visualizes graph + findings│
└─────────────────────────────────────────────────────────────────┘
```

**Usage paths:**

- **Standalone scan** (no server): `python aws_cspm_scan.py` or `odineyes graph-scan`
- **Live API** (backend only): `uvicorn odineyes.api.server:app` → manual HTTP calls to `/api/live/*`
- **Full dashboard** (backend + frontend): Both CLI commands above + `npm run dev` → interactive UI

All three read from the same collector → same graph → same attack-path engine. Pick whichever fits your workflow.

## What the output means

At the end of the simulation, the Attack Path Engine will print a summary table of the discovered risks. 

- **INFRASTRUCTURE_EXFILTRATION**: This indicates a critical multi-hop path where a public-facing workload possesses critical vulnerabilities, has access to a sensitive IAM role, and that role has direct permissions to exfiltrate data from an RDS database.
- **K8S_CLUSTER_TAKEOVER**: This indicates a container escape vulnerability chain. It means an external IP routes to a highly-privileged Pod, and that Pod's associated ServiceAccount holds an over-permissioned `cluster-admin` RoleBinding, allowing full cluster compromise.
- **Hop Count**: The length of the graph relationship chain required to execute the attack. A 5-hop path means an attacker must pivot through 5 distinct nodes (e.g., IP -> VM -> Secret -> IAM Role -> DB) to achieve their objective.
- **What to do if zero paths are found**: If no paths are found, it simply means your environment is currently secure against these specific toxic combinations. If you are testing, ensure your target paths meet the precise query configurations.

## Running the dashboard (React + TypeScript)

The dashboard reads the live graph from the FastAPI backend — **no Neo4j
required**. Run both:

### Windows PowerShell

```powershell
# First run creates/installs .venv. Later runs omit -Install.
powershell -ExecutionPolicy Bypass -File .\scripts\start-windows-backend.ps1 -Install

# Separate PowerShell window
Set-Location frontend
npm.cmd run dev
```

The backend uses `%LOCALAPPDATA%\Odineyes\odineyes.db`, so SQLite stays on the
Windows filesystem. It uses the Windows AWS CLI profile `default` by
default; override with `-AwsProfile <profile>`. No WSL is needed for API,
inventory, findings, graph, or account onboarding. Tetragon/eBPF remains a
Linux workload sensor and is not started locally on Windows.

The Windows launcher verifies the selected AWS profile with STS and derives
`ODINEYES_AWS_ACCOUNT_ID` before it starts the API. Configure the profile on
the Windows host with `aws configure --profile default`; do not put
AWS access keys in `.env`, Compose files, or the repository.

### Linux or WSL

```bash
# 1. backend - first run creates a Linux/WSL-only virtual environment.
chmod +x ./scripts/start-linux-backend.sh
./scripts/start-linux-backend.sh --install

# 2. frontend (Vite dev server proxies /api → :8000)
cd frontend
npm install
npm run dev          # open the printed http://localhost:5173
```

The Linux launcher uses `.venv-linux` and stores SQLite data in
`$XDG_DATA_HOME/odineyes/odineyes.db` (normally `~/.local/share/odineyes`). It
therefore works from a checkout shared with Windows without attempting to run a
Windows `.venv` inside WSL. It uses the AWS shared-config profile
`default` by default; override with `--aws-profile <profile>`.

The UI has four views:
- **Dashboard** — account header, stat cards, the interactive attack-path graph
  (internet-exposed nodes highlighted), and a severity breakdown.
- **Attack Paths** — every toxic combination with risk score, plain-English
  explanation, the hop chain, and violated compliance controls. Filter by severity.
- **Inventory** — resources grouped by type (EC2 / S3Bucket / IamRole / RDS / …)
  with their properties, straight from the graph.
- **Settings** — change AWS region, toggle the CVE scan, re-run on demand.

Production build: `npm run build` (output in `frontend/dist/`). Point the build
at a non-localhost backend with `VITE_API_BASE=https://host npm run build`.

## Security notes

- **All AWS calls are `describe_*` only**, never mutating or destructive.
- **Secrets are stored as SHA-256 hashes only**. The raw secret strings are discarded immediately upon discovery in memory and never persisted to the graph.
