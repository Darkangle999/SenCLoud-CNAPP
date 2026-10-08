# Odineyes — What is real vs mock

This file is honest about which parts run against live infrastructure and which
are demonstrations.

## REAL (runs against a live AWS account, read-only)
- **Inventory + findings + attack paths (the spine)** — the single scan stack.
  `inventory/aws_raw_collector.py` collects ~14 account resource types read-only
  (EC2 / Security Groups / S3 / IAM roles / RDS / Lambda / Redshift / …),
  normalizes them, and persists to SQLite. `inventory/rules.py` evaluates
  per-asset + combination findings; `inventory/issues.py` derives multi-hop
  attack-path issues. Driven on demand by `POST /api/live/scan-cycle` and on an
  interval by the `_inventory_monitor` background loop. No Neo4j, no Docker.
  (The former in-memory `ToxicPathEngine` / `graph/security_graph.py` /
  `cloud/aws_collector.py` graph stack and the Neo4j Cypher engine were removed —
  the persisted spine is now the only path.)
- **Attack-path coverage** (`inventory/issues.py`): public S3 exposure,
  internet → EC2 → admin IAM role, internet → EC2 → role → data, IAM privilege
  escalation, cross-account role assumption, internet → public RDS/Redshift.
- **CVE scan (hosts)** — `cloud/cve_scanner.py`: real package inventory via SSM
  `AWS-RunShellScript` (read-only `dpkg`/`rpm`/`pip`) + OSV.dev matching. If an
  instance is NOT SSM-managed it is **skipped, never faked**.
- **Container image scan (CWPP)** — `cloud/trivy_scanner.py`: discovers ECR
  images (latest tag per repo) and runs `trivy image --format json` against each,
  persisting the CVEs to the same `vulnerabilities` table as the host path
  (resource_id = image ref). Requires the `trivy` binary; if it's absent the
  scan is **skipped, never faked**. Trigger: `POST
  /api/inventory/vulnerabilities/scan-images` or the Vulnerabilities page
  "Scan images" button. Host vs container resolve passes are scope-isolated so
  one never resolves the other's findings.
- **Compliance mapping** — each finding maps to CIS/SOC2/NIST/PCI/ISO controls
  (`inventory/rules.py:COMPLIANCE`).
- **Remediation + export** — each finding carries a copy-paste AWS CLI fix
  (`inventory/rules.py:remediation_command`) and is exportable as auditor CSV/JSON
  (`GET /api/inventory/findings/export`).
- **Live CSPM/compliance API** — `api/server.py` `/api/live/cspm` +
  `/api/live/compliance/snapshot` run the boto3 check engine + score frameworks.
- **CSPM misconfiguration checks** — `core/checks_extended.py` real boto3 checks.

## MOCK / DEMONSTRATION (do not present as real coverage)
- **Agentless snapshot scanner** — `cloud/agentless_scanner.py` simulates EBS
  snapshot mount + filesystem scan. The real CVE path is `cloud/cve_scanner.py`.
- **`core/agentless_scanner.py`** — real snapshot/attach orchestration, but only
  runs if a `scanner_instance_id` is configured; CVE findings now come from the
  real `CveScanner` (no more fabricated secrets).
- **eBPF sensor** — see below.
- **Azure / GCP** — collectors are not implemented; this prototype is AWS-focused.

---

## eBPF sensor
The sensor in sensor/ebpf_probe.c has not been validated against a live kernel in this project.
It requires:
  - Linux kernel 5.8+ (for BPF ring buffer support)
  - Kernel headers matching the running kernel
  - Root or CAP_BPF + CAP_PERFMON capabilities
  - BCC installed as a system package

It cannot run on macOS, Windows, or inside an unprivileged container. To test it properly:
  1. Provision a Linux VM (Ubuntu 22.04 recommended)
  2. Install bcc: apt install bpfcc-tools python3-bpfcc
  3. Run: sudo python3 sensor/agent.py

## AWS IAM permissions required
The AwsPoller requires these IAM permissions. It will silently return empty results if they are missing — this looks identical to a clean account.

Required permissions:
  ec2:DescribeInstances
  ec2:DescribeSecurityGroups
  iam:ListInstanceProfiles
  iam:GetInstanceProfile
  iam:ListAttachedRolePolicies
  rds:DescribeDBInstances

## Secrets scanner false positive rate
The current entropy-only detection will:
  - Miss secrets with entropy below 3.5 (e.g. password=letmein, api_key=test123)
  - Flag base64-encoded non-secret config values that happen to have high entropy

To reduce false positives, the scanner only flags high-entropy strings that also appear within 3 lines of a keyword (secret, key, token, password, credential, api).

## Attack path engine coverage
The persisted attack-path engine (`inventory/issues.py`) covers:
  - Public S3 exposure (public bucket, esp. sensitive/unencrypted)  ✅
  - Internet → EC2 → admin IAM role (workload → account takeover)   ✅
  - Internet → EC2 → role → S3 data (exfiltration)                  ✅
  - Internet → EC2 → CVE → role → data (exploit → exfil)            ✅
  - IAM privilege escalation (self-escalation primitives)           ✅
  - Cross-account IAM role assumption (external/`*` trust)          ✅
  - Internet → public RDS                                           ✅

(The in-memory `ToxicPathEngine` and the Neo4j Cypher engine that previously
mirrored these were removed in the dual-stack consolidation — one engine now.)

Not yet covered:
  - Container image CVEs are scanned + persisted (`cloud/trivy_scanner.py`), but
    not yet linked into attack PATHS (vulnerable image → running task → role → data)
  - Lateral movement via VPC peering / network reachability graphs

DSPM: real object sampling is implemented (`dspm/classifier.py` +
`dspm/stores.py`) — S3 ranged-get, DynamoDB scan, Secrets/SSM value
classification into PII/PCI/PHI/credential types. Name/tag heuristics are the
fallback when objects can't be read. Collected each scan cycle via
`InventoryService.scan_dspm`.

## Data freshness
Continuous scanning is implemented (`inventory/monitor.py` + the
`_inventory_monitor` background loop in `api/server.py`). Each cycle runs a full
inventory scan -> findings -> attack-path issues and alerts on findings that
newly cross into open + critical/high. No Celery/APScheduler dependency — it uses
the server's own asyncio loop.

Enable it via env (off by default — live scans cost AWS API calls):
  ODINEYES_SCAN_INTERVAL_MIN=360     # e.g. every 6h; <=0 disables
  ODINEYES_SCAN_REGION=us-east-1
  ODINEYES_SCAN_PROFILE=default      # optional
  ODINEYES_ALERT_WEBHOOK=https://hooks.slack.com/services/...  # optional

Manual trigger: `POST /api/live/scan-cycle`. Cron/systemd (no server) can call
`python -c "from odineyes.inventory.monitor import run_cycle; run_cycle()"`.

Recommended cadence for the other pollers (not yet auto-scheduled):
  osv_client:       every 24 hours
  secrets_scanner:  on every new EBS snapshot
  ebpf_agent:       continuous
