# Odineyes — Product Manual

> A cloud security platform (CNAPP) that finds, prioritizes, and explains the
> real attack paths in a company's cloud — built and measured against the same
> architecture model the market leader (Wiz) publishes.

---

## 1. What it is (the one-paragraph version)

Companies run hundreds-to-thousands of cloud resources (servers, databases,
storage, identities). A single misconfiguration — a public storage bucket, an
over-privileged role, an internet-exposed server — can lead to a breach.
**Odineyes continuously inventories a company's cloud, detects these
weaknesses, and — critically — connects them into the *attack paths* an
intruder would actually walk**, ranked by real business risk. It is a
**CNAPP** (Cloud-Native Application Protection Platform): one console covering
posture, identities, data, vulnerabilities, runtime threats, and compliance.

**Guiding principle: real data only.** Every number on screen traces to a live
finding. When a data source has not reported yet, the screen says *"no data"* —
it never fabricates results. This is a trust feature: a CEO or auditor can
believe what the dashboard shows.

---

## 2. Why it matters (business value)

| Problem | Odineyes answer |
|---|---|
| "Are we exposed right now?" | Live posture across every connected account, one dashboard. |
| "Of 500 alerts, what do we fix *first*?" | Attack-path correlation + risk scoring — surfaces the handful that lead to real damage. |
| "Can we pass SOC 2 / PCI / HIPAA?" | Automated mapping of findings to 6+ compliance frameworks. |
| "Did the breach start here?" | Runtime threat detection (eBPF) records what actually executed. |
| "Catch it before it ships" | Infrastructure-as-Code scanning blocks misconfigurations pre-deployment. |

The differentiator vs a long list of alerts: **Odineyes shows the *graph*** —
"Internet → this server → this admin role → your customer data" — so teams fix
the link that breaks the chain, not 500 disconnected tickets.

---

## 3. The ten security pillars (and our status)

Mapped to the Wiz *Cloud Security Architecture* model. Honest maturity:

| # | Pillar | What it does | Status |
|---|---|---|---|
| 1 | **Visibility** | Inventory every cloud asset, track drift | ✅ Production |
| 2 | **Identity (CIEM)** | Flag admin / privilege-escalation / external-trust roles | ✅ Production |
| 3 | **Data security (DSPM)** | Encryption + public-exposure of data stores | ✅ Production |
| 4 | **Vulnerabilities (CWPP)** | Real CVEs on workloads (live OSV + NVD) | ✅ Production* |
| 5 | **Threat detection** | Runtime process monitoring via eBPF | ⚙️ Needs sensor deployed |
| 6 | **Compliance** | Findings → CIS, SOC 2, NIST, PCI, HIPAA, ISO | ✅ Production |
| 7 | **IaC security** | Scan Terraform / CloudFormation pre-deploy | ✅ Production |
| 8 | **Continuous monitoring & risk** | Risk scoring + fleet-wide scheduled scans | ✅ Production |
| 9 | **Automation & integration** | Parallel fleet orchestration, suppression | ✅ Production |
| — | **Attack-path graph** | Correlates all of the above into walkable paths | ✅ Production |

\* CWPP requires the target servers to be SSM-managed (AWS-managed); others are
reported as "not scannable", never faked.

⚙️ = the engine is built and tested; it needs an agent deployed in the
customer environment to produce data. This is normal for runtime
security (they require something running where the workloads run).

---

## 4. How it works (plain-English flow)

```
   Connect a cloud account (read-only role)
        │
        ▼
   1. COLLECT    pull every resource (servers, storage, identities, …)
   2. NORMALIZE  put them in one common shape
   3. ANALYZE    ├─ rules        → individual misconfigurations
                 ├─ graph        → connect them into attack paths
                 ├─ risk score   → rank by business impact
                 └─ compliance   → map to frameworks
        │
        ▼
   Dashboard: posture, attack-path map, prioritized fixes
```

Add-on sensors feed the same dashboard:
- **Vulnerability scan** — reads installed software, matches live CVE databases.
- **eBPF runtime sensor** — watches the Linux kernel for what executes.
- **IaC scan** — checks a deployment template *before* it goes live.

---

## 5. The console (what you'll see in a demo)

| Screen | Shows |
|---|---|
| **Architecture** | The 9-pillar scorecard + the CIA triad (Confidentiality/Integrity/Availability) — the "are we secure?" one-pager. |
| **Attack paths** | The signature view: an interactive graph (Internet → server → role → data) with real cloud icons; click a finding to see the full chain, why it matters, and the fix. |
| **Inventory / Identity / Data** | Every asset, every risky identity, every data store and its encryption status. |
| **Findings / Vulnerabilities** | Misconfigurations and real CVEs, ranked by severity, each linking to NVD/MITRE. |
| **Threats** | Live runtime events from the eBPF sensor. |
| **IaC** | Paste a deployment template, get instant misconfiguration findings. |
| **Compliance** | Score per framework with pass/fail per control. |

---

## 6. Running a demo (technical operator)

```bash
# Start the platform
python -m uvicorn odineyes.api.server:app --port 8000   # backend API
npm --prefix frontend run dev                                # console (http://localhost:5173)

# Connect an account and scan it
#   (register account with a read-only role, then:)
POST /api/inventory/scan-all     → inventory, findings, attack paths, compliance populate

# Optional sensors
POST /api/inventory/vulnerabilities/scan   → real CVEs
sudo ./deploy/install-sensor.sh            → live eBPF runtime monitoring
```

**Built-in test harnesses (proof it works):**
```bash
python -m pytest src/odineyes/tests    # ~195 automated tests
python scripts/cnapp_smoke.py               # checks all 9 pillars reflect in the console
python scripts/e2e_website_test.py --deploy # plants a vulnerable lab, proves detection end-to-end
```

There is a **safe red-team lab** (`scripts/redteam_lab.py`) that deploys
deliberately-vulnerable resources in a throwaway sandbox so the platform's
detection can be demonstrated, then torn down.

---

## 7. Honest limitations (say these to the CEO before they ask)

- **Prototype, not yet a hosted product.** Runs locally / self-hosted today; no
  multi-tenant SaaS, billing, or SSO yet.
- **AWS is deepest.** Azure/GCP collectors exist but AWS coverage is the most
  complete.
- **Runtime detection needs deployment** in the customer environment to
  produce data (inherent to that category).
- **Vulnerability scanning** covers AWS-managed (SSM) Linux servers today.
- Single-node database (SQLite/Postgres); scale-out not yet hardened.

None of these are faked around — the product is explicit when a source is
unavailable. That honesty is a selling point with security buyers and auditors.

---

## 8. Technology (for the technical due-diligence question)

- **Backend:** Python, FastAPI, SQLAlchemy (SQLite / PostgreSQL).
- **Frontend:** React, TypeScript, Vite; animated graph (motion + dagre), real
  AWS service icons.
- **Security data:** OSV.dev + NVD (vulnerabilities), eBPF/BCC (runtime),
  boto3 (AWS).
- **Quality:** ~195 automated tests, per-pillar smoke + full end-to-end harness.
- **Optional:** Neo4j graph projection.

---

## 9. One-line pitch

> "Odineyes tells you the *one* path an attacker would take through your
> cloud to reach your crown jewels — and exactly how to cut it — instead of
> drowning your team in disconnected alerts."

---

*See also: [WORKFLOW.md](WORKFLOW.md) (architecture + operator commands),
[CSPM_MVP_PLAN.md](CSPM_MVP_PLAN.md) (build plan).*
