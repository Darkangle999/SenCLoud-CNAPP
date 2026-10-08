# Odineyes CSPM: Detailed Real-World Problem Statement

Status: product and research problem statement  
Evidence companion: ODINEYES_REAL_WORLD_CSPM_CASE_STUDIES.md  
Scope: cloud infrastructure, identity, data, CI/CD, and runtime exposure

## 1. The problem in plain language

Cloud infrastructure users do not primarily fail because they have never heard of a security best practice. They fail because the security-relevant facts of one environment are split across many places, change continuously, and have to be understood together before anyone can tell whether a finding is urgent.

A cloud security analyst may see:

- a public security group in AWS;
- a critical vulnerability in a container image;
- a workload role with broad S3 access;
- an exposed CI/CD token;
- a storage account containing customer data; and
- a new suspicious process on the same workload.

Each tool normally reports one fragment. The analyst has to manually determine whether those fragments form a real path from an attacker to a sensitive asset. In a large environment, that work is slow, inconsistent, and frequently postponed behind alert volume.

The core problem Odineyes must solve is therefore:

> How can a cloud-security team continuously determine which combinations of configuration, identity, workload, pipeline, data, and runtime behavior create a credible route to business-critical assets, and then give the responsible person the smallest safe remediation action?

This is not only a compliance reporting problem. It is an operational decision problem.

## 2. Case-study-aligned problem statements

Each problem statement below is deliberately paired with a documented incident. This prevents Odineyes from describing generic product features without explaining the real failure, the affected users, and the decision the product must improve.

### Problem statement 1: Configuration drift can silently create long-lived data exposure

**Real-world case: Toyota cloud-configuration exposure, 2023**

Toyota reported that portions of customer information had potentially been externally accessible because of cloud-environment misconfiguration. The affected exposure window extended across multiple years. The key lesson is not simply that a configuration was wrong. It is that the environment did not reliably surface the business impact of that configuration change quickly enough.

**What cloud users face**

A platform engineer may make a temporary policy, networking, or storage change to unblock an application. The change is later inherited, overridden, copied to another account, or left in place after the incident is over. Security teams often only see the resource after a periodic assessment. The data owner may not know the resource is externally reachable, and the security team may not know whether the resource contains customer or regulated data.

**Why current controls fail**

- Annual audits and occasional manual reviews only see a point in time.
- IaC review does not detect console changes, inherited policies, or changes made in a different account or region.
- Public-access checks often lack data classification, ownership, and historical change evidence.
- A finding may be assigned to a generic cloud queue instead of the team that owns the service and data.

**Actual operational consequence**

The organization cannot answer when the exposure started, which change introduced it, what data was reachable, whether it was accessed, and whether the remediation closed every equivalent path.

**Odineyes problem to solve**

Odineyes must continuously discover resources across accounts and regions, compare expected and observed state, retain a change timeline, identify public or effective external access, attach data sensitivity and ownership, and verify the path after remediation.

**Decision Odineyes should produce**

> This customer-data store became externally reachable after this policy change. It has been exposed since this timestamp. The data owner is this team. Remove this policy statement or restrict this principal/CIDR, then re-evaluate effective access to confirm closure.

---

### Problem statement 2: Exposed cloud credentials cannot be prioritized without permission and data context

**Real-world case: Microsoft overly-permissive Azure Storage SAS token, 2023**

Microsoft reported that an employee had shared a blob-storage URL containing an overly permissive SAS token in a public GitHub repository. The token granted access to internal storage information. Microsoft also reported that an earlier detection had been marked as a false positive.

**What cloud users face**

Developers, security engineers, and incident responders regularly receive alerts for keys, tokens, signed URLs, connection strings, and credentials in repositories, tickets, build logs, and collaboration tools. Most teams cannot quickly determine whether a discovered string is active, what it can access, whether it is network restricted, whether it expires soon, or whether the target store is sensitive.

**Why current controls fail**

- Secret scanning treats a token as text rather than an authorization capability.
- Cloud IAM and storage permissions are reviewed separately from repository findings.
- Triage systems make it easy to dismiss a noisy finding without requiring evidence of expiry, revocation, or access scope.
- Static credentials often remain valid after a repository cleanup because the underlying credential was never rotated.

**Actual operational consequence**

The team either investigates every secret alert manually or learns to ignore them. Both outcomes are dangerous: the first consumes scarce analyst time; the second allows a valid high-scope credential to remain usable until an external party discovers it.

**Odineyes problem to solve**

Odineyes must link an exposed secret to its cloud principal or storage capability, calculate effective scope, expiry, permissions, target data sensitivity, and network restrictions, then guide rotation and verify that old access no longer works.

**Decision Odineyes should produce**

> This repository-exposed capability remains active for 21 days and permits read access to a production storage account containing customer records. Revoke or rotate the token, remove the repository secret, and verify that the previous token no longer authorizes storage access.

---

### Problem statement 3: CI/CD systems are production identity systems, not only developer tools

**Real-world case: CircleCI secrets incident, 2023**

CircleCI reported that malware on an engineer's laptop stole a valid 2FA-backed SSO session. The company advised customers to rotate secrets stored in the platform because customer environment variables, keys, and third-party tokens may have been exposed.

**What cloud users face**

CI/CD platforms routinely hold credentials that deploy production software, modify cloud infrastructure, assume cloud roles, access Kubernetes clusters, publish artifacts, and read data. Those permissions are often configured by application teams and not included in the cloud security inventory. A security team may know a token was exposed but cannot identify every AWS account, role, cluster, or data store it can reach.

**Why current controls fail**

- MFA protects interactive login but does not fully prevent session theft or malware-based credential theft.
- Pipeline secrets and environment variables are invisible to CSPM asset graphs.
- Repositories, build runners, and deployment roles are owned by separate teams and stored in separate systems.
- Credential rotation is often a manual checklist with no proof that the old secret stopped working.

**Actual operational consequence**

A compromise in a developer-facing system becomes a cloud-production incident. During response, teams must scramble to discover which secrets existed, where they were used, which roles they could assume, and whether they have all been revoked.

**Odineyes problem to solve**

Odineyes must model CI/CD workflows, runners, secrets, OIDC federation, deployment identities, and cloud roles as one privilege chain. It must turn an incident into an evidence-backed rotation queue rather than a broad instruction to rotate everything blindly.

**Decision Odineyes should produce**

> This CI/CD environment variable can assume this production deployment role, which can modify this Kubernetes cluster and access these data stores. Rotate the credential, invalidate existing sessions, replace static access with short-lived federation, and verify the retired identity cannot obtain a new cloud session.

---

### Problem statement 4: Stolen or stale identities remain exploitable when authentication and network controls are incomplete

**Real-world case: UNC5537 Snowflake customer-account campaign, 2024**

Mandiant reported that the campaign used stolen customer credentials to access Snowflake customer instances. It identified recurring factors including missing MFA, credentials that remained valid long after theft, and absent network allow lists.

**What cloud users face**

Organizations have thousands of users, service accounts, access keys, tokens, and role sessions. Some are created for contractors, migrations, integrations, emergency access, or historical applications. Their owners change, their last use is unclear, and their effective access grows over time through group membership, policy inheritance, cross-account roles, or service integrations.

**Why current controls fail**

- IAM dashboards show policy attachments but do not always calculate effective, cross-system access.
- MFA reporting may cover console users but omit SaaS identities, service credentials, and federated paths.
- Key age is tracked without showing whether the credential can access sensitive production data.
- Network allow lists are treated as a separate network control, not an identity-risk reduction.

**Actual operational consequence**

A credential stolen months or years ago can still grant access. The security team has no concise way to determine blast radius, prioritize rotation, or decide which identities need both credential and network restrictions first.

**Odineyes problem to solve**

Odineyes must continuously identify MFA gaps, stale credentials, inactive but high-privilege principals, missing network restrictions, role chains, and the sensitive data each principal can access. It must prioritize the combination rather than any single control.

**Decision Odineyes should produce**

> This identity has no MFA, has not rotated its credential in 380 days, is not restricted by an allow list, and can export sensitive analytics data. Disable or rotate the credential, enforce MFA, restrict trusted network locations, and review the least-privilege role grants.

---

### Problem statement 5: A software supply-chain compromise can become a cloud-control-plane compromise

**Real-world case: tj-actions/changed-files compromise, 2025**

GitHub's advisory for CVE-2025-30066 states that compromised action tags pointed to malicious code that extracted CI/CD secrets from runner memory and exposed them in workflow logs. The incident affected a large number of repositories because a trusted third-party component was mutable.

**What cloud users face**

Application teams depend on third-party actions, packages, containers, modules, templates, and build plugins. These dependencies can execute with access to secrets and cloud deployment credentials. A security team may inventory workload vulnerabilities but not the CI/CD dependency that can read a cloud credential before the workload is even built.

**Why current controls fail**

- Teams pin dependency names or tags rather than immutable versions.
- Dependency posture, runner access, workflow secrets, and cloud permissions are not connected in one model.
- Build logs can become an accidental secret store.
- A repository compromise is classified as an engineering issue rather than a cloud access incident.

**Actual operational consequence**

An attacker who compromises a build dependency may acquire valid cloud credentials without attacking the cloud account directly. The response must cover source control, runners, logs, secret rotation, and downstream cloud privileges at the same time.

**Odineyes problem to solve**

Odineyes must extend its asset graph beyond cloud-native resources to include repositories, workflows, third-party actions, runners, secret sources, and the cloud identities those systems can use. It must identify mutable dependencies that can reach production credentials.

**Decision Odineyes should produce**

> This mutable third-party workflow action executes on a runner that holds a token capable of assuming this production role. Pin the action to a reviewed immutable commit, rotate all secrets exposed to affected runs, invalidate workflow logs where possible, and verify the replaced token cannot assume the role.

---

### Problem statement 6: The team must distinguish a theoretical attack path from active malicious behavior

**Supporting evidence: all five cases, plus runtime investigation needs**

The previous cases show potential paths through configuration, identity, credentials, and pipelines. During an active incident, security teams still need to know whether the exposure is being used. A static CSPM finding cannot prove that a process ran, a shell spawned, credentials were accessed, or an unexpected connection occurred.

**What cloud users face**

Analysts either escalate every high-severity posture finding as if exploitation is occurring, or they delay response while querying host logs, Kubernetes logs, audit trails, and EDR tools separately.

**Why current controls fail**

- CSPM is static and resource-oriented.
- Runtime tools are event-oriented and frequently disconnected from cloud identity and data context.
- Analysts cannot quickly link a suspicious process to the workload role, reachable data, vulnerability, and network exposure that make it important.

**Odineyes problem to solve**

Odineyes must correlate runtime evidence from supported hosts and clusters with the CSPM graph. The planned Tetragon integration should increase confidence only when a runtime event maps to a real cloud exposure path.

**Decision Odineyes should produce**

> This internet-reachable workload with a critical deployed vulnerability spawned a shell and accessed a cloud credential path. Its attached role can read this sensitive store. Treat this as a confirmed high-confidence path and isolate or remediate the entry exposure and role permission first.

## 3. What cloud-infrastructure users are actually facing

### 2.1 They do not have one cloud environment

Most organizations operate a connected estate rather than a single AWS account:

- multiple AWS accounts, regions, VPCs, subscriptions, projects, and tenants;
- production, staging, development, and sandbox environments;
- Kubernetes, EC2, serverless, managed databases, storage, queues, and SaaS;
- human users, IAM roles, workload identities, external vendors, and service accounts;
- repositories, CI/CD workflows, runners, artifact registries, and third-party actions;
- security tooling, ticketing systems, SIEM, cloud audit logs, and data-classification tools.

The resources may be owned by different teams. The IAM role is owned by platform engineering, the bucket by a data team, the repository by application engineering, and the network rule by a central cloud team. No single owner sees the complete attack chain by default.

The user problem is not merely "we have too many resources." It is "we cannot reliably answer what exists, who can use it, what it contains, and whether it is reachable right now."

### 2.2 Security state changes faster than manual review

Infrastructure changes through Terraform, CloudFormation, Kubernetes manifests, console changes, CI/CD deployment, incident debugging, and temporary exceptions. A secure environment can become insecure without a breach, simply because:

- a bucket policy overrides a public-access block;
- a new security-group rule permits the internet;
- a database is created outside the approved template;
- encryption, logging, deletion protection, or versioning is disabled;
- an IAM policy is attached for troubleshooting and never removed;
- a new region is enabled but not included in monitoring;
- a developer shares a storage URL or deployment token;
- a role trust policy is edited during cross-account onboarding.

Point-in-time audits answer what was true during the audit. They do not answer what changed yesterday or who changed it. The Toyota case in the evidence document demonstrates the operational consequence: a cloud configuration can remain externally permissive for a long period when continuous detection, ownership, and evidence are absent.

The real user requirement is:

    Expected state -> observed change -> current exposure -> owner -> remediation -> verification

Without this lifecycle, a CSPM becomes a list of snapshots rather than a security control.

### 2.3 Identity is now the primary security perimeter

In cloud environments, the perimeter is not only a firewall. It is the effective authorization of users, roles, workload identities, tokens, SSO sessions, service accounts, resource policies, permission boundaries, and cross-account trust.

A principal that appears harmless in isolation may be able to:

1. Assume another role.
2. Pass a role to a compute service.
3. Modify an IAM policy.
4. Obtain temporary credentials.
5. Read a sensitive store.
6. Disable logging or create a new persistence path.

The Snowflake campaign and CircleCI incident show why this matters. A valid credential or stolen session can be enough to enter a cloud or SaaS environment even when the provider's underlying infrastructure has not been breached. Missing MFA, stale credentials, permissive network access, weak session controls, and overly broad access turn a single identity compromise into data theft.

What users need is not only an IAM policy viewer. They need an effective-access answer:

    Which identity can reach which production resource, by which trust and policy
    relationship, from which external or workload entry point, with what blast radius?

### 2.4 Teams cannot distinguish an exposed secret from an exploitable secret

Secret scanners find strings. Cloud platforms enforce permissions. Data systems contain varying levels of sensitive information. These three facts are usually disconnected.

For example, a token found in a public repository may be:

- expired and harmless;
- restricted to read one non-sensitive artifact;
- active but limited to a private network;
- active with broad storage scope;
- active with access to production data;
- active with the ability to deploy code or assume a high-privilege role.

Treating every discovered token as critical creates alert fatigue. Treating it as low-risk without calculating its effective scope creates dangerous false negatives. The Microsoft SAS-token case illustrates that a token is itself a cloud permission boundary, not merely a leaked string.

The user needs a risk decision that combines:

    Secret exposure x validity x effective permission x reachable data x network context

They also need a rotation workflow that proves the old credential is no longer usable after remediation.

### 2.5 CI/CD is a privileged cloud identity plane

CI/CD systems are often treated as developer tooling outside the CSPM boundary. In practice, they commonly contain deployment credentials, cloud tokens, repository write access, artifact publishing permissions, Kubernetes credentials, and production environment variables.

The CircleCI and tj-actions cases demonstrate the same structural problem from different angles:

- a stolen human session can expose pipeline-held secrets;
- a compromised dependency can execute inside a runner;
- a mutable third-party action can change after a team has approved its name;
- runner-process memory and build logs can expose credentials;
- an exposed deployment secret can laterally move into cloud infrastructure.

For a platform engineer, the problem is that the runner can act like a production administrator but is not modeled as one. For a CISO, the problem is that a software supply-chain incident may silently become a cloud-account incident. For an analyst, the problem is that the repository alert and the cloud access path live in different products.

Odineyes must therefore treat repositories, workflows, runners, third-party actions, secrets, and federated cloud roles as connected assets.

### 2.6 Data risk cannot be inferred from storage configuration alone

A publicly reachable bucket containing public web images and a private bucket containing customer records are not equivalent risks. Encryption state alone does not answer whether data can be read. A strong data-security decision depends on:

- data sensitivity and regulatory classification;
- public, network, and identity exposure;
- effective permissions;
- encryption and key-management state;
- logging and investigation capability;
- environment and business criticality;
- backups, replicas, snapshots, and downstream copies.

Cloud teams face a prioritization trap. A scanner may report thousands of storage findings, but the team must decide which one could cause material customer, financial, operational, or regulatory harm.

The correct question is:

> If this identity, workload, or external actor reaches this data store, what data can they obtain and how serious is that outcome?

### 2.7 Vulnerability lists do not explain workload risk

Trivy, image scanners, and CVE feeds can show vulnerable packages. They do not, by themselves, prove that a vulnerable package is deployed, exposed, reachable, exploitable, or capable of reaching sensitive data.

A CVE needs cloud context:

- Is the affected image running in production?
- Is the workload internet reachable?
- Is a vulnerable service listening on an exposed port?
- Does the workload have a privileged IAM role?
- Can it reach a sensitive datastore?
- Is there a compensating control such as a private subnet, WAF, security group, or service mesh policy?
- Is there runtime evidence that a suspicious process executed?

Without this context, teams spend time patching low-impact packages while a smaller number of exposed, high-privilege workloads remain unresolved.

### 2.8 Static posture does not prove active compromise

CSPM tells a team that an exploit path may exist. It does not usually tell them that a process actually spawned a shell, accessed credentials, opened an unexpected connection, or crossed a container boundary.

This gap creates two bad outcomes:

- analysts overreact to every theoretical path; or
- analysts underreact because they cannot establish confidence quickly.

Runtime evidence, such as the planned Tetragon eBPF integration, can raise confidence when it connects suspicious behavior to an existing cloud path:

    Internet exposure
    -> vulnerable workload
    -> suspicious process execution
    -> attached workload role
    -> sensitive data access

The runtime signal must enrich the CSPM graph. It should not become an isolated event dashboard that produces another alert queue.

### 2.9 Security teams are overwhelmed by isolated findings

Large cloud environments produce many technically valid alerts:

- missing tags;
- unused security groups;
- public endpoints;
- weak TLS settings;
- excessive permissions;
- old keys;
- unsupported images;
- missing logs;
- unencrypted resources;
- dormant users;
- risky repository settings.

Most are not immediately exploitable. A severity label alone does not identify the action that materially reduces risk. The analyst has to manually correlate the finding with asset criticality, network reachability, privilege, data sensitivity, and compensating controls.

This creates alert fatigue, inconsistent triage, and a pattern where teams remediate what is easy to close rather than what is most dangerous.

Odineyes must prioritize decisions, not raw volume:

    What is exploitable now?
    What sensitive asset is reachable?
    Which identity or workload enables the path?
    Who owns the affected resource?
    What is the smallest change that breaks the path?
    How can we verify that the change worked?

### 2.10 Remediation is risky, distributed, and hard to verify

Security teams may know that a role is overprivileged or a security group is open, but the resource owner fears breaking production. Generic remediation text such as "restrict access" is insufficient because it does not say which access is actually required.

Real remediation requires:

- a named owner and service context;
- evidence explaining why the resource is risky;
- the minimum policy, network, or configuration change;
- change-control or pull-request workflow;
- an exception path with expiry and approver;
- rescanning or runtime verification after the change;
- a record that the risk was resolved, accepted, or reopened.

Without verification, a ticket can be closed while the harmful relationship still exists elsewhere through a role chain, resource policy, backup, replica, or stale credential.

## 3. The same problem looks different to each user

| User | What they see today | What they need from Odineyes |
| --- | --- | --- |
| CISO or security leader | A growing count of alerts, unclear breach exposure, and no defensible risk narrative | A small number of material decisions, business impact, coverage gaps, ownership, trends, and evidence for audit or board reporting |
| Cloud security analyst | Multiple tools, duplicate alerts, incomplete asset context, and manual spreadsheets | A normalized graph, confidence-ranked paths, evidence timeline, investigation context, and one remediation queue |
| Cloud or platform engineer | Security tickets that lack application context and may break production | Exact affected resource, required versus risky access, smallest safe change, IaC-ready remediation, and verification |
| DevSecOps or application engineer | Build and deployment secrets, third-party dependencies, and unclear cloud permission impact | Repository-to-runner-to-role mapping, secret exposure scope, immutable dependency controls, and rotation guidance |
| IAM administrator | Policies and trust relationships that are individually understandable but collectively complex | Effective permissions, cross-account paths, stale access, privilege escalation routes, and role-trust validation |
| Data owner or privacy team | Unclear location and access paths for regulated or customer data | Data classification, data-store inventory, public and identity exposure, ownership, and evidence of access |
| Incident responder | Too little context during an investigation and too many places to search | Timeline from configuration change to identity use to runtime event, plus impacted accounts, workloads, roles, and data |

## 4. Failure patterns derived from the case studies

The cited Toyota, Microsoft, CircleCI, Snowflake, and GitHub Action cases are different incidents, but they repeatedly show the same failure patterns.

| Failure pattern | What goes wrong in practice | User consequence | Odineyes requirement |
| --- | --- | --- | --- |
| Long-lived misconfiguration | A cloud resource remains public, unmonitored, or incorrectly configured after the original change | Exposure persists until an audit, researcher, or attacker notices it | Continuous discovery, drift detection, evidence history, and owner assignment |
| Credential without context | A key, SAS, token, or session is exposed but teams cannot determine its real scope | False positives are ignored or material secrets are under-prioritized | Secret-to-identity-to-data correlation, expiry, permission, and network analysis |
| Overprivileged identity | A user, role, runner, or workload can assume, pass, or modify privileged access | One compromise expands into lateral movement and broad blast radius | Effective-access graph and privilege-escalation analysis |
| CI/CD blind spot | Build systems hold secrets or execute untrusted dependencies | Supply-chain compromise reaches production infrastructure | CI/CD inventory, dependency posture, runner identity, and cloud role mapping |
| Weak authentication lifecycle | MFA gaps, stale credentials, session abuse, and absent network restrictions persist | Valid credentials remain usable for a long time after theft | MFA, key-age, inactivity, trusted-network, rotation, and abnormal-use controls |
| Data without sensitivity context | Storage is assessed without knowing what it contains or who can read it | Teams fix low-value findings before customer-data exposure | Classification, ownership, effective access, and impact-aware priority |
| Static-only security evidence | A theoretical path cannot be distinguished from active malicious behavior | Slow incident response and poor prioritization | Runtime evidence correlated to the posture graph |
| Unverified remediation | A ticket is closed but the path continues through another relationship | Repeated exposure and weak audit evidence | Rescan, graph re-evaluation, runtime verification, and exception expiry |

## 5. Formal problem statement

Modern cloud environments distribute security decisions across cloud configurations, identities, trust policies, networks, workloads, source repositories, CI/CD pipelines, data stores, third-party dependencies, and runtime processes. These elements are owned by different teams and change continuously. Existing posture, vulnerability, secret-scanning, IAM, and runtime tools often evaluate them independently. This produces incomplete inventories, disconnected findings, alert fatigue, and remediation decisions that do not account for effective access or business impact.

As a result, organizations struggle to identify which combinations of exposure, vulnerability, identity privilege, data sensitivity, and runtime behavior form a realistically exploitable path to sensitive assets. They also struggle to assign ownership, make a safe corrective change, and verify that the path is actually broken.

Odineyes will address this problem by continuously collecting and normalizing cloud and adjacent security evidence, modeling relationships between identities, workloads, networks, pipelines, data, and findings, detecting both atomic and multi-step risk conditions, and presenting evidence-backed remediation decisions ranked by exploitability, blast radius, and impact.

## 6. Product thesis

Odineyes should not compete only on the number of checks it can run.

Its useful output is a decision such as:

> This production workload is internet reachable. It runs an image with a critical vulnerability. Its attached role can access a customer-data bucket. The workload has now executed a suspicious shell process. Restrict this ingress rule and remove this role permission to break the path. The application team owns the workload; the IAM team owns the role. Rescan and runtime verification will confirm closure.

That is materially more actionable than five separate alerts with five different severity labels.

## 7. Minimum measurable outcomes

The product should be evaluated on whether it improves the user outcomes below:

| Outcome | Example measure |
| --- | --- |
| Asset visibility | Percentage of connected accounts, regions, and supported resource types observed within freshness SLO |
| Exposure detection | Time from a material cloud change to a normalized finding or path reassessment |
| Identity understanding | Percentage of privileged and cross-account trusts modeled with effective-access evidence |
| Risk prioritization | Reduction in high-volume, low-actionability findings shown to analysts without suppressing verified critical paths |
| Remediation quality | Percentage of high-risk paths with owner, precise remediation, and verification state |
| Credential hygiene | Count and age of long-lived credentials, unrotated exposed secrets, and unresolved MFA or allow-list gaps |
| Data protection | Percentage of sensitive stores classified and evaluated for public, identity, and encryption exposure |
| Runtime confidence | Percentage of supported workloads with healthy runtime coverage and time to correlate a confirmed event to a posture path |

## 8. Scope boundary

The problem is broad, so Odineyes should deliver it in layers:

1. Continuous AWS inventory, configuration drift, identity, network, and data-store posture.
2. Effective IAM and cross-account relationship graph with verified onboarding trust excluded from attack paths.
3. Contextual findings and attack-path prioritization.
4. Trivy vulnerability context tied to deployed workloads and exposure.
5. CI/CD and secret relationship modeling.
6. Tetragon runtime evidence for supported Linux EC2 and EKS worker-node workloads.
7. Safe remediation workflow, ownership, verification, and controlled enforcement.

The product must not imply coverage where it does not exist. Unsupported compute, data sources, regions, or runtime platforms should be shown as coverage gaps with a clear next action.

## 9. Evidence references

The incident facts and source descriptions supporting this statement are maintained in:

- ODINEYES_REAL_WORLD_CSPM_CASE_STUDIES.md
- Toyota cloud-configuration exposure, 2023
- Microsoft Azure Storage SAS token exposure, 2023
- CircleCI secrets incident, 2023
- Mandiant UNC5537 Snowflake customer-account campaign, 2024
- GitHub Advisory CVE-2025-30066 for the tj-actions changed-files compromise, 2025

This document distinguishes evidence-supported incident facts from the Odineyes product interpretation. It does not claim that a CSPM alone would have prevented each incident.
