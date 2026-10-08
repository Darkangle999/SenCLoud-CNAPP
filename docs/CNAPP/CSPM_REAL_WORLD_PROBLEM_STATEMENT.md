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

As of September 2026, **most of the individual problems we listed are already addressed to some degree by major CNAPP vendors**. The opportunity is not in simply detecting those conditions; the stronger gap is in **connecting them across infrastructure, identity, code, runtime, data, third parties and business impact, then reasoning about cause and the safest remediation**.

This matters because your current problem statement already aims beyond isolated findings: it wants to determine whether configuration, identity, workload, pipeline, data and runtime behavior form a credible attack route. That general direction is now very much where leading CNAPPs are moving.

### How much of each problem is already solved?

|Problem we discussed|Market status|Vendors already addressing it|Where there is still room|
|---|---|---|---|
|Developer identity → CI/CD → production|🟡 **Partially solved**|Wiz, Prisma Cloud, Microsoft, Orca|Cross-SaaS/session → repo → pipeline → cloud → business impact is still inconsistent|
|Vulnerable internet workload → IAM → data|🟢 **Strongly solved**|Wiz, Prisma, Microsoft, Orca, CrowdStrike|Little differentiation if you only reproduce attack paths|
|Kubernetes SA → cloud IAM escalation|🟢 **Mostly solved**|Wiz, Prisma, Microsoft, CrowdStrike, Orca|Deep effective privilege + runtime confirmation can differentiate|
|Forgotten/shadow cloud assets|🟢 **Mostly solved**|Wiz, Prisma, Orca, Microsoft|Business ownership + historical reason for existence remains weaker|
|Disable logging/security before attack|🟡 **Partially solved**|CrowdStrike, Prisma, Microsoft, Wiz|Modeling **loss of defensive capability** as part of the attack consequence is interesting|
|Indirect privilege accumulation|🟢 **Strongly solved**|Wiz, Prisma, Microsoft, Orca|Causal privilege reasoning and least-disruptive correction are more open|
|Cloud ransomware / recovery destruction|🟡 **Partially solved**|Microsoft, CrowdStrike, Prisma|Primary system + backup + business recovery dependency modeling is a stronger gap|
|Private data exfiltration via legitimate APIs|🟡 **Partially solved**|Microsoft, Prisma, Wiz, Orca|Legitimate access + data movement + business/process context remains difficult|
|Third-party/vendor access → production|🟡 **Partially solved**|Wiz, Prisma, Microsoft, Orca|Supply-chain/vendor dependency graph through to business service remains fragmented|
|Malicious insider using valid permissions|🟡 **Partially solved**|CrowdStrike, Microsoft, Prisma|Behavioral + entitlement + data + business-purpose reasoning is difficult|
|Temporary emergency access becomes permanent|🟢/🟡 **Detection solved; lifecycle partially solved**|Wiz, Prisma, Microsoft, Orca|Understanding _why_ change existed, expiry, incident context and rollback is promising|
|Remediation could cause production outage|🔴 **Not completely solved**|All provide remediation guidance to varying degrees|**Predicting operational impact before applying security remediation is a real opportunity**|

So I would **not** build the product thesis around:

> "CNAPPs cannot correlate cloud risks."

That is no longer defensible.

Microsoft, for example, explicitly builds a multicloud security graph containing assets, internet exposure, permissions, network relationships and vulnerabilities, then searches it for paths from external entry points to critical resources. ([Microsoft Learn](https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-attack-path?utm_source=chatgpt.com "Security explorer and attack paths in Microsoft Defender for Cloud - Microsoft Defender for Cloud | Microsoft Learn"))

Wiz similarly describes its Security Graph as connecting assets, identities, permissions, vulnerabilities and threat activity, with runtime signals used to validate attack paths and code mapping used to trace them back toward the source. ([wiz.io](https://www.wiz.io/academy/detection-and-response/attack-path-analysis?utm_source=chatgpt.com "What is Attack Path Analysis? | Wiz"))

Prisma Cloud's Infinity Graph correlates misconfigurations, vulnerabilities, pipeline risks, exposure, identities, secrets and sensitive data; Palo Alto also describes overlaying active attack activity and tracing issues back toward code. ([Palo Alto Networks](https://www.paloaltonetworks.com/blog/2023/10/announcing-innovations-cnapp-prisma-cloud/?utm_source=chatgpt.com "Prisma Cloud: Darwin Release Introduces Code to Cloud Intelligence"))

Orca says its unified model prioritizes attack paths across misconfigurations, vulnerabilities, malware, identity, sensitive data and APIs, including cross-account and cross-cloud attack paths. ([Orca Security](https://orca.security/?INTCMP=technology-partners_link_&utm_source=chatgpt.com "Orca Security | AI-Powered Cloud Security Platform & CNAPP"))

CrowdStrike similarly markets a CNAPP spanning CSPM, CIEM, DSPM, ASPM and KSPM with runtime protection and attack-path visibility across application, identity and cloud layers. ([CrowdStrike.com](https://www.crowdstrike.com/en-us/resources/reports/2026-frost-radar-for-cloud-native-application-protection-platforms/?utm_source=chatgpt.com "2026 Frost Radar for CNAPPs Report | CrowdStrike"))

## Where I think your stronger research gaps are

The most interesting gap is **not Attack Path Analysis 2.0**. Wiz, Prisma, Orca and Microsoft are already too strong there.

Your proposed system becomes much more interesting if you move from:

```text
What can the attacker reach?
```

to:

```text
WHY does this attack path exist?
        ↓
Which change caused it?
        ↓
Who/what business process depends on it?
        ↓
What control breaks the path?
        ↓
What else will that control break?
        ↓
What residual attack paths remain?
        ↓
Does the proposed control satisfy the required
security/compliance obligation?
```

That is substantially closer to your earlier **Federated Causal Cyber Resilience Twin** idea.

---

# Gap 1 — Causal root-cause reasoning

Current platforms are very good at:

```text
Internet
 ↓
Vulnerable workload
 ↓
IAM role
 ↓
Sensitive database
```

But there is another question:

> **Why did this path come into existence?**

Imagine this:

```text
Monday
Terraform policy = secure

Tuesday
Developer emergency change
        ↓
IAM permission added

Wednesday
New deployment inherits role

Thursday
Network rule changed

Friday
Workload becomes externally reachable
```

A CNAPP can tell you:

> There is an attack path.

Your system should tell the security engineer:

> **The attack path exists because change A combined with deployment B and inherited policy C. Before Tuesday this path was impossible.**

That is a different level of reasoning.

---

# Gap 2 — Remediation blast-radius prediction

This is probably one of the strongest problems in your whole proposal.

Current CNAPP:

> Remove `s3:GetObject`.

Your proposed system:

> Removing `s3:GetObject` closes Attack Paths 18, 23 and 42.

But then:

> Payment service A depends on `GetObject` against `prod-payment-config/*`.

Therefore:

```text
Security remediation
        ↓
Attack path ↓
        BUT
Application dependency affected
        ↓
Potential outage
```

The system should calculate:

```text
Security benefit
      versus
Operational impact
```

and recommend:

```text
Do NOT remove GetObject completely.

Current:
s3:GetObject → *

Recommended:
s3:GetObject →
arn:aws:s3:::prod-payment-config/*
```

That is considerably more useful than:

> "Least privilege is recommended."

Your current material already identifies the practical problem: resource owners fear security remediation because generic recommendations might break production.

### I would make this a major research problem.

---

# Gap 3 — Business-process attack paths

Most CNAPP graphs terminate around:

```text
Database
S3 bucket
Key Vault
Admin role
Kubernetes cluster
```

But the CISO does not actually care primarily about:

> `prod-db-0342`

They care that:

```text
prod-db-0342
      ↓
Payment Database
      ↓
Payment Processing Service
      ↓
Checkout
      ↓
42% of company revenue
```

Now an attack path becomes:

```text
Internet
  ↓
API
  ↓
RCE
  ↓
Kubernetes service account
  ↓
AWS role
  ↓
Payment database
  ↓
Payment Processing
  ↓
Checkout unavailable
  ↓
Revenue/customer impact
```

That moves from a **cloud security graph** toward a **cyber resilience graph**.

That remains a much stronger differentiation direction.

---

# Gap 4 — Cross-domain infrastructure, not only cloud

Most CNAPPs are fundamentally cloud-centered even when integrations expand outward.

Your original idea becomes substantially more defensible if the graph covers:

```text
Internet
 ↓
SaaS
 ↓
Employee identity
 ↓
GitHub
 ↓
CI/CD
 ↓
AWS
 ↓
Kubernetes
 ↓
On-prem API
 ↓
Active Directory
 ↓
ERP
 ↓
Third-party supplier
 ↓
Business service
```

Instead of:

```text
AWS
Azure
GCP
Kubernetes
```

The question becomes:

> **Can we calculate an attack path across the enterprise rather than merely across the cloud environment?**

That pushes you closer to:

**Federated Cyber Exposure / Resilience Management**

rather than another CNAPP.

---

# Gap 5 — Control simulation before remediation

This is particularly interesting.

Suppose you find:

```text
Attacker
 ↓
Web application
 ↓
IAM role
 ↓
Customer database
```

Instead of merely recommending controls, let the analyst simulate them.

### Simulation A

```text
Remove public ingress
```

Result:

```text
Attack path: CLOSED
Application availability: FAILED
Customers affected: YES
```

### Simulation B

```text
Restrict IAM role
```

Result:

```text
Attack path: CLOSED
Application availability: NORMAL
Affected workload calls: 0
Compliance improvement: YES
```

### Simulation C

```text
Introduce WAF rule
```

Result:

```text
Attack path: REDUCED
Residual identity path: EXISTS
```

Now you're answering:

> **What happens if I implement this security control?**

That is much less commoditized than displaying an attack graph.

---

# Gap 6 — Compliance-aware remediation

Another potentially strong differentiator is joining attack-path reasoning with obligation reasoning.

For example:

```text
Customer PII
 ↓
Publicly reachable workload
 ↓
Overprivileged identity
```

System identifies:

```text
Technical risk:
Data disclosure

Business asset:
Customer records

Applicable obligations:
PCI DSS / ISO 27001 / SOC 2 / internal policy
```

Then proposed change:

```text
Restrict IAM permission
```

The engine evaluates:

```text
Does it close attack path?        YES
Does application still work?      YES
Does it satisfy control intent?   YES
Evidence produced?                YES
```

So you're connecting:

**Threat → Control → Operational impact → Compliance**

That combination is much less common than traditional CNAPP reporting.

---

# Gap 7 — "What happened?" + "What could happen?" in one model

CNAPP commonly separates:

### Posture

```text
Could happen
```

from:

### Runtime detection

```text
Is happening
```

Your model could add another stage:

```text
Could happen
    ↓
Likely to happen
    ↓
Currently happening
    ↓
Already happened
```

For example:

```text
Internet exposed workload
        ↓
Critical CVE
        ↓
Exploit observed
        ↓
Shell spawned
        ↓
Metadata queried
        ↓
AWS role assumed
        ↓
S3 data accessed
```

Then confidence could move:

```text
Potential path       35%
Reachable path       60%
Exploit observed     82%
Credential used      95%
Data accessed        99%
```

That gives the incident responder a much more understandable risk narrative.

Your existing material already recognizes the weakness of static posture alone and the need to connect runtime evidence back into the posture graph.

---

# So where does your product stand against the market?

I would position it like this:

| Capability                                            |             Wiz |          Prisma |  Microsoft |                           Orca | CrowdStrike |     Proposed system |
| ----------------------------------------------------- | --------------: | --------------: | ---------: | -----------------------------: | ----------: | ------------------: |
| CSPM                                                  |               ✅ |               ✅ |          ✅ |                              ✅ |           ✅ |                   ✅ |
| CIEM                                                  |               ✅ |               ✅ |          ✅ |                              ✅ |           ✅ |                   ✅ |
| Vulnerability context                                 |               ✅ |               ✅ |          ✅ |                              ✅ |           ✅ |                   ✅ |
| DSPM                                                  |               ✅ |               ✅ |          ✅ |                              ✅ |           ✅ |                   ✅ |
| Kubernetes                                            |               ✅ |               ✅ |          ✅ |                              ✅ |           ✅ |                   ✅ |
| Runtime                                               |               ✅ |               ✅ |          ✅ | ✅/partial depending deployment |           ✅ |                   ✅ |
| Code → cloud                                          |               ✅ |               ✅ |          ✅ |                              ✅ |           ✅ |                   ✅ |
| Attack paths                                          | **Very strong** | **Very strong** | **Strong** |                **Very strong** |  **Strong** | ⚠️ Not enough alone |
| Attack → runtime correlation                          |               ✅ |               ✅ |          ✅ |                              ✅ |           ✅ | ⚠️ Not enough alone |
| **Causal "why did path appear?"**                     |              🟡 |              🟡 |         🟡 |                             🟡 |          🟡 |       **🟢 Target** |
| **Remediation operational impact simulation**         |              🟡 |              🟡 |         🟡 |                             🟡 |          🟡 |       **🟢 Target** |
| **Security-control what-if simulation**               |              🟡 |              🟡 |         🟡 |                             🟡 |          🟡 |       **🟢 Target** |
| **Business-process dependency mapping**               |              🟡 |              🟡 |         🟡 |                             🟡 |          🟡 |       **🟢 Target** |
| **Cloud + on-prem + SaaS + third-party causal graph** |              🟡 |              🟡 |         🟡 |                             🟡 |          🟡 |       **🟢 Target** |
| **Control → compliance obligation reasoning**         |              🟡 |              🟡 |         🟡 |                             🟡 |          🟡 |       **🟢 Target** |
| **Predict resulting business impact**                 |           🔴/🟡 |           🔴/🟡 |      🔴/🟡 |                          🔴/🟡 |       🔴/🟡 |       **🟢 Target** |

The 🟡 entries don't mean those vendors have zero capability; several are rapidly adding AI, automation, ownership, workflows and remediation. They mean I would **not currently characterize these functions as uniformly solved in the same causal, business-impact-aware way you're proposing**.

## This changes your core problem statement

I would stop describing the research problem as:

> **Organizations cannot identify attack paths in complex cloud infrastructure.**

The market has largely solved that at a useful level.

A much stronger research problem is:

> **Modern security platforms can increasingly identify attack paths across cloud configuration, identity, workloads, code, data and runtime. However, security teams still struggle to determine why a risky path came into existence, which business services depend on the affected relationships, which remediation will break the attack path without disrupting legitimate operations, what residual risk will remain after the change, and whether the resulting control satisfies required security and compliance obligations.**

Then your proposed system becomes:

```text
              Federated Causal Cyber Resilience Twin

                         OBSERVE
                           │
             ┌─────────────┼──────────────┐
             ↓             ↓              ↓
         Cloud          On-Prem         SaaS
             ↓             ↓              ↓
         Identity ─── Applications ─── Third Party
             │
             ▼
       CAUSAL SECURITY GRAPH
             │
     ┌───────┼─────────┐
     ▼       ▼         ▼
   WHY?    WHAT IF?   SO WHAT?
     │       │         │
Root cause  Control   Business
 analysis  simulation impact
     │       │         │
     └───────┼─────────┘
             ↓
      SAFE REMEDIATION
             │
             ▼
       COMPLIANCE CHECK
             │
             ▼
       VERIFY CLOSURE
```

**That** is considerably harder for me to point at and say, "Wiz already does the whole thing," or "Prisma already does the whole thing."

And that is exactly where I would concentrate the research—not on building **another CNAPP**, but on developing the **causal decision and simulation layer above CNAPP/EDR/IAM/DSPM/CMDB/business-service data**.

If you want, the next useful research step is a **feature-by-feature competitive gap analysis of Wiz vs Prisma Cloud vs Microsoft Defender for Cloud vs Orca vs CrowdStrike against your proposed Causal Cyber Resilience Twin**, marking each capability as `Solved / Partially Solved / Unsolved / Research Opportunity`. That would tell us much more precisely which problem statement is defensible for a paper or new product.
# Adaptive Counterfactual Cyber Intervention Planning

## 1. Background

Modern cybersecurity platforms have become increasingly capable of discovering assets, identifying vulnerabilities and misconfigurations, calculating attack paths, connecting exposures to critical business assets, correlating runtime evidence, prioritizing risk, recommending remediation, automating changes, and validating whether specific security controls are effective.

Therefore, the research problem should **not** be framed as:

“Organizations cannot identify attack paths.”

It should also not be:

“Organizations do not know what to remediate.”

Nor should it simply be:

“Security teams do not know whether remediation will break production.”

These problems are increasingly addressed by commercial CNAPP, exposure-management, attack-path, breach-and-attack-simulation, cyber-risk and automated-remediation platforms.

The remaining problem occurs **after an exposure has been understood but before the defender changes the environment**.

---

## 2. Core problem

A security team may know:

> An internet-facing workload can be exploited, its workload identity can access a sensitive database, and removing a particular permission will break the known attack path.

But that does not answer several critical questions.

Will the attacker still be able to achieve the same objective through another identity, workload, CI/CD system, SaaS service, replica, third party or control plane?

Will removing that permission disrupt legitimate production workloads?

Will the application team create an emergency workaround that introduces another security weakness?

Will the intervention violate a business-service availability requirement?

Will another security control become weaker?

Will the organization remain compliant?

And, after the change has been implemented, did the environment actually behave the way the model predicted?

These questions concern the **consequences of defender intervention**, rather than simply the current security posture.

---

# 3. Consolidated problem statement

> **Modern cybersecurity platforms can increasingly identify vulnerabilities, reconstruct attack paths, validate exploitability, prioritize exposures using technical and business context, recommend remediation, automate security changes, and verify security-control effectiveness. However, these capabilities primarily reason about the current or observed environment, or about a remediation that has already been selected.**
> 
> **Organizations still lack a comprehensive mechanism for evaluating multiple hypothetical security interventions against both an adaptive adversary and the legitimate business system before implementation. Closing one vulnerability or attack path does not necessarily prevent an adversary from achieving the same objective through another identity, workload, application, data copy, third party, pipeline or control plane. Likewise, a technically effective security change may disrupt required business operations, reduce system resilience, violate operational constraints, shift risk into another domain, or encourage insecure operational workarounds.**
> 
> **The research problem is therefore to determine whether a continuously updated causal model of identities, infrastructure, applications, workloads, networks, data, security controls, development pipelines, third parties and critical business services can evaluate counterfactual cyber interventions before execution. The model should predict which attacker capabilities would be removed, how an adversary could adapt toward the same objective, which alternative or newly created attack paths would remain, which legitimate business capabilities would be affected, whether resilience and compliance constraints would remain satisfied, and which intervention or combination of interventions would achieve the greatest reduction in attacker capability with the least disruption to required business capability.**
> 
> **After an intervention is implemented, the system should compare the observed post-change state with the predicted state so that future intervention decisions can be continuously improved.**

---

# 4. Central objective

The objective should be expressed very simply:

> **Minimize attacker capability while preserving required business capability.**

That is stronger than merely saying:

> Reduce cyber risk.

A defender does not want to reduce risk at any cost.

For example, disconnecting the entire payment infrastructure from the network might eliminate many cyberattack paths.

It would also eliminate the business.

Therefore the system must optimize both sides:

|Defender objective|Business constraint|
|---|---|
|Remove exploitable attack paths|Preserve legitimate workflows|
|Reduce privilege|Maintain required application permissions|
|Contain lateral movement|Maintain critical connectivity|
|Isolate compromised systems|Preserve critical-service availability|
|Protect sensitive information|Maintain authorized data access|
|Prevent attacker persistence|Preserve administrative recovery mechanisms|
|Improve security controls|Maintain compliance and resilience requirements|

The security problem therefore becomes a **constrained intervention-selection problem** rather than merely a vulnerability-remediation problem.

---

# 5. Real-world threat scenario

Consider a financial organization operating a payment application.

Current environment:

```text
Internet
   │
   ▼
Payment API
   │
   ▼
Kubernetes workload
   │
   ▼
Service Account
   │
   ▼
Cloud IAM Role
   │
   ▼
Payment Database
```

A CNAPP or exposure-management platform identifies the attack path.

It recommends restricting the workload identity.

That solves the obvious path.

However, the same environment contains:

```text
Payment API
   │
   ├────────→ Cloud IAM Role ─────→ Payment DB
   │
   ├────────→ Kubernetes SA
   │                │
   │                ▼
   │          CI/CD Credential
   │                │
   │                ▼
   │        Deployment Role
   │                │
   │                ▼
   └────────→ Analytics Service ──→ Payment Replica
```

The attacker's actual objective is not:

> Use IAM role X.

The attacker's objective is:

> Obtain payment-card information.

This distinction is critical.

---

# 6. What happens with conventional remediation

Security proposes:

```text
Remove database access
from IAM role X.
```

The known path becomes:

```text
Internet
   ↓
Payment API
   ↓
Workload
   ↓
IAM Role

        X

Payment DB
```

The finding can now appear resolved.

But an adaptive attacker evaluates the environment again:

```text
Payment API
   ↓
Kubernetes Service Account
   ↓
CI/CD credential
   ↓
Deployment role
   ↓
Analytics service
   ↓
Payment replica
```

The original path is closed.

The **attacker objective remains achievable**.

Therefore:

```text
Finding resolved          YES

Original attack path      CLOSED

Attacker objective        STILL ACHIEVABLE

Enterprise risk           NOT FULLY REMOVED
```

This is the distinction the proposed research should focus on.

---

# 7. What the proposed system should do

The system receives an attacker objective:

```text
Objective:
Exfiltrate payment-card records
```

It then evaluates several defender interventions.

### Intervention A

```text
Remove IAM role completely
```

Predicted result:

```text
Original attack path        CLOSED

Alternative attacker path   EXISTS

Settlement application      FAILS

Payment processing          DEGRADED

Business impact             HIGH

Residual attacker objective ACHIEVABLE

Recommendation              REJECT
```

### Intervention B

```text
Restrict IAM role
+
rotate CI/CD credential
+
remove analytics-replica access
```

Predicted result:

```text
Original path               CLOSED

Known alternate paths       CLOSED

Payment API                 NORMAL

Settlement processing       NORMAL

Analytics                   NORMAL

Compliance constraints      SATISFIED

Attacker objective          NOT ACHIEVABLE
                            through modelled routes

Recommendation              PREFERRED
```

### Intervention C

```text
Block external network access
```

Predicted result:

```text
Internet path               CLOSED

Internal identity path      REMAINS

Mobile application          DEGRADED

Attacker objective          STILL ACHIEVABLE
                            through compromised identity

Recommendation              INSUFFICIENT
```

The system is therefore not recommending the strongest security control.

It is identifying the **best intervention under security and business constraints**.

---

# 8. The technical research difference

Traditional exposure management asks:

```text
Given current state S:

Can attacker A reach target T?
```

Attack-path analysis computes approximately:

```text
S → T
```

Traditional remediation reasoning asks:

```text
Given exposure E:

Which fix F removes E?
```

The proposed research asks something different:

```text
Current enterprise state = S

Attacker objective = O

Business requirements = B

Resilience requirements = R

Compliance constraints = C

Candidate interventions =
I₁, I₂, I₃ ... Iₙ
```

For every candidate intervention:

```text
S' = do(I)
```

The system then evaluates:

```text
Attacker capabilities under S'

Attacker best alternative strategy under S'

Business processes under S'

Application dependencies under S'

Residual attack paths under S'

New attack paths introduced under S'

Resilience properties under S'

Compliance properties under S'
```

The system then attempts to choose:

```text
I*
```

such that:

```text
Attacker capability is minimized
```

subject to:

```text
Required business capability remains available

Resilience constraints remain satisfied

Compliance constraints remain satisfied

Operational disruption remains acceptable
```

This is the conceptual shift from an **attack graph** to a **causal intervention model**.

---

# 9. A particularly important new problem: attacker adaptation

A standard attack-path product asks:

> Which paths currently reach this asset?

The proposed system should ask:

> If the defender changes the environment, what would the attacker's best remaining strategy become?

That changes the model from:

```text
Defender discovers
        ↓
Defender fixes
        ↓
Done
```

into:

```text
Defender proposes intervention
            ↓
Environment changes hypothetically
            ↓
Attacker observes new environment
            ↓
Attacker changes strategy
            ↓
System evaluates remaining objectives
            ↓
Defender modifies intervention
```

This is closer to a defender-attacker decision problem.

The security objective should therefore be defined around **attacker capability**, not merely attack paths.

---

# 10. Defender-induced risk

There is another important problem that should be included.

Security interventions themselves can generate new risk.

Consider:

```text
Security blocks database access
            ↓
Application fails
            ↓
Operations team creates emergency access
            ↓
Long-lived service credential created
            ↓
Credential receives broad privilege
            ↓
New attack path appears
```

The original remediation may technically be correct.

But the organizational response creates a new vulnerability.

Therefore the system needs to reason about:

> **Risk transferred or created by the expected operational response to security intervention.**

This creates a second important research question:

> Can an intervention model predict not only the immediate technical effects of a security change, but also likely compensating configurations and operational workarounds that transfer security risk elsewhere?

This is potentially one of the most interesting parts of the research.

---

# 11. Business-service-aware reasoning

The model should not terminate at technical assets.

Instead of:

```text
Attack
 ↓
Database
```

it should understand:

```text
Attack
 ↓
Payment database
 ↓
Payment processing service
 ↓
Checkout capability
 ↓
Customer transactions
 ↓
Revenue / regulatory / operational consequence
```

This allows security interventions to be evaluated against **business capabilities**.

For example:

```text
Control X closes attack path

BUT

Control X removes a dependency required
by the settlement process

THEREFORE

Security effectiveness     HIGH

Business availability      UNACCEPTABLE
```

The system should instead search for another intervention.

---

# 12. Closed-loop verification

The system should not end after recommending a change.

Its lifecycle should be:

```text
OBSERVE
   ↓
MODEL
   ↓
PROPOSE
   ↓
SIMULATE
   ↓
ADVERSARY RE-PLANS
   ↓
BUSINESS IMPACT EVALUATED
   ↓
SELECT INTERVENTION
   ↓
IMPLEMENT
   ↓
OBSERVE REAL RESULT
   ↓
COMPARE

Predicted vs Actual
   ↓
UPDATE MODEL
```

For example:

```text
Predicted:

Service latency increase = 2%

Observed:

Service latency increase = 11%
```

The system now knows that its dependency model was incomplete.

That evidence should modify future intervention decisions.

This creates an important learning mechanism:

> **The digital twin should become more accurate from the difference between predicted and observed intervention outcomes.**

---

# 13. What the product is NOT

|Existing category|Why we should not become another one|
|---|---|
|CSPM|Configuration detection is commoditized|
|CNAPP|Cloud-native risk correlation is highly competitive|
|CIEM|Effective privilege analysis already exists|
|DSPM|Data exposure analysis already exists|
|CTEM|Exposure prioritization and validation are established|
|Attack-path platform|Wiz, Tenable, XM Cyber and others already provide mature capabilities|
|Cyber digital twin for attack paths|Already commercialized|
|BAS / automated pentesting|Established market|
|AI remediation assistant|Rapidly becoming standard|
|Business-aware remediation alone|Reclaim and others already occupy the category|
|Cyber-risk quantification|Established category|
|Compliance automation|Established category|

For example, Tenable already correlates attack paths from web applications, IT, OT, IoT, identities and external attack surface information to business services and processes.

Wiz explicitly positions its remediation agent around answering what caused a risk, who owns it, and how to fix it without breaking production.

And Reclaim explicitly claims to simulate potential business impact before applying changes.

Therefore none of those capabilities alone should be claimed as the novelty.

---

# 14. Where the proposed differentiation sits

The differentiation is the intersection of six reasoning problems:

|Capability|Existing market|Proposed research|
|---|---|---|
|Identify existing attack path|Mature|Input|
|Recommend remediation|Mature|Input|
|Estimate remediation disruption|Emerging|Input|
|Model attacker adaptation to hypothetical remediation|Limited / fragmented|**Core**|
|Model legitimate business behaviour under the same hypothetical state|Limited / fragmented|**Core**|
|Compare multiple interventions against security + business constraints|Limited|**Core**|
|Predict defender-induced/new risk|Limited|**Core**|
|Optimize intervention combinations against attacker objectives|Limited|**Core**|
|Compare predicted and actual post-intervention outcomes|Fragmented|**Core learning loop**|

Therefore the proposed platform should sit **above** existing security products.

It should consume their findings rather than attempting to replace them.

---

# 15. Proposed architecture direction

```text
                 EXISTING SECURITY ECOSYSTEM

     CNAPP      EDR/XDR      IAM       DSPM
       │           │          │          │
       ├───────────┼──────────┼──────────┤
       │
     CTEM        BAS        SIEM      CMDB
       │           │          │          │
       └───────────┴──────────┴──────────┘
                       │
                       ▼
             FEDERATED EVIDENCE LAYER
                       │
                       ▼
              CAUSAL ENTERPRISE MODEL
                       │
        ┌──────────────┼────────────────┐
        │              │                │
        ▼              ▼                ▼
   ATTACKER       BUSINESS         SECURITY
   CAPABILITY     DEPENDENCY       CONTROLS
     MODEL          MODEL            MODEL
        │              │                │
        └──────────────┼────────────────┘
                       │
                       ▼
            COUNTERFACTUAL ENGINE

             "What if we do X?"
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
       Attacker    Business      Resilience /
       response     impact       compliance
          │            │            │
          └────────────┼────────────┘
                       ▼
              INTERVENTION OPTIMIZER
                       │
                       ▼
                Recommended action
                       │
                       ▼
                    EXECUTE
                       │
                       ▼
              VERIFY REAL OUTCOME
                       │
                       ▼
                  LEARN / UPDATE
```

---

# 16. Primary users

The most important users would be the people currently forced to negotiate security-versus-operation trade-offs.

The security analyst needs to know whether the attacker can still achieve the objective.

The incident responder needs to know which containment action stops the attack with the least collateral damage.

The platform engineer needs confidence that remediation will not unnecessarily break production.

The application owner needs to understand which business dependencies are affected.

The IAM team needs to know whether reducing privilege creates another access requirement.

The resilience team needs to know whether critical-service tolerances remain satisfied.

The CISO needs to understand the business consequence of choosing one intervention over another.

---

# 17. Product output

The output should not look like:

```text
CRITICAL

IAM role is overprivileged.

Recommendation:
Apply least privilege.
```

It should look something like:

```text
ATTACKER OBJECTIVE

Exfiltrate customer payment data


CURRENT STATE

5 feasible attack routes identified.


PROPOSED INTERVENTION

Restrict PaymentAPI-Role to
payment-config/*


PREDICTED SECURITY EFFECT

Attack paths removed:            3
Attack paths degraded:           1
Attack paths remaining:          1

Attacker objective achievable:   YES


PREDICTED BUSINESS EFFECT

Payment API:                     Normal
Settlement processing:           Normal
Analytics workflow:              Normal


RESIDUAL ROUTE

Compromised CI/CD identity
→ AnalyticsRole
→ Payment replica


RECOMMENDED ADDITIONAL CONTROL

Rotate CI/CD credential and remove
AnalyticsRole access to payment replica.


COMBINED RESULT

Known attacker objective:        BLOCKED
Payment processing:              PRESERVED
Settlement:                      PRESERVED
Resilience constraints:          SATISFIED
Compliance constraints:          SATISFIED


RECOMMENDATION

Apply combined intervention.
```

That is the product experience worth aiming for.

---

# 18. Working research questions

The project can ultimately be tested through five research questions:

**RQ1 — Counterfactual security reasoning**

Can an enterprise security model accurately predict how a proposed defensive intervention changes attacker capabilities and reachable objectives?

**RQ2 — Adaptive adversary reasoning**

Can the model identify alternative strategies available to an adversary after the defender hypothetically changes the environment?

**RQ3 — Operational consequence reasoning**

Can legitimate application, infrastructure and business dependencies be modeled accurately enough to predict material operational consequences before remediation?

**RQ4 — Intervention optimization**

Can multiple technically valid security interventions be ranked according to reduction in attacker capability while satisfying business, resilience and compliance constraints?

**RQ5 — Closed-loop learning**

Can differences between predicted and observed post-intervention states improve subsequent intervention predictions?

These five questions are considerably more defensible than researching another attack-path engine.

---

# 19. Proposed hypothesis

A useful central hypothesis would be:

> **A security decision system combining causal infrastructure relationships, adversary-objective modelling and business-service dependencies can select defensive interventions that reduce attacker capability more effectively and with lower operational disruption than remediation strategies based only on vulnerability severity, individual attack paths or asset risk scores.**

This can actually be evaluated experimentally.

---

# 20. Measurable success criteria

The system should eventually be measured on:

|Metric|Question|
|---|---|
|Attack objective reduction|How many modeled attacker objectives become infeasible?|
|Residual-path discovery|How many alternative paths are identified after intervention?|
|New-risk detection|Did the intervention introduce another exploitable relationship?|
|Prediction accuracy|Did the real post-change environment match the simulated environment?|
|Business-impact accuracy|Were affected services correctly predicted?|
|Security disruption ratio|How much attacker capability was removed per unit of legitimate capability affected?|
|Intervention efficiency|Could fewer changes achieve the same security objective?|
|Resilience preservation|Did the critical service remain within its required tolerance?|
|Compliance preservation|Were required controls maintained after remediation?|

The **security disruption ratio** could become particularly interesting academically.

Conceptually:

```text
Security Utility =
Attacker capability removed
────────────────────────────
Legitimate capability disrupted
```

The goal would not necessarily be to maximize security controls.

It would be to maximize **useful risk reduction**.

---

# 21. Product positioning

Do not position this as:

**Next-generation CNAPP**

or:

**AI-powered CNAPP**

or:

**Unified exposure management**

or:

**Cybersecurity digital twin**

Those positions immediately put us against mature platforms.

A stronger category would be:

> **Cyber Intervention Decision Platform**

or academically:

> **Adaptive Counterfactual Cyber Intervention Planning**

The architecture underneath can still be called:

> **Cyber Resilience Decision Twin**

The distinction is useful:

**Problem:** Adaptive Counterfactual Cyber Intervention Planning.

**Solution:** Cyber Resilience Decision Twin.

---

# 22. Final one-line problem statement

For presentations:

> **Security teams can increasingly identify what attackers can exploit, but they still lack a reliable way to determine which defensive intervention will prevent the attacker from achieving their objective without unnecessarily disrupting the business.**

For the research paper:

> **How can an enterprise security system reason counterfactually about competing defensive interventions, adaptive attacker responses and legitimate business dependencies to select the intervention that minimizes attacker capability while preserving required business capability?**

And for product strategy:

> **Don't tell me only what to fix. Tell me what will happen if I fix it, what the attacker will do next, what the business will lose, and which action gives me the best overall outcome.**

That is the direction I would take forward.