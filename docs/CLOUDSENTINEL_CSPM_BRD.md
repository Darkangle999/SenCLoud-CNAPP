# CloudSentinel CSPM Business Requirements Document

| Document control | Value |
|---|---|
| Product | CloudSentinel CSPM |
| Repository codename | Odineyes |
| Document type | Business Requirements Document |
| Version | 1.0 |
| Date | 30 July 2026 |
| Status | Draft for stakeholder approval |
| Product category | Cloud Security Posture Management with a phased path to CNAPP |
| Initial market | Mid-market and enterprise organizations operating AWS, followed by Azure and Google Cloud |
| Primary owners | Product, Cloud Security, Engineering, GRC |

## 1. Executive summary

CloudSentinel will provide continuous, evidence-backed visibility into cloud assets, misconfigurations, identities, vulnerabilities, sensitive data, compliance controls, and the relationships that create exploitable attack paths.

The business problem is not a lack of alerts. Cloud providers and security tools already generate large numbers of isolated findings. The unresolved problem is deciding which combinations create material business risk, identifying the owner who can fix them, recommending the smallest safe change, and proving that the risk has been removed.

CloudSentinel will address this problem through:

1. Low-friction, read-only cloud account onboarding.
2. Normalized asset and security-context inventory.
3. Evidence-backed configuration assessment and compliance mapping.
4. Graph-based correlation of exposure, identity, vulnerability, data, and runtime context.
5. Risk prioritization based on exploitability and business impact instead of provider severity alone.
6. An operational workflow from discovery through assignment, remediation, verification, exception, and audit.
7. Open APIs and exports that allow the platform to work with existing security, engineering, and GRC processes.

The first production release will be AWS-first. Azure and Google Cloud must not be marketed as generally available until the acceptance criteria in this BRD are met. The present repository contains a strong AWS technical foundation, while several broader CNAPP capabilities remain roadmap items.

## 2. Purpose

This BRD defines:

- The business outcomes CloudSentinel must achieve.
- Target customers, users, and jobs to be done.
- Market-derived product expectations.
- Functional and non-functional requirements.
- Scope boundaries and phased delivery.
- Success measures, acceptance gates, risks, and governance.

This document states product requirements. It does not replace the solution architecture, threat model, security design, test plan, data protection impact assessment, or release plan.

## 3. Product vision

> CloudSentinel tells an organization which exposed identity, workload, pipeline, or credential can reach which critical asset, through what path, with what evidence, and which smallest safe action will break that path.

### 3.1 Product principles

- **Evidence before assertion:** A finding must show the observed configuration, source, collection time, and evaluation logic.
- **Context before severity:** Exposure, privilege, exploitability, data sensitivity, compensating controls, ownership, and confidence must influence priority.
- **Read-only by default:** Initial onboarding and assessment use least-privilege, read-only access.
- **Human approval for change:** Remediation actions are proposed and previewed before execution unless an administrator has explicitly approved a bounded automation policy.
- **No compliance theater:** Compliance results show technical evidence and scope limitations; passing a control must not be represented as proof of security.
- **Fail transparently:** Missing permissions, stale data, unsupported services, and uncertain reachability are shown as coverage gaps rather than secure results.
- **Open integration:** Findings, assets, evidence, and status changes are available through documented APIs and standard exports.

## 4. Business context and market analysis

### 4.1 Market evolution

The CSPM market has expanded into Cloud-Native Application Protection Platforms. Current category expectations now include CSPM, vulnerability management, CIEM, attack-path analysis, DSPM, IaC and pipeline security, Kubernetes and workload runtime visibility, and code-to-cloud traceability.

Major platforms demonstrate the following market expectations:

| Platform | Publicly documented market pattern | Requirement implication for CloudSentinel |
|---|---|---|
| Wiz | Context-based risk assessment, security graph, toxic combinations, agentless visibility, and attack-path prioritization | Graph context and material-risk prioritization are core, not optional |
| Palo Alto Prisma Cloud | Near real-time posture monitoring, historical configuration context, large policy catalog, broad compliance coverage, and code-to-cloud remediation | CloudSentinel needs policy breadth, drift history, custom policy, and code ownership |
| Orca Security | Agentless asset visibility, workload and data context, lateral-movement analysis, attack paths, and source tracing | Vulnerability, identity, network, data, and source-code relationships must converge |
| Microsoft Defender for Cloud | Multicloud posture, secure score, attack paths, risk prioritization, DevOps security, and pull-request annotations in paid CSPM | Executive posture scoring must lead to inspectable evidence and engineering workflow |
| AWS Security Hub CSPM | AWS-native controls, standards mapping, change-triggered or periodic checks, ASFF findings, suppression, and automation rules | CloudSentinel should ingest native findings and add cross-domain prioritization rather than duplicate every provider control |
| Google Security Command Center | Security postures, drift monitoring, centralized findings, threat detection, and correlated issues | Desired state, drift, threat correlation, and issue grouping are expected enterprise functions |
| CrowdStrike Falcon Cloud Security | Agentless discovery combined with CSPM, CIEM, DSPM, AI security posture, vulnerabilities, and threat intelligence | A standalone posture scanner is insufficient for long-term differentiation |

The matrix is a capability-pattern analysis based on vendor documentation, not an independent product benchmark or a claim that all capabilities are equivalent.

### 4.2 Market lessons

1. **Alert volume is not value.** Buyers expect material-risk reduction, not a larger list of failed controls.
2. **The security graph is becoming table stakes.** Differentiation comes from evidence quality, confidence, explainability, workflow, and time to remediation.
3. **Identity is the cloud perimeter.** Effective access and privilege-escalation paths must be analyzed with network and data context.
4. **Code-to-cloud closes the ownership gap.** A runtime finding should link to the repository, IaC resource, deployment, and team that can fix it.
5. **Continuous means change-aware.** Scheduled snapshots alone leave material detection gaps.
6. **Native findings remain valuable.** Provider services offer broad, frequently updated controls. CloudSentinel should normalize and enrich them.
7. **Remediation must be safe.** Buyers require approvals, preview, rollback guidance, verification, and complete audit history.
8. **Coverage transparency builds trust.** A denied API or unsupported service must reduce confidence and appear in coverage reporting.

### 4.3 Real-world cases informing the requirements

| Case | Failure pattern | Product requirement |
|---|---|---|
| Toyota cloud exposure, 2023 | Cloud configuration left data potentially externally accessible over a long period | Continuous discovery, configuration history, drift detection, data context, and ownership |
| Microsoft storage SAS exposure, 2023 | Public repository contained an overly permissive storage token; an earlier alert was dismissed | Secret-to-permission-to-data correlation, durable triage decisions, and false-positive governance |
| CircleCI incident, 2023 | Stolen authenticated session enabled theft of customer keys, tokens, and environment variables | CI/CD identity mapping, credential blast radius, rotation workflow, and verification |
| Snowflake customer campaign, 2024 | Stolen credentials, missing MFA, valid old credentials, and missing network restrictions enabled data theft | Identity hygiene, access restrictions, sensitive-data context, and anomalous-use correlation |
| `tj-actions/changed-files`, 2025 | Compromised CI/CD dependency exposed secrets from runner memory into logs | Pipeline dependency inventory, immutable pinning policy, secret blast radius, and rotation queue |

These cases establish that cloud security risk crosses configuration, identity, data, source control, CI/CD, and runtime boundaries. CloudSentinel must therefore correlate conditions rather than treat them as independent alerts.

## 5. Business problem

Target organizations experience the following problems:

- Cloud inventory is incomplete, stale, or split across accounts, regions, providers, and tools.
- Security teams cannot reliably distinguish an exploitable path from an isolated best-practice failure.
- Provider, vulnerability, identity, data, and runtime findings use different identifiers and severities.
- Developers receive findings without ownership, source-code location, business context, or safe remediation guidance.
- GRC teams manually collect screenshots and evidence, then cannot prove whether the evidence remains current.
- Security exceptions are handled in tickets or spreadsheets without consistent expiry, approval, or revalidation.
- Teams cannot measure whether remediation programs are reducing material risk.
- Multicloud tools sometimes hide collection failures and overstate coverage.

## 6. Business objectives

### 6.1 Objectives

| ID | Objective | Target outcome |
|---|---|---|
| BO-01 | Establish trusted cloud visibility | At least 95% of supported in-scope assets discovered within the freshness SLA |
| BO-02 | Reduce alert overload | At least 80% reduction from raw findings to prioritized material-risk issues |
| BO-03 | Accelerate remediation | 50% reduction in median time to remediate Critical and High material-risk issues |
| BO-04 | Improve accountability | At least 90% of Critical and High issues mapped to an owner or ownership queue |
| BO-05 | Improve assurance efficiency | At least 70% of supported audit evidence produced automatically with timestamps and provenance |
| BO-06 | Prevent recurrence | At least 90% of remediated Critical issues automatically revalidated after relevant change or rescan |
| BO-07 | Support engineering adoption | At least 80% of IaC findings delivered before deployment for integrated repositories |
| BO-08 | Build customer trust | 100% of results show freshness, evidence, confidence, and known coverage gaps |

Targets are initial product goals and must be baselined during pilot deployments.

### 6.2 Non-goals for the initial release

- Replacing a SIEM, EDR, SOAR, full vulnerability-management platform, or cloud provider control plane.
- Performing offensive exploitation of customer environments.
- Storing customer cloud access keys.
- Automatically changing customer infrastructure without an explicit, bounded approval policy.
- Claiming legal or regulatory compliance solely from technical checks.
- Offering full Azure or Google Cloud parity in the AWS-first release.
- Reading secret values by default.

## 7. Target customers and segmentation

### 7.1 Ideal customer profile

- 20 or more cloud accounts, subscriptions, or projects.
- AWS-led environment with increasing multicloud use.
- A centralized security or platform team supporting decentralized application teams.
- Regulated or audit-sensitive workloads.
- Existing ticketing, source-control, SIEM, and cloud-native security services.
- Pain from alert overload, unclear ownership, slow evidence collection, or tool cost.

### 7.2 Initial segments

| Segment | Primary need | Buying trigger |
|---|---|---|
| Mid-market cloud-native company | Enterprise-grade prioritization without enterprise operational overhead | Security team cannot keep pace with cloud growth |
| Regulated enterprise | Evidence, control mapping, tenancy, data residency, and governance | Audit finding, cloud transformation, or tool consolidation |
| Managed security provider | Multi-tenant visibility, delegated administration, and customer reporting | Need to deliver repeatable CSPM services |
| DevSecOps-led organization | IaC prevention and code-to-cloud ownership | Production issues repeatedly originate in infrastructure code |

## 8. Stakeholders and personas

| Persona | Core job | Required experience |
|---|---|---|
| CISO / security leader | Understand material cloud risk and trend | Executive posture, crown-jewel exposure, risk acceptance, measurable reduction |
| Cloud security engineer | Find and break exploitable paths | Evidence, graph, query, suppression, remediation, verification |
| SOC analyst | Investigate active or likely exploitation | Runtime and threat context, timeline, related assets, handoff to SIEM/SOAR |
| Cloud / platform engineer | Fix safely without breaking production | Resource context, exact owner, IaC location, tested guidance, rollback |
| Application owner | Understand business impact | Plain-language risk, affected service, due date, status |
| GRC / auditor | Assess control operation and evidence | Framework mapping, scope, evidence package, exceptions, history |
| IAM engineer | Reduce excessive access | Effective permissions, use history, trust chains, rightsizing |
| Data security / privacy | Locate sensitive stores and exposure | Classification, lineage, access paths, jurisdiction and retention context |
| Product administrator | Configure tenants, roles, integrations, and policies | RBAC, SSO, audit logs, health, quotas, and configuration |
| MSP operator | Operate across customers without data leakage | Tenant isolation, delegated roles, customer branding, consolidated reporting |

## 9. Key business use cases

### UC-01: Onboard a cloud organization

An administrator generates a least-privilege CloudFormation or Terraform package, deploys it in the customer environment, verifies the role and ExternalId, selects accounts and regions, and receives a coverage report. No long-lived cloud credentials are stored.

### UC-02: Identify material attack paths

A security engineer sees a Critical route such as:

`Internet -> exposed workload -> exploitable vulnerability -> privileged role -> sensitive data store`

The route includes evidence for each hop, confidence, first and last observed time, business owner, regulatory impact, and the smallest changes that break the route.

### UC-03: Triage and assign a finding

An analyst validates the evidence, assigns the issue, sets an SLA, links a ticket, adds a comment, or creates a time-bound exception. Duplicate symptoms remain attached to one material-risk issue.

### UC-04: Remediate and verify

An engineer views console, CLI, and IaC guidance; previews impact; applies the change through the approved workflow; and triggers re-evaluation. CloudSentinel closes the issue only when the relevant evidence shows the path is broken.

### UC-05: Prevent insecure deployment

A pull request introduces public ingress and a wildcard role on a workload connected to sensitive data. CloudSentinel comments on the changed lines, explains the future attack path, identifies the owner, and fails the required check according to policy.

### UC-06: Produce audit evidence

A GRC user selects a framework, business scope, and date range. The platform produces control status, technical checks, evidence provenance, exceptions, coverage gaps, and change history without asserting certification.

### UC-07: Investigate a compromised credential

An analyst searches a credential or principal, identifies reachable roles and data, reviews recent use and runtime signals, creates a rotation and revocation checklist, and verifies that the old path no longer works.

### UC-08: Govern policy and exceptions

A policy administrator creates or imports a versioned control, tests it against historical assets, publishes it to selected scopes, monitors false positives, and manages approval-based exceptions with expiration.

## 10. Product scope

### 10.1 Release 1: Production AWS CSPM

In scope:

- AWS Organizations, account, and region onboarding.
- Read-only, ExternalId-based role access.
- Continuous AWS asset inventory and relationship graph.
- Configuration findings with evidence and collection confidence.
- Contextual network exposure and reachability.
- AWS identity posture and priority privilege-escalation patterns.
- Vulnerability and exploitability context for supported compute and images.
- Sensitive-data posture for supported AWS stores using privacy-preserving methods.
- Graph-based attack paths and material-risk issues.
- Compliance mapping and evidence reporting.
- Manual and scheduled scans, plus event-driven reassessment for material changes.
- Finding workflow, ownership, SLA, exception, ticket, and verification.
- REST API, webhooks, CSV/JSON/PDF reports, and SIEM/ticketing integrations.
- Enterprise authentication, authorization, audit, tenancy, and operational controls.

### 10.2 Release 2: Shift-left and identity depth

- GitHub, GitLab, Bitbucket, Azure DevOps, and common CI/CD integrations.
- Terraform, CloudFormation, Kubernetes manifest, and supported template scanning.
- Pull-request annotations and policy gates.
- Resource-to-code ownership mapping.
- Effective-permission evaluation across identity policies, resource policies, permission boundaries, session policies, and AWS Organizations SCPs.
- Usage-based rightsizing and multi-hop role analysis.
- Kubernetes and IRSA relationship coverage.

### 10.3 Release 3: Multicloud and runtime correlation

- Production-depth Azure and Google Cloud inventory and policies.
- Unified cross-cloud identity and exposure graph.
- Kubernetes admission and runtime relationships.
- Correlation of runtime events with posture, vulnerabilities, identities, and data.
- Automated response playbooks with approvals and rollback controls.

### 10.4 Future scope

- Oracle Cloud and additional platforms based on customer demand.
- AI Security Posture Management for models, data sources, agents, and AI services.
- SaaS Security Posture Management where it strengthens a cloud attack path.
- External attack-surface and API posture integrations.

## 11. Functional business requirements

Priority uses MoSCoW: Must, Should, Could, Won't in the defined release.

### 11.1 Tenant, identity, and access management

| ID | Requirement | Priority | Acceptance condition |
|---|---|---|---|
| FR-IAM-001 | The platform shall isolate all assets, findings, evidence, policies, reports, and logs by tenant | Must | Automated tests prove cross-tenant requests return no data |
| FR-IAM-002 | The platform shall support SAML 2.0 and OIDC SSO | Must | A tenant can configure and validate either protocol |
| FR-IAM-003 | The platform shall support role-based access for administrator, operator, analyst, engineer, auditor, and read-only user | Must | Every privileged API action enforces an explicit permission |
| FR-IAM-004 | The platform shall support custom roles and scope by tenant, business unit, account, and environment | Should | An admin can create and test a restricted role |
| FR-IAM-005 | The platform shall record immutable audit events for authentication, policy, exception, integration, export, and remediation activity | Must | Events include actor, action, target, result, time, and correlation ID |
| FR-IAM-006 | The platform shall support SCIM user and group provisioning | Should | Create, update, group mapping, and deprovision flows pass integration tests |

### 11.2 Cloud onboarding and coverage

| ID | Requirement | Priority | Acceptance condition |
|---|---|---|---|
| FR-ONB-001 | AWS onboarding shall use a customer-deployed role with ExternalId and least-privilege read permissions | Must | No static AWS key is requested or stored |
| FR-ONB-002 | The platform shall support single account and AWS Organizations onboarding | Must | An authorized admin can discover and select member accounts |
| FR-ONB-003 | The platform shall validate role trust, required permissions, regions, and service reachability before activation | Must | Verification produces a pass, fail, or explicit gap for each check |
| FR-ONB-004 | The platform shall show collection coverage by account, region, service, asset type, permission, and last success | Must | A denied API is visible and reduces coverage confidence |
| FR-ONB-005 | The platform shall allow controlled offboarding and data-retention handling | Must | Offboarding disables collection and applies the approved retention policy |
| FR-ONB-006 | Onboarding templates and permissions shall be versioned and upgradeable | Must | Admin sees deployed and current version plus the permission delta |

### 11.3 Asset inventory and graph

| ID | Requirement | Priority | Acceptance condition |
|---|---|---|---|
| FR-AST-001 | The platform shall maintain a normalized inventory with provider-native identifiers and source payload references | Must | Assets can be searched by ARN, provider ID, name, tag, owner, account, region, and type |
| FR-AST-002 | The platform shall represent network, identity, data, deployment, vulnerability, and ownership relationships | Must | Supported relationships are queryable and visible with provenance |
| FR-AST-003 | The platform shall track first seen, last seen, configuration version, and deletion status | Must | Asset history reconstructs material posture changes |
| FR-AST-004 | The platform shall deduplicate resources and findings across collectors and integrations | Must | Duplicate provider and imported records resolve to one canonical asset |
| FR-AST-005 | Users shall define crown jewels, business services, owners, criticality, environment, and data residency | Must | Context changes recalculate affected risk within the freshness SLA |
| FR-AST-006 | The platform shall expose graph and inventory data through documented APIs | Must | API supports pagination, filtering, tenant scope, and stable identifiers |

### 11.4 Posture policy and findings

| ID | Requirement | Priority | Acceptance condition |
|---|---|---|---|
| FR-CSPM-001 | The platform shall evaluate versioned configuration controls against collected evidence | Must | Each result references policy version, asset, evidence, and evaluation time |
| FR-CSPM-002 | A result shall be Pass, Fail, Error, Not assessed, or Not applicable | Must | Missing evidence can never be silently converted to Pass |
| FR-CSPM-003 | Policies shall support severity, rationale, remediation, framework mappings, parameters, and supported asset types | Must | Catalog fields are available through UI and API |
| FR-CSPM-004 | Administrators shall create, test, stage, publish, retire, and roll back custom policies | Should | Historical test shows impact before publication |
| FR-CSPM-005 | The platform shall ingest and normalize supported native and partner findings | Must | Original identifier, status, severity, and source remain traceable |
| FR-CSPM-006 | The platform shall support scoped suppression and risk acceptance with owner, reason, approval, expiry, and review | Must | Expired exceptions automatically return to the review queue |
| FR-CSPM-007 | Findings shall retain evidence snapshots and status history | Must | Auditor can reconstruct why a result existed at a given time |

### 11.5 Exposure and reachability

| ID | Requirement | Priority | Acceptance condition |
|---|---|---|---|
| FR-NET-001 | The platform shall distinguish public address from proven, blocked, and unverified reachability | Must | UI never labels uncertain exposure as proven |
| FR-NET-002 | Reachability shall consider routes, gateways, load balancers, security groups, network ACLs, resource policies, and supported higher-layer controls | Must | Every path hop includes the control evidence used |
| FR-NET-003 | Users shall query exposure by protocol, port, source, destination, asset, account, and business service | Should | Query results match test topologies |
| FR-NET-004 | Material changes to reachable exposure shall trigger targeted re-evaluation | Must | Supported change produces an updated issue within five minutes at p95 |

### 11.6 CIEM

| ID | Requirement | Priority | Acceptance condition |
|---|---|---|---|
| FR-CIEM-001 | The platform shall inventory human, workload, federated, and service identities and their trust relationships | Must | Supported identity types appear in the graph |
| FR-CIEM-002 | The platform shall detect wildcard administration, privilege-escalation primitives, risky trust, missing MFA, long-lived keys, and dormant privileged identities | Must | Curated positive and negative test cases pass |
| FR-CIEM-003 | Effective access shall account for identity and resource policies, boundaries, session policies, and SCPs | Must for Release 2 | Evaluation explains allows, denies, uncertainty, and source policies |
| FR-CIEM-004 | The platform shall model role chaining and cross-account access to critical assets | Must for Release 2 | Multi-hop test paths are detected without unsupported inference |
| FR-CIEM-005 | The platform shall recommend rightsizing from observed use with a configurable observation period | Should | Recommendation never removes a recently used permission without warning |
| FR-CIEM-006 | Users shall simulate the security impact of a proposed permission change | Should | Before-and-after reachable assets and broken paths are shown |

### 11.7 Vulnerability and workload context

| ID | Requirement | Priority | Acceptance condition |
|---|---|---|---|
| FR-VUL-001 | The platform shall ingest or generate vulnerabilities for supported VMs, images, functions, and packages | Must | CVE, package, version, source, scan time, and asset are retained |
| FR-VUL-002 | Prioritization shall use CVSS, CISA KEV, EPSS, exploit maturity, reachability, runtime, privilege, and data impact when available | Must | Score explanation identifies every applied and missing factor |
| FR-VUL-003 | Vulnerabilities shall be correlated to deployed and reachable workloads, not only registries | Must | A vulnerable image maps to its running workload and identity where supported |
| FR-VUL-004 | The platform shall produce or ingest SBOMs in a standard format | Should | CycloneDX or SPDX export validates against its schema |
| FR-VUL-005 | Scan coverage and method shall distinguish agentless, agent, registry, SSM, and imported results | Must | User can identify blind spots and scan age |

### 11.8 Data security posture

| ID | Requirement | Priority | Acceptance condition |
|---|---|---|---|
| FR-DSPM-001 | The platform shall discover supported cloud data stores and classify sensitivity using metadata-first, privacy-preserving techniques | Must | Sampling is disabled by default unless explicitly approved |
| FR-DSPM-002 | Classification shall expose method, confidence, sample scope, taxonomy, and regulatory mapping | Must | User can distinguish confirmed from inferred sensitivity |
| FR-DSPM-003 | Data sensitivity, volume, public exposure, encryption, backups, and identity access shall affect material-risk priority | Must | Public sensitive data outranks an equivalent non-sensitive asset |
| FR-DSPM-004 | The platform shall avoid persisting sampled secret or sensitive values | Must | Security test verifies only non-sensitive evidence and hashes are retained |
| FR-DSPM-005 | Data collection shall support per-tenant, account, store, and classifier allow or deny policy | Must | Admin can prove sampling is disabled for excluded scopes |

### 11.9 Attack paths and risk prioritization

| ID | Requirement | Priority | Acceptance condition |
|---|---|---|---|
| FR-RISK-001 | The platform shall correlate individual findings into deduplicated material-risk issues | Must | One issue groups related evidence without losing source findings |
| FR-RISK-002 | Each attack path shall include entry point, hops, target, evidence, confidence, blast radius, first and last seen, and remediation options | Must | All displayed hops have source-backed relationships |
| FR-RISK-003 | Risk shall consider likelihood, impact, confidence, business context, and compensating controls | Must | Score is explainable and reproducible from versioned inputs |
| FR-RISK-004 | Users shall view which remediation breaks the most Critical and High paths | Must | System calculates path-reduction impact before change |
| FR-RISK-005 | Users shall query and filter paths by tenant, account, service, owner, severity, confidence, framework, and crown jewel | Must | Filters work consistently in UI, API, and export |
| FR-RISK-006 | The engine shall prevent unsupported relationships from being presented as fact | Must | Inferred edges are labeled and confidence is reduced |

### 11.10 Compliance and evidence

| ID | Requirement | Priority | Acceptance condition |
|---|---|---|---|
| FR-GRC-001 | The platform shall map technical checks to versioned control frameworks | Must | Mapping records include source, version, rationale, and review date |
| FR-GRC-002 | Initial framework support shall include CIS AWS Foundations, AWS Foundational Security Best Practices, NIST CSF 2.0, NIST SP 800-53 Rev. 5, PCI DSS 4.0.1, ISO 27001, SOC 2, HIPAA, GDPR, and CSA CCM 4.1 as licensed and applicable | Must/Should by customer segment | Published support matrix distinguishes native, mapped, and manual controls |
| FR-GRC-003 | Users shall define assessment scope, applicability, control owner, implementation status, and compensating control | Must | Report separates technical posture from organizational controls |
| FR-GRC-004 | Evidence exports shall include timestamps, source, asset, policy version, result, exception, and integrity metadata | Must | Export can be independently reconciled to stored records |
| FR-GRC-005 | The platform shall show posture trend and control drift | Must | User can compare any two supported periods |
| FR-GRC-006 | Reports shall display coverage limitations and shall not claim certification | Must | Legal and product review approve report wording |

### 11.11 IaC, source control, and code-to-cloud

| ID | Requirement | Priority | Acceptance condition |
|---|---|---|---|
| FR-IAC-001 | The platform shall scan supported IaC locally, through API, and in CI | Must for Release 2 | Same policy produces consistent result across modes |
| FR-IAC-002 | Pull-request results shall identify changed file, line, resource, risk, and secure alternative | Must for Release 2 | Annotation links to the applicable policy and evidence |
| FR-IAC-003 | Policy gates shall be configurable by severity, new versus existing risk, confidence, and scope | Must for Release 2 | Existing debt can be baselined without allowing new Critical risk |
| FR-IAC-004 | Deployed assets shall link to the originating repository, code resource, deployment, and owner where evidence supports it | Must for Release 2 | Runtime asset opens the correct source location |
| FR-IAC-005 | CI/CD dependencies and credential relationships shall be modeled for supported systems | Should | Mutable action and exposed credential tests produce connected risk |

### 11.12 Workflow, remediation, and integrations

| ID | Requirement | Priority | Acceptance condition |
|---|---|---|---|
| FR-WF-001 | An issue shall support New, Triaged, Assigned, In progress, Resolved, Accepted, Suppressed, and Reopened states | Must | State transition and actor are audited |
| FR-WF-002 | Issues shall support owner, comments, SLA, due date, labels, attachments, and external ticket link | Must | Fields round-trip through API and UI |
| FR-WF-003 | The platform shall integrate with Jira, ServiceNow, GitHub Issues, Slack, Teams, email, SIEM, and webhooks according to demand | Should | Integration matrix and contract tests define supported actions |
| FR-WF-004 | Remediation guidance shall include console, CLI, and IaC options where applicable | Must | Guidance is versioned and tested against supported provider behavior |
| FR-WF-005 | Proposed automated remediation shall show affected resources, expected path reduction, prerequisites, possible impact, and rollback guidance | Must | No change can execute before preview and authorization |
| FR-WF-006 | The platform shall re-evaluate affected assets after remediation and reopen recurring risk | Must | Resolved status requires new passing evidence |
| FR-WF-007 | Bidirectional integrations shall prevent update loops and retain source-of-truth rules | Must | Contract tests cover conflicting updates and retries |

### 11.13 Reporting and analytics

| ID | Requirement | Priority | Acceptance condition |
|---|---|---|---|
| FR-RPT-001 | Role-specific dashboards shall serve executive, analyst, engineer, and GRC users | Must | Usability testing confirms each persona can complete its primary job |
| FR-RPT-002 | Metrics shall include asset coverage, stale data, material risk, risk age, SLA, recurrence, exception debt, and remediation impact | Must | Metric definitions are documented and reproducible |
| FR-RPT-003 | Reports shall support scheduled and on-demand CSV, JSON, and PDF output | Must | Export respects tenant and user scope |
| FR-RPT-004 | Executive reporting shall show business services and crown jewels, not only cloud resources | Must | Top-risk view maps to business context |
| FR-RPT-005 | The platform shall provide an API usage and integration-health dashboard | Should | Admin can identify failed delivery, lag, retries, and quota use |

## 12. Non-functional requirements

| ID | Category | Requirement |
|---|---|---|
| NFR-001 | Availability | Production control plane target: 99.9% monthly availability, excluding agreed maintenance |
| NFR-002 | Freshness | Material supported cloud changes reflected within 5 minutes at p95; scheduled full reconciliation within 24 hours |
| NFR-003 | Scale | Initial design target: 1,000 cloud accounts and 10 million assets per tenant without architectural redesign |
| NFR-004 | Performance | p95 interactive read API under 2 seconds for standard filtered queries; graph expansion under 5 seconds for bounded paths |
| NFR-005 | Durability | Configuration, issue, exception, and audit records use tested backup and point-in-time recovery according to service tier |
| NFR-006 | Security | Encryption in transit and at rest, tenant-aware authorization, secure SDLC, dependency scanning, penetration testing, and vulnerability SLAs |
| NFR-007 | Secrets | Customer cloud access keys shall not be stored; platform secrets use an approved secrets manager and are never logged |
| NFR-008 | Privacy | Data minimization, configurable retention, regional processing options, deletion workflow, and auditable administrative access |
| NFR-009 | Auditability | Security-sensitive actions generate tamper-evident, exportable events retained according to tenant policy |
| NFR-010 | Resilience | Collection retries use bounded backoff, idempotency, checkpoints, provider-rate-limit awareness, and dead-letter handling |
| NFR-011 | Accessibility | Web interface targets WCAG 2.2 AA for primary workflows |
| NFR-012 | Compatibility | Current and previous major versions of Chrome, Edge, Firefox, and Safari are supported |
| NFR-013 | API | Versioned REST API, OpenAPI description, pagination, stable IDs, idempotency for mutations, and published rate limits |
| NFR-014 | Observability | Metrics, logs, traces, correlation IDs, health checks, SLO dashboards, alerting, and collection-lag reporting |
| NFR-015 | Explainability | Every score and path can be traced to versioned inputs, evidence, logic, and missing context |
| NFR-016 | Deployment | SaaS is primary; private or customer-hosted collectors may be offered for regulated environments |
| NFR-017 | Maintainability | Provider collectors, policies, normalizers, and integrations use versioned contracts and automated regression suites |
| NFR-018 | Data portability | Tenant can export its supported asset, finding, issue, evidence, and audit data in documented formats |

## 13. Data and information requirements

### 13.1 Core business entities

- Tenant, user, group, role, permission.
- Cloud organization, account, subscription, project, region.
- Asset, configuration version, tag, owner, business service, crown jewel.
- Identity, credential metadata, policy, permission, trust relationship, activity summary.
- Network endpoint, route, rule, exposure relationship.
- Vulnerability, package, image, SBOM, exploitability signal.
- Data store, classification, sensitivity, jurisdiction, retention label.
- Policy definition, framework control, mapping, evaluation, evidence.
- Finding, material-risk issue, attack path, graph node, graph edge.
- Exception, approval, ticket, remediation action, verification.
- Scan job, collector, coverage record, integration delivery, audit event.

### 13.2 Required provenance

Every collected or derived record must retain:

- Tenant and source system.
- Provider-native ID and canonical ID.
- Account and region scope.
- Collection or event time.
- Ingestion and evaluation time.
- Collector and schema version.
- Policy or algorithm version.
- Evidence reference and integrity value.
- Confidence and coverage status.
- Derivation chain for calculated results.

### 13.3 Retention

Default proposed retention:

- Current inventory: while connected plus 30 days after offboarding.
- Configuration history and evidence: 13 months.
- Findings, issues, exceptions, and audit history: 7 years for regulated tier, configurable for other tiers.
- Sampled content: never retained.
- Runtime events: 30 to 90 days by service tier unless exported to the customer SIEM.

Final retention and residency requirements require legal, privacy, cost, and target-market approval.

## 14. Security, privacy, and compliance requirements

- Use a documented shared-responsibility model for SaaS, collectors, and customer cloud environments.
- Map the product security program to NIST CSF 2.0 and CSA CCM 4.1.
- Design the service for SOC 2 Type II readiness and ISO 27001 alignment.
- Maintain a threat model covering tenant isolation, confused deputy, supply chain, collector compromise, graph poisoning, integration tokens, and remediation abuse.
- Generate onboarding trust policies with unique ExternalId values and minimum required actions.
- Keep sensitive-data sampling opt-in and independently configurable.
- Redact secrets, tokens, credentials, and sensitive values from logs, errors, UI, support bundles, and exports.
- Require step-up authentication for high-impact tenant administration and remediation.
- Support customer-managed encryption options where commercially justified.
- Separate product control mappings from certification claims.
- Review third-party framework licensing before embedding control text or commercial mappings.

## 15. Primary workflows

### 15.1 Discover-to-verify

1. Connect cloud scope.
2. Validate access and coverage.
3. Collect and normalize assets.
4. Build relationships and evaluate policies.
5. Correlate material-risk issues and attack paths.
6. Add business, identity, data, vulnerability, and runtime context.
7. Triage and assign.
8. Propose and approve remediation.
9. Apply through the customer's chosen workflow.
10. Recollect affected evidence.
11. Verify that the path is broken.
12. Report trend, control status, and recurrence.

### 15.2 Exception lifecycle

1. User requests exception with reason, scope, expiry, and compensating control.
2. Required approver reviews risk and affected paths.
3. Approved exception changes workflow, not underlying evidence.
4. Material configuration or context changes trigger re-review.
5. Expiring exceptions generate notifications.
6. Expired exceptions return to active triage automatically.

## 16. Risk model

CloudSentinel will maintain separate values for:

- **Technical severity:** Intrinsic severity of the policy or vulnerability.
- **Likelihood:** Reachability, exploitability, credential exposure, active use, and attack prerequisites.
- **Impact:** Asset criticality, privilege, sensitive data, blast radius, availability, and regulatory relevance.
- **Confidence:** Evidence completeness, freshness, source reliability, and inference.
- **Material-risk score:** Versioned combination of likelihood and impact, qualified by confidence and compensating controls.

The UI must show the factors, not only a number. Administrators may adjust business context and thresholds but may not alter historical evidence.

## 17. Integration requirements

| Domain | Minimum integration pattern |
|---|---|
| Cloud | AWS APIs and AWS Security Hub CSPM; later Azure Resource Graph/Defender for Cloud and Google Cloud Asset Inventory/Security Command Center |
| Source and CI/CD | GitHub, GitLab, Bitbucket, Azure DevOps, Jenkins, and generic CI API |
| Ticketing | Jira, ServiceNow, GitHub Issues, and generic webhook |
| Collaboration | Slack, Teams, and email |
| SIEM/SOAR | Splunk, Microsoft Sentinel, Elastic, syslog/CEF where suitable, and webhook |
| Identity | SAML, OIDC, SCIM |
| Vulnerability | Trivy, provider-native vulnerability services, CISA KEV, EPSS, OSV, and supported commercial tools |
| GRC | CSV/JSON/PDF export first; API-based evidence exchange based on customer demand |

Each integration must define direction, authentication, data ownership, retries, deduplication, rate limits, health, permissions, and failure behavior.

## 18. Current repository assessment

This assessment distinguishes a working technical foundation from product-complete capability.

| Capability | Current evidence in repository | Product status |
|---|---|---|
| AWS read-only inventory | AWS collectors, Go scanner, normalized inventory, scan APIs | Implemented foundation; production coverage and scale validation required |
| Account onboarding | CloudFormation and Terraform generation, ExternalId, verify endpoints | Implemented foundation; enterprise UX and lifecycle hardening required |
| Asset graph and attack paths | Graph engine, reachability, issues, attack-path UI | Implemented foundation; relationship quality and scale gates required |
| Findings and policies | Evidence model, rule registry, findings API and UI | Implemented foundation; policy lifecycle and broader coverage required |
| Compliance | Multiple catalogs, imports, statements of applicability, reports and history | Implemented foundation; licensed mappings and evidence assurance required |
| CIEM | Identity inventory, boundaries, trust and priority rules | Partial; effective permission, SCP, usage rightsizing, and multi-hop chains remain |
| Vulnerability management | Trivy, NVD, OSV, KEV, EPSS, SBOM-related services | Partial; deployment correlation and production agentless scanning remain |
| DSPM | Supported AWS stores and regex-based classification | Partial; privacy controls, scale, precision, and enterprise governance remain |
| IaC scanning | Terraform and CloudFormation scanning API | Partial; repository app, PR diff, gating, and code-to-cloud mapping remain |
| Runtime/eBPF | Tetragon sensor and runtime event endpoints | Partial; posture and runtime fusion remains roadmap |
| Azure and Google Cloud | Collector and normalizer scaffolding | Preview only; must not be represented as full coverage |
| Workflow integrations | Limited or roadmap documentation | Major product gap |
| Enterprise tenancy and access | Account scoping and API security components exist | Requires formal isolation, SSO, SCIM, RBAC, audit, and scale validation |

### 18.1 Recommended positioning

Near-term:

> Evidence-backed, AWS-first CSPM that turns cloud configuration, identity, vulnerability, and data signals into explainable attack paths and verifiable remediation.

Avoid describing the current product as a fully equivalent multicloud CNAPP until the Release 2 and Release 3 gates are met.

## 19. Release acceptance gates

### Gate A: Security and tenancy

- Independent tenant-isolation test passes.
- Threat model and penetration test have no unresolved Critical or High issue.
- SSO, RBAC, audit, encryption, backup, restore, retention, and offboarding are verified.
- No customer static cloud credentials are stored.

### Gate B: Coverage and evidence

- Supported AWS services and API actions are published.
- Curated inventory test accounts achieve at least 95% supported-asset recall.
- Denied APIs and stale sources are visible.
- Every Critical and High issue has inspectable, source-backed evidence.
- Policy regression suite covers true positive, true negative, missing evidence, and API error.

### Gate C: Risk and attack paths

- Red-team test topologies produce expected paths.
- Negative topologies do not produce unsupported paths.
- Confidence changes with freshness and missing evidence.
- Path-breaking recommendations are reviewed by cloud security engineers.

### Gate D: Operations

- Scan, event, and integration SLOs pass a 30-day pilot.
- Backup and restore exercises pass.
- Rate-limit, retry, partial failure, and provider outage tests pass.
- Support and incident runbooks are approved.

### Gate E: Customer value

- At least three design partners complete onboarding without vendor engineering access to their cloud accounts.
- At least 80% of surfaced Critical issues are confirmed actionable or accepted with documented reason.
- Median time from issue to owner is under one business day.
- Pilot customers demonstrate measurable material-risk reduction.

## 20. Success metrics

### 20.1 North-star metric

**Verified material-risk reduction:** the weighted number of previously active, evidence-backed attack paths that have been broken and independently revalidated during the reporting period.

### 20.2 Product metrics

- Time to first inventory.
- Time to first material-risk issue.
- Supported-asset coverage and stale-asset rate.
- Findings-to-issue compression ratio.
- Critical and High issue precision.
- Percentage of paths with complete evidence.
- Percentage of issues with owner.
- Median time to triage, assign, remediate, and verify.
- SLA breach rate.
- Recurrence rate.
- Exception count, age, and expiry compliance.
- Percentage of production findings detected in IaC before deployment.
- Integration delivery success and lag.
- Weekly active users by persona.

### 20.3 Guardrail metrics

- Cross-tenant access incidents: zero.
- Unapproved infrastructure changes: zero.
- Secret or sensitive-value persistence incidents: zero.
- Unsupported result shown as Pass: zero.
- Critical false-negative rate in curated regression environments.
- Cloud API throttling caused by collection.
- Customer workload performance impact.

## 21. Delivery roadmap

| Phase | Indicative duration | Outcome |
|---|---|---|
| Phase 0: Product hardening | 0-3 months | Tenant model, SSO/RBAC, audit, evidence contracts, coverage dashboard, operational SLOs |
| Phase 1: AWS CSPM GA | 3-6 months | AWS Organizations, event-aware inventory, policy and native finding ingestion, material-risk workflow, reports, integrations |
| Phase 2: Code and CIEM | 6-10 months | Git-based IaC gating, resource-to-code, effective permissions, role chains, rightsizing, Kubernetes identity |
| Phase 3: Multicloud | 10-15 months | Production-depth Azure and Google Cloud, unified policies, cross-cloud graph |
| Phase 4: Runtime CNAPP | 12-18 months | Posture-vulnerability-runtime fusion, response playbooks, advanced workload and data protection |

Dates are planning ranges, not commitments. Engineering estimation follows approved scope and architecture.

## 22. Dependencies

- Stable cloud provider APIs, audit logs, and service quotas.
- Legal review of control-framework and vulnerability-data licensing.
- Customer availability for design-partner validation.
- Enterprise identity, notification, ticketing, and source-control integrations.
- Production data architecture that supports graph traversal and historical evidence at target scale.
- Security engineering ownership of policy quality and attack-path regression environments.
- GRC ownership of control mappings and report language.
- Privacy approval for any sensitive-data sampling.

## 23. Business and delivery risks

| Risk | Impact | Mitigation |
|---|---|---|
| Overstating current multicloud capability | Loss of trust and failed evaluations | Publish provider and service coverage matrix with maturity status |
| False positives create alert fatigue | Low adoption | Evidence requirements, confidence, context, feedback loop, and policy quality gates |
| False negatives create false assurance | Security and legal exposure | Coverage gaps, Not assessed state, regression accounts, native finding ingestion |
| Excessive cloud permissions | Customer rejection and security risk | Least-privilege roles, ExternalId, permission diff, read-only default |
| Sensitive-data sampling creates privacy risk | Regulatory and trust impact | Metadata first, opt-in sampling, redaction, no value retention, scoped policy |
| Automated remediation disrupts production | Availability incident | Preview, approval, canary, rollback, verification, bounded automation |
| Graph scale or poor entity resolution | Slow or inaccurate paths | Canonical IDs, versioned schemas, bounded queries, scale testing |
| Provider changes outpace policy catalog | Coverage decay | Native finding ingestion, versioned policy pipeline, telemetry and content SLO |
| Framework licensing misuse | Commercial and legal exposure | Legal review and licensed content strategy |
| Product becomes an unmanageable CNAPP bundle | Delayed delivery | AWS-first sequencing, explicit release gates, integration over reinvention |

## 24. Governance and RACI

| Decision or activity | Product | Security | Engineering | GRC | Privacy/Legal | Customer Success |
|---|---|---|---|---|---|---|
| Product scope and priority | A/R | C | C | C | C | C |
| Security architecture and threat model | C | A/R | R | C | C | I |
| Collector and platform implementation | C | C | A/R | I | I | I |
| Policy logic and risk model | A | R | R | C | I | C |
| Framework mapping and report wording | C | C | I | A/R | C | I |
| Data sampling and retention | C | R | R | C | A | I |
| Release approval | A | R | R | R | C | C |
| Pilot success and adoption | A | C | C | C | I | R |

Legend: A = Accountable, R = Responsible, C = Consulted, I = Informed.

## 25. Assumptions

- CloudSentinel is delivered primarily as SaaS.
- The initial commercial product is AWS-first.
- Customers can deploy a read-only role and permit outbound communication or API access as required.
- Customers retain authority for infrastructure changes.
- Vulnerability, provider, and framework data sources may have licensing and usage constraints.
- Exact service coverage, scale limits, retention, regions, and service tiers will be published separately.
- "CloudSentinel" is the customer-facing name and "Odineyes" is the current repository codename; product leadership must confirm naming before launch.

## 26. Decisions required

| ID | Decision | Owner | Required by |
|---|---|---|---|
| DEC-01 | Confirm product name: CloudSentinel, Odineyes, or another brand | Executive/Product | Before external collateral |
| DEC-02 | Confirm first customer segment and regulated industries | Product/Sales | Before roadmap commitment |
| DEC-03 | Select SaaS regions and data-residency model | Product/Legal/Engineering | Before production architecture freeze |
| DEC-04 | Approve supported AWS service matrix for GA | Security/Product | Before pilot |
| DEC-05 | Select ticketing, SIEM, source-control, and collaboration integrations for GA | Product | Before Phase 1 build |
| DEC-06 | Approve default retention and tenant deletion policy | Legal/Privacy/Security | Before pilot data |
| DEC-07 | Approve risk-model governance and customer customization boundaries | Product/Security/GRC | Before GA |
| DEC-08 | Decide whether automated remediation is excluded from GA or offered as limited preview | Product/Security | Before pilot contract |
| DEC-09 | Confirm commercial licensing approach for CIS, CSA CCM, and other framework content | Legal/GRC | Before commercial reporting |
| DEC-10 | Define pricing metric, such as cloud resources, workloads, accounts, or annual cloud spend | Product/Finance | Before launch |

## 27. Traceability summary

| Business objective | Primary requirements |
|---|---|
| BO-01 Trusted visibility | FR-ONB, FR-AST, NFR-002, NFR-010 |
| BO-02 Reduce alert overload | FR-RISK, FR-NET, FR-CIEM, FR-VUL, FR-DSPM |
| BO-03 Accelerate remediation | FR-WF, FR-IAC, FR-RISK-004 |
| BO-04 Improve accountability | FR-AST-005, FR-WF-002, FR-IAC-004 |
| BO-05 Improve assurance efficiency | FR-GRC, FR-RPT |
| BO-06 Prevent recurrence | FR-WF-006, FR-CSPM-007, FR-GRC-005 |
| BO-07 Engineering adoption | FR-IAC, FR-WF-004 |
| BO-08 Build customer trust | FR-CSPM-002, FR-ONB-004, NFR-015 |

## 28. Glossary

| Term | Definition |
|---|---|
| CSPM | Cloud Security Posture Management |
| CNAPP | Cloud-Native Application Protection Platform |
| CIEM | Cloud Infrastructure Entitlement Management |
| DSPM | Data Security Posture Management |
| CWPP | Cloud Workload Protection Platform |
| IaC | Infrastructure as Code |
| Attack path | Evidence-backed sequence of relationships and weaknesses that may lead from an entry point to a material target |
| Toxic combination | Multiple conditions whose combined risk is materially greater than any isolated condition |
| Material-risk issue | Deduplicated, contextual unit of risk suitable for ownership and remediation |
| Crown jewel | Asset or business service whose compromise would have exceptional business impact |
| Effective permission | Net permission after applicable grants, explicit denies, boundaries, session restrictions, resource policies, and organization controls |
| Evidence | Source-backed configuration or event data used to support an evaluation |
| Coverage gap | A scope in which data is missing, stale, denied, unsupported, or otherwise insufficient |

## 29. Research sources

Market and standards research was reviewed on 30 July 2026.

### Vendor and cloud-provider sources

- [Wiz CSPM](https://www.wiz.io/solutions/cspm)
- [Palo Alto Networks Prisma Cloud CSPM](https://www.paloaltonetworks.com/prisma/cloud/cloud-security-posture-management)
- [Orca Security platform overview](https://orca.security/resources/product-info/orca-cloud-security-platform-solution-brief/)
- [Microsoft Defender for Cloud CSPM](https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management)
- [AWS Security Hub CSPM](https://aws.amazon.com/security-hub/cspm/)
- [AWS Security Hub CSPM control reference](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html)
- [Google Cloud Security Command Center security posture](https://docs.cloud.google.com/security-command-center/docs/security-posture-overview)
- [CrowdStrike Falcon Cloud Security CSPM](https://www.crowdstrike.com/en-us/platform/cloud-security/cspm/)

### Standards sources

- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20)
- [Cloud Security Alliance Cloud Controls Matrix 4.1](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1)
- [CIS Amazon Web Services Benchmarks](https://www.cisecurity.org/benchmark/amazon_web_services)
- [PCI DSS 4.0.1 document library](https://www.pcisecuritystandards.org/document_library/?class=pcidss&doc=pci_dss)

### Incident sources

- [Toyota cloud configuration notice](https://global.toyota/en/newsroom/corporate/39241625.html)
- [Microsoft Security Response Center storage SAS incident](https://www.microsoft.com/en-us/msrc/blog/2023/09/microsoft-mitigated-exposure-of-internal-information-in-a-storage-account-due-to-overly-permissive-sas-token)
- [CircleCI January 2023 incident report](https://circleci.com/blog/jan-4-2023-incident-report/)
- [Mandiant report on UNC5537 and Snowflake customer instances](https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion)
- [GitHub Advisory CVE-2025-30066](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3)

## 30. Approval

Approval confirms agreement on business outcomes, scope boundaries, priorities, and release gates. It does not approve implementation estimates or customer commitments not explicitly included in this document.

| Role | Name | Decision | Date |
|---|---|---|---|
| Executive sponsor |  | Approve / Reject |  |
| Product owner |  | Approve / Reject |  |
| Security owner |  | Approve / Reject |  |
| Engineering owner |  | Approve / Reject |  |
| GRC owner |  | Approve / Reject |  |
| Privacy / Legal |  | Approve / Reject |  |
