# Odineyes CSPM — Prioritized Product and Implementation Solution

## Objective

Odineyes must answer one operational question reliably:

> Which evidenced combination of exposure, identity privilege, vulnerable workload, and sensitive data creates material cloud risk, and what smallest change breaks that path?

The product is not measured by raw rule count. It is measured by inventory completeness, relationship accuracy, path explainability, alert reduction, and remediation verification.

## Priority order

| Priority | Outcome | Why now | Delivery state |
|---|---|---|---|
| P0 | Trustworthy onboarding, scans, and evidence coverage | Every other feature is misleading if credentials, assets, or evidence are missing | In progress |
| P0 | Relationship-aware IAM/data attack paths | Atomic findings do not show realistic blast radius | First vertical slice implemented |
| P1 | Complete IAM effective-access analysis | Explicit allows are only part of AWS authorization | Research/integration phase |
| P1 | Network reachability graph | Public flags alone do not prove reachability | Next implementation phase |
| P1 | Contextual vulnerability correlation | CVE severity without deployment context creates noise | Trivy foundation exists |
| P2 | Continuous drift and event ingestion | Periodic snapshots leave a detection window | Planned |
| P2 | Data classification and DSPM | Configuration cannot identify sensitive content | Planned, consent-sensitive |
| P3 | Owner-aware remediation and verification | A finding without a safe workflow remains operational debt | Planned |
| P3 | Multi-cloud semantic parity | AWS correctness should stabilize before broad shallow coverage | Planned |

## P0 delivered in this slice

1. IAM enrichment preserves explicit, unconditional `sts:AssumeRole` and S3 object-read resource grants.
2. Role trust is collected with the permission side of `AssumeRole`.
3. The graph derives policy-backed `CAN_ASSUME` and `CAN_ACCESS` edges.
4. The attack-path detector follows bounded role chains before deciding whether a public workload reaches data.
5. The graph API reports analysis readiness, evidence counts, conclusion, and explicit limitations.
6. The UI distinguishes `no path observed` from `insufficient IAM evidence`.
7. Fleet-wide Analyze evaluates every scoped account instead of silently analyzing only the first account.

The implementation is intentionally conservative. Conditional policies, `NotAction`, `NotResource`, permission boundaries, SCPs, session policies, and explicit deny precedence do not generate new edges yet. The API exposes this boundary instead of presenting the result as complete.

## P0 completion work

### Onboarding and scan preflight

- Model onboarding as `draft -> role_created -> access_verified -> scanning -> healthy/degraded`.
- Disable Scan when `role_arn` is absent.
- Run `sts:GetCallerIdentity` and a target `AssumeRole` preflight before queueing a full scan.
- Persist preflight error category separately from scan errors.
- Display the exact principal, target role, ExternalId presence, and permission failure class without exposing credentials.

### Collection coverage

- Persist attempted, successful, denied, truncated, and unsupported operations per scan.
- Report coverage by AWS service and region.
- Never interpret an empty service result as clean when its listing API failed.
- Add freshness and authoritative-scope status to every security conclusion.

### Supply-chain controls

- Pin every downloaded binary by version and independently stored SHA-256.
- Verify release provenance/signatures where available.
- Produce an SBOM for the Odineyes image.
- Block production builds when a binary checksum is absent.
- Track upstream security advisories before version promotion.

## P1: effective IAM authorization

The immediate graph handles explicit unconditional allows. Production CIEM requires an evaluator for:

- Users, groups, roles, instance profiles, workload identities, and federated identities.
- Identity policies and resource policies.
- Permission boundaries and session policies.
- AWS Organizations SCPs.
- Explicit deny precedence.
- Conditions such as source ARN, source account, tags, MFA, IP, VPC endpoint, OIDC subject, and ExternalId.
- `iam:PassRole`, policy mutation, access-key creation, trust-policy mutation, and service-mediated escalation.

Recommended approach:

1. Collect `GetAccountAuthorizationDetails` as the IAM snapshot backbone.
2. Normalize policy statements separately from asset presentation properties.
3. Build a deterministic effective-permission evaluator with fixture parity against AWS policy simulation.
4. Use Principal Mapper and Cloudsplaining as reference implementations and validation oracles; do not copy unreviewed code directly into the runtime.
5. Store edge evidence: policy ARN, statement SID, action, resource, condition summary, and confidence.

Definition of done: every `CAN_ASSUME`, `CAN_ACCESS`, and `CAN_ESCALATE` edge can explain both the allowing statements and any limiting controls.

## P1: network reachability

Model the path rather than only the asset's public flag:

`Internet -> DNS/CDN/API/LB -> listener -> target -> ENI -> security group -> subnet route -> workload`

Collect and relate VPCs, subnets, route tables, internet/NAT/transit gateways, ENIs, NACLs, security groups, load balancers, API Gateway, CloudFront, Lambda URLs, EKS services, and private endpoints.

Definition of done: an exposure finding identifies the protocol/port, ingress source, routing evidence, target workload, and the exact control that breaks reachability.

## P1: contextual vulnerabilities

Keep Trivy as a scanner adapter, not a separate product silo. Correlate each CVE with:

- Deployed image digest or workload package evidence.
- Internet or lateral reachability.
- Workload IAM identity and reachable data.
- CISA KEV and EPSS where available.
- Fix availability and running-versus-unused package state.

Priority should rise for an exploitable, deployed, reachable workload with privilege or sensitive-data access, and fall for an unreachable image not deployed anywhere.

## P2: drift and data security

### Continuous drift

- Consume CloudTrail/EventBridge events into the asset-event timeline.
- Trigger narrow resource refreshes after security-relevant changes.
- Retain scheduled full scans for reconciliation and missed-event recovery.
- Compare deployed state with IaC state and identify console drift.

### DSPM

- Start with tags, resource metadata, Macie findings, encryption, public access, and effective principals.
- Keep object/content sampling disabled by default.
- Require explicit customer consent, strict sampling limits, and no content retention.
- Feed sensitivity and regulatory taxonomy into path risk, not a disconnected data page.

## P3: remediation workflow

Every material issue should support:

- Accountable owner and business context.
- Proposed minimal path-breaking change.
- CLI/IaC patch preview.
- Approval and ticket state.
- Risk acceptance with expiry.
- Post-change rescan and verified closure.
- Rollback guidance for availability-sensitive controls.

## Open-source adoption policy

Use open source by interface and evidence, not by uncontrolled vendoring.

| Project | Useful pattern | Odineyes use |
|---|---|---|
| Aqua Trivy | Vulnerability, secret, IaC, image, Kubernetes and SBOM scanning | Existing adapter; keep version/checksum/provenance pinned |
| CNCF Cartography | Relationship-first cloud inventory in Neo4j | Schema and ingestion reference; retain SQL as source of truth and Neo4j as projection |
| NCC Group PMapper | IAM principal graph and privilege-escalation analysis | Effective-permission validation reference |
| Salesforce Cloudsplaining | Least-privilege and risk-oriented IAM policy analysis | Policy risk classification reference |
| CloudQuery | Broad typed cloud collection and incremental sync | Evaluate as an optional collector adapter, not a second canonical datastore |
| Wiz public research/data | Cloud vulnerability and attack-path research | Research input only; use only clearly licensed repositories/data |

Before adoption: verify license compatibility, maintenance health, release signatures, known advisories, transitive dependencies, data handling, and the ability to pin reproducibly.

## Success metrics

- Inventory: percentage of enabled accounts, regions, and expected services authoritatively scanned.
- Identity: percentage of principals with complete policy/trust/boundary/SCP evaluation.
- Graph: percentage of edges carrying source evidence and confidence.
- Detection: precision, recall, duplicate rate, and findings per material attack path.
- Operations: median time to triage, owner assignment, remediation, and verified closure.
- Freshness: delay from cloud change to posture update.
- Safety: failed or rolled-back automated remediations.

## Immediate next implementation order

1. Complete onboarding/access preflight and disable invalid scan actions.
2. Persist per-service/per-region collection coverage.
3. Add group policies, resource policies, boundaries, SCPs, and deny/condition semantics.
4. Expand the network graph from public flags to route-level reachability.
5. Correlate Trivy findings with deployed workload, identity, exposure, and data.
6. Add EventBridge/CloudTrail narrow refresh and drift history.
7. Integrate Macie/metadata classification before any content sampling.

## Reference implementations

- Trivy: https://github.com/aquasecurity/trivy
- Cartography: https://github.com/cartography-cncf/cartography
- Principal Mapper: https://github.com/nccgroup/PMapper
- Cloudsplaining: https://github.com/salesforce/cloudsplaining
- CloudQuery: https://github.com/cloudquery/cloudquery

