# Odineyes CSPM Policy Coverage Strategy

Status: Phase 1 implemented locally
Scope: AWS-first CSPM and CNAPP policy expansion
Architecture: modular monolith with versioned policy packs

## 1. Product objective

Odineyes should provide broad posture coverage without treating policy count as
the product. The target outcome is:

> Continuously collect sufficient cloud evidence, evaluate configuration and
> identity controls, correlate related weaknesses into attack paths, and explain
> the smallest safe remediation that breaks material exposure.

Wiz and other mature CNAPP products combine several engines:

- cloud configuration policies;
- identity entitlement and trust analysis;
- network reachability;
- vulnerability and secret scanning;
- data sensitivity;
- Kubernetes and runtime evidence;
- graph-based toxic combinations;
- compliance mappings and exceptions.

Odineyes should follow the same capability model without copying proprietary
Wiz policy text or implementations. Built-in controls should come from public
cloud-provider guidance, open standards, and appropriately licensed open-source
policy projects.

Useful public baselines:

- [AWS Security Hub CSPM control reference](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html)
- [AWS Config managed rule catalog](https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html)

## 2. Current implemented baseline

The persisted native policy engine now contains 71 policies:

| Category | Policies |
|:---|---:|
| Data | 30 |
| Management and logging | 11 |
| Identity | 11 |
| Compute | 9 |
| Network | 7 |
| Application | 3 |
| **Total** | **71** |

Evaluation shape:

| Mode | Policies |
|:---|---:|
| Single-resource evaluation | 66 |
| Relationship or account evaluation | 5 |
| Evidence-gated enrichment policies | 21 |

Service distribution:

| Service | Policies |
|:---|---:|
| IAM (including account-wide settings) | 11 |
| RDS, Aurora, Neptune, DocumentDB | 8 |
| EC2 networking and compute | 7 |
| CloudTrail | 6 |
| S3 | 5 |
| DynamoDB | 3 |
| EBS volumes and snapshots | 3 |
| ECR | 3 |
| ECS | 3 |
| API Gateway | 2 |
| CloudWatch Logs | 2 |
| EFS | 2 |
| EKS | 2 |
| GuardDuty | 2 |
| KMS | 2 |
| Secrets Manager | 2 |
| SNS | 2 |
| SQS | 2 |
| AWS Config | 1 |
| Lambda | 1 |
| Redshift | 1 |
| VPC flow logs | 1 |

The collector registry behind these policies is 29 operations across 22
services plus six identifier-list collection paths (ECS clusters, ECS task
definitions, EKS, SQS, DynamoDB, GuardDuty) and the account IAM settings
pseudo-asset. The derived least-privilege onboarding policy
is 83 IAM actions — it is generated from the registry, so it cannot drift from
what the code calls.

The catalog is available from:

```text
GET /api/inventory/policy-catalog
GET /api/inventory/policy-catalog?service=s3
GET /api/inventory/policy-catalog?category=identity
GET /api/inventory/policy-catalog?evaluation_mode=relationship
```

The repository also contains broader but currently separate engines:

- Powerpipe and Steampipe AWS compliance benchmarks;
- Trivy image, package, secret, and SBOM scanning;
- Checkov infrastructure-as-code scanning;
- Tetragon runtime evidence for Linux workloads;
- custom normalized-asset policies.

The principal integration gap is that broad Powerpipe findings are returned by
the live compliance API but are not reconciled into the same persisted Finding
model used by inventory, risk, history, and attack-path correlation.

## 3. Architecture decision

### Context

Hand-writing every AWS control would be slow and expensive to maintain. Using
only an external benchmark runner would provide breadth but would not provide
Odineyes-specific evidence quality, graph relationships, risk context, finding
history, or explainable attack paths.

Constraints:

- small development team;
- AWS-first scope;
- free-tier-sensitive production environment;
- SQLite development and current modular-monolith backend;
- low tolerance for false positives;
- scans must remain useful when individual AWS APIs are denied.

### Options

| Option | Advantages | Costs |
|:---|:---|:---|
| Hand-code every rule | Full control and graph awareness | Slow expansion and high maintenance |
| Use only external scanners | Immediate breadth | Fragmented findings and weak contextual correlation |
| Hybrid native plus adapters | Broad coverage and native graph intelligence | Requires a canonical adapter contract |

### Decision

Use a hybrid policy architecture:

1. Native evidence-aware policies for high-value posture and relationship checks.
2. Powerpipe or another licensed policy pack for broad cloud configuration coverage.
3. Trivy and Checkov for workload and pre-deployment coverage.
4. A single normalized persisted Finding contract for every engine.
5. Graph correlation promotes related findings into attack paths.

### Trade-offs

- External policy packs remain pinned dependencies and require parser contract tests.
- Native policies remain necessary for controls that depend on Odineyes graph
  evidence or need strict false-positive suppression.
- A policy adapter layer adds code, but avoids separate finding silos.

### Revisit trigger

Split policy execution into independent workers only when scan concurrency or
benchmark duration cannot be supported by the modular monolith.

## 4. Evidence model

Every collected property must have one of these states:

```text
observed   API returned the configuration
absent     API proved that the configuration does not exist
denied     scanner lacked permission
error      API, endpoint, or parser failed
```

Only `observed` and, where semantically valid, `absent` can produce a failed
policy. `denied` and `error` must produce a coverage gap, never an insecure
configuration finding.

This phase implements that behavior for S3 encryption, versioning, access
logging, public access block, Secrets Manager resource policies, CloudTrail
logging status, and AWS Config recorder status.

## 5. Phase 1 implemented policy expansion

New policies:

### S3

- default encryption disabled;
- versioning disabled;
- server access logging disabled;
- incomplete bucket-level Block Public Access.

### EC2 and VPC

- IMDSv2 not required;
- subnet automatically assigns public IPv4 addresses.

### Databases

- RDS, Aurora, Neptune, or DocumentDB cluster unencrypted;
- database cluster deletion protection disabled;
- RDS backup retention shorter than seven days;
- RDS instance deletion protection disabled;
- RDS Proxy does not require TLS.

### Secrets, containers, and monitoring

- Secrets Manager rotation disabled;
- unconditional wildcard secret resource policy;
- ECS Container Insights disabled;
- CloudTrail trail not actively logging;
- KMS key pending deletion.

Corrections included:

- `describe_subnets` now reads the explicit `Subnets` response member instead of
  selecting an arbitrary response list;
- non-object AWS resource entries become explicit response-shape errors;
- wildcard resource policies with restrictive conditions are not labelled public;
- denied CloudTrail and Config status calls no longer generate false findings;
- S3 access logging is now actually collected before evaluating its policy.

## 6. Prioritized coverage roadmap

### Phase 2: collection breadth and foundational AWS controls

Target: 80 to 120 persisted policies. Currently at 71.

Delivered:

- EBS volumes and snapshots, including snapshot sharing (`createVolumePermission`);
- ECR repositories, image scan configuration, lifecycle policies, and repository policies;
- VPC records and flow-log coverage;
- EFS file systems and resource policies;
- DynamoDB tables, point-in-time recovery, deletion protection, and key governance;
- SQS and SNS encryption and access policies;
- API Gateway REST APIs and per-stage logging and cache encryption;
- GuardDuty detector status, including the "no detector anywhere" account case;
- IAM account summary and password policy (root access keys, root MFA, CIS password baseline).

Still open:

- ELB listeners, target groups, TLS policies, access logging, deletion protection, and WAF attachment;
- NAT gateways, VPC endpoints, and peering;
- EventBridge and Kinesis encryption and access policies;
- Security Hub, Inspector, Macie, and Access Analyzer status;
- IAM credential report, groups, permission boundaries, and policy condition evidence.

Required rule families:

- encryption and key governance;
- public and cross-account access;
- logging and audit coverage;
- backup and deletion resilience;
- TLS and authentication requirements;
- service-level security feature enablement;
- stale and excessive identity permissions.

### Phase 3: persist external policy findings

Target: broad AWS control coverage with one finding lifecycle.

Implement a `PolicyFindingAdapter` contract:

```text
engine result
  -> source policy id
  -> canonical resource id
  -> normalized severity
  -> observed evidence
  -> remediation
  -> framework mappings
  -> FindingRepository reconciliation
```

Adapters:

- Powerpipe and Steampipe;
- AWS Security Hub findings;
- Checkov;
- Trivy misconfiguration and secret findings.

Deduplicate by:

```text
account + canonical resource + semantic control family
```

The native finding should win when it has stronger graph or evidence context.
External results remain attached as supporting evidence.

### Phase 4: CIEM and attack-path depth

Target: 30 or more high-confidence relationship policies.

Collect and evaluate:

- effective IAM permissions;
- resource policies;
- role trust conditions;
- `iam:PassRole`;
- permission boundaries;
- session policies;
- AWS Organizations service control policies;
- Access Analyzer findings;
- instance profile to role resolution;
- Lambda and ECS task execution roles;
- cross-account S3, KMS, Secrets Manager, SQS, SNS, and ECR access.

Required path patterns:

- exposed workload to privileged role;
- role chaining to administration;
- identity to sensitive data;
- public service to secret;
- cross-account trust to destructive privilege;
- vulnerable deployed image to cloud credentials;
- compromised workload to data exfiltration.

### Phase 5: EKS, Kubernetes, and runtime

Target: combined CSPM, KSPM, CWPP, and runtime prioritization.

- EKS control-plane configuration;
- Kubernetes RBAC and workload security;
- admission policies and network policy;
- Trivy Kubernetes and image results;
- Tetragon runtime findings;
- actively exploited attack-path promotion.

### Phase 6: multi-cloud

Use the same asset, evidence, policy, and finding contracts for:

- Azure subscriptions and resource graph;
- GCP projects and Cloud Asset Inventory;
- cross-cloud identity and data relationships.

## 7. Policy quality gates

Every built-in policy must include:

1. Stable policy identifier.
2. Supported asset types.
3. Evidence prerequisites.
4. Pass, fail, and unknown semantics.
5. Severity and contextual elevation rules.
6. Human remediation.
7. Compliance mappings.
8. Positive fixture.
9. Secure negative fixture.
10. Missing or denied evidence fixture.
11. Duplicate and reconciliation regression coverage.

A policy must not ship if it treats any of these as equivalent:

```text
public endpoint configured != internet reachable
property absent             != permission denied
wildcard principal          != unconditional public access
CVE present                 != deployed and exploitable
control not assessed        != control failed
```

## 8. Success metrics

Track quality alongside count:

| Metric | Initial target |
|:---|:---|
| Persisted native policies | 40, then 80 to 120 |
| Relationship policies | 4, then 30+ |
| Evidence-gated enrichment facets | 7, then all optional facets |
| False-positive rate on reviewed findings | below 5% |
| Findings with canonical resource linkage | above 98% |
| Findings with remediation | 100% |
| Collection errors shown as coverage gaps | 100% |
| High-risk paths with complete evidence | above 90% |

Policy count is a coverage indicator, not the primary quality metric. The product
should be judged by whether it identifies material, explainable exposure with
enough evidence for an operator to act.
