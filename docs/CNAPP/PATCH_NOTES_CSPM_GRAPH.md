# Odineyes CSPM Patch Notes — Evidence-Aware Attack Paths

**Release scope:** AWS inventory, IAM relationship modelling, Attack Paths, and CSPM prioritization.

## Summary

Odineyes now derives attack-path relationships from explicit IAM evidence instead of treating every finding as an isolated alert. The system can connect public compute, workload roles, role chaining, and S3 data access into an explainable path.

It also explains when an empty Attack Paths view means **insufficient evidence** rather than a clean cloud environment.

## Added

### IAM evidence collection

- Collects explicit unconditional `sts:AssumeRole` permissions from IAM users and roles.
- Collects explicit unconditional S3 object-read permissions.
- Preserves role trust information alongside the identity policy evidence.
- Stores the collection state through `policy_analysis_complete`.
- Handles AWS trust policies where `Principal` is the literal wildcard string (`"*"`).

### Security graph relationships

- Adds IAM users as graph nodes.
- Derives `CAN_ASSUME` only when both conditions are evidenced:
  1. the source identity policy allows `sts:AssumeRole`; and
  2. the target role trust policy accepts that identity or account.
- Derives `CAN_ACCESS` when an identity has an explicit S3 read grant or administrator-level access.
- Supports S3 object/prefix grants by mapping them back to the corresponding bucket node.
- De-duplicates graph relationships while preserving evidence metadata.

### Attack-path analysis

The detector can now model a bounded multi-role chain such as:

```text
Internet
  → exposed EC2 workload
  → attached workload role
  → assumable privileged/data role
  → sensitive S3 bucket
```

The issue includes the chain and remediation guidance to remove unnecessary role assumption, S3 access, or overly broad trust.

### Attack Paths user experience

- Adds an analysis-readiness panel to the graph view.
- Displays assets, graph relationships, traversable relationships, entry points, and detected paths.
- Shows evidence coverage for inventory, identity, data, relationships, and entry points.
- Distinguishes these outcomes:
  - `paths_detected`
  - `no_entry_points_observed`
  - `no_path_to_target`
  - `insufficient_identity_evidence`
  - `not_analyzed`
- Running **Analyze** now evaluates all accounts in the current scope instead of silently using only the first account.

## Why an empty Attack Paths page may still be correct

An empty graph is no longer automatically presented as a secure result.

| Situation | Meaning in Odineyes |
|---|---|
| IAM policy evidence is incomplete | The result is **partial**; initiate a new scan before making a security decision. |
| No public or externally trusted entry relationship exists | The graph reports that no modeled entry point was observed. |
| Entry points exist but cannot reach privileged identities or data | The graph reports no path to a target. |
| A complete relationship chain exists | Odineyes reports a walkable attack path with source evidence. |

## Required action after deployment

Existing inventory records do not contain the newly collected IAM policy fields. Rebuild/restart the application, then run a new scan for every connected AWS account.

For the current Dharani account, the first scan after this patch is required before Attack Paths can assess the account with complete identity evidence.

## Verification completed

- Backend: **101 tests passed** across raw AWS collection, normalization, graph derivation, persistence, inventory API, exploitation, and attack-path logic.
- Frontend: TypeScript check passed.
- Production frontend build passed.
- `git diff --check` passed.

## Intentional limitations

This release uses conservative, explicit-Allow evidence. It does not yet calculate AWS's complete authorization result.

- IAM group policies, permission boundaries, SCPs, session policies, explicit denies, and conditional policies are not yet fully evaluated.
- Network reachability is not yet route-level; VPC route tables, NACLs, load balancers, and firewall paths remain the next implementation area.
- Data sensitivity classification requires a consented integration such as Amazon Macie, tags, metadata, or a DSPM provider.
- Trivy CVEs still need deployment, exposure, identity, and data-context correlation for risk-based prioritization.

## Open-source implementation references

The roadmap uses ideas and integration boundaries inspired by:

- [Cartography](https://github.com/cartography-cncf/cartography) for cloud asset/relationship graph patterns.
- [Principal Mapper](https://github.com/nccgroup/PMapper) for IAM relationship and privilege-escalation analysis.
- [Cloudsplaining](https://github.com/salesforce/cloudsplaining) for IAM policy-risk analysis.
- [Trivy](https://github.com/aquasecurity/trivy) for vulnerabilities, secrets, SBOM, and IaC signals.

No proprietary Wiz implementation was copied. Any future open-source integration must be pinned, license-reviewed, dependency-reviewed, and provenance-verified before production use.
