# Trivy EBS Direct vulnerability scanning

Odineyes can scan an existing private EBS snapshot without attaching it to an
EC2 instance. The API invokes Trivy's experimental `vm` target with the
`ebs:<snapshot-id>` source. Trivy reads only the snapshot blocks it needs
through the AWS EBS Direct APIs and reports package vulnerabilities.

## Scanner boundary

Odineyes does not implement vulnerability matching. Aqua Security Trivy is the
scanner and vulnerability database. Odineyes provides AWS lifecycle control,
temporary STS credentials, result normalization, graph correlation, evidence,
and cleanup.

## What this release does

1. The operator creates or selects a private EBS snapshot through an approved
   customer process.
2. Odineyes assumes the account's optional `OdineyesReadOnly-DiskScan` role
   using the account-specific ExternalId.
3. The API starts `trivy vm --scanners vuln ebs:<snapshot-id>` with only the
   temporary role credentials in its child-process environment.
4. Odineyes stores normalized CVE metadata and scan coverage. It does not store
   file contents, package databases, snapshot blocks, or secret values.

The explicit snapshot endpoint remains read-only. It does **not** create,
share, attach, mount, or delete customer resources.

The EC2 lifecycle endpoint automates one bounded operation:

1. Resolve only the instance's root EBS volume.
2. Reject volumes above `ODINEYES_EBS_DIRECT_MAX_VOLUME_GIB` (100 GiB by
   default) and repeat requests inside `ODINEYES_EBS_SCAN_COOLDOWN_HOURS`
   (12 hours by default).
3. Create an incremental snapshot tagged `ManagedBy=CSPM-G3`,
   `Purpose=OdineyesAgentlessScan`, source instance, and expiry time.
4. Wait for completion and run the official `trivy vm` command.
5. Persist normalized CVEs against the EC2 instance, not the temporary
   snapshot.
6. Delete the snapshot in a `finally` cleanup path whether scanning succeeds
   or fails. Cleanup failure remains visible in scan evidence.

## Onboarding permissions

Set `EnableDiskScanning=true` in the customer CloudFormation onboarding stack.
The stack creates the separate disk role and grants the EBS Direct actions
needed by Trivy:

```yaml
ebs:ListSnapshotBlocks
ebs:GetSnapshotBlock
```

The role is separate from `OdineyesReadOnly` because snapshot creation and KMS
grant operations are data-access capabilities. The standard inventory role
remains read-only. Encrypted snapshots using a customer-managed KMS key also
need a key policy that permits the disk role; the onboarding stack cannot alter
customer-owned key policies safely.

## API

Preferred automated lifecycle (returns HTTP 202 and runs in the background):

```http
POST /api/inventory/vulnerabilities/scan-ec2-instance
Content-Type: application/json
Authorization: Bearer <operator-token>

{
  "provider": "aws",
  "account_identifier": "123456789012",
  "region": "ap-south-1",
  "instance_id": "i-0123456789abcdef0"
}
```

Existing-snapshot scan:

```http
POST /api/inventory/vulnerabilities/scan-ebs-snapshot
Content-Type: application/json
Authorization: Bearer <operator-token>

{
  "provider": "aws",
  "account_identifier": "123456789012",
  "region": "ap-south-1",
  "snapshot_id": "snap-0123456789abcdef0"
}
```

The response reports `scanned: false` with `skipped_reason` when disk scanning
is not enabled, Trivy is unavailable, role assumption fails, or EBS Direct
access is denied. A skipped scan never resolves pre-existing vulnerabilities.

## Container packaging

The local Docker image and the AWS runtime Docker image install the pinned
Trivy release using `scripts/install-trivy.sh`. The script verifies the official
release checksum and records the installed binary's SHA-256. At runtime,
Odineyes refuses a binary whose hash no longer matches the recorded pin.

`ODINEYES_TRIVY_VM_TIMEOUT_SECONDS` controls the VM scan ceiling. It defaults
to 1800 seconds and is clamped between 60 and 7200 seconds. Start with a small
number of snapshots and set AWS Budgets or Cost Anomaly Detection because EBS
Direct API reads are billable. `ODINEYES_EBS_SNAPSHOT_WAIT_SECONDS` bounds the
snapshot waiter. `ODINEYES_EBS_DIRECT_MAX_VOLUME_GIB` and
`ODINEYES_EBS_SCAN_COOLDOWN_HOURS` bound per-scan and event-churn cost.

## Why this is the default agentless path

The EBS Direct method avoids a scanner EC2, temporary EBS volume, remote mount,
and cleanup race. It is the safer first implementation for vulnerability
inventory. Trivy documents the VM target as experimental, so Odineyes keeps its
scope narrow and records scan evidence for every attempt.

Regional Fargate execution remains a future worker backend. Current free-tier
production runs the same pinned Trivy binary inside the isolated Odineyes API
container and assumes the customer disk role for each scan. Adding Fargate now
would add ECR, ECS networking, task roles, result delivery, and regional rollout
without changing scanner results.

The mounted-volume workflow remains a future option for content inspection that
cannot be performed through Trivy VM scanning. It must run in a dedicated
isolated worker VPC with encrypted temporary volumes, read-only mounts, a
cleanup watchdog, and explicit customer consent before it is enabled.
