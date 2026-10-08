"""CIS Amazon Web Services Foundations Benchmark v1.5.0 — full control catalog.

The control reference numbers (1.1 … 5.6) and their short titles are factual
identifiers of the published benchmark, reproduced widely (AWS Security Hub, the
CIS website, every CSPM). The copyrighted *rationale/audit/remediation* prose
from the CIS PDF is NOT included — only the control list and section tree that a
compliance report and Statement of Applicability need.

A CSPM auto-assesses the controls that map to a cloud-config check (see
``CHECK_MAP``); the inherently-manual controls (contact details, root-user
hygiene, data classification, peering least-access) surface as ``not_assessed``,
which is honest and exactly what an auditor expects from automated coverage.

Five sections: 1 IAM · 2 Storage · 3 Logging · 4 Monitoring · 5 Networking.
"""

from __future__ import annotations

from typing import Any

# Section names match the platform-wide labels (compliance_mapper._SECTION_BY_CATEGORY)
# so a control's section aggregates consistently across frameworks.
IAM = "Identity and Access Management"
STORAGE = "Storage"
LOGGING = "Logging"
MONITORING = "Monitoring"
NETWORKING = "Networking"

# (control_id, title, profile_level). Level 1 = baseline, Level 2 = defense-in-depth.
_CONTROLS: list[tuple[str, str, int, str]] = [
    # ── 1 Identity and Access Management ────────────────────────────────────
    ("1.1",  "Maintain current contact details", 1, IAM),
    ("1.2",  "Ensure security contact information is registered", 1, IAM),
    ("1.3",  "Ensure security questions are registered in the AWS account", 1, IAM),
    ("1.4",  "Ensure no 'root' user account access key exists", 1, IAM),
    ("1.5",  "Ensure MFA is enabled for the 'root' user account", 1, IAM),
    ("1.6",  "Ensure hardware MFA is enabled for the 'root' user account", 2, IAM),
    ("1.7",  "Eliminate use of the 'root' user for administrative and daily tasks", 1, IAM),
    ("1.8",  "Ensure IAM password policy requires minimum length of 14 or greater", 1, IAM),
    ("1.9",  "Ensure IAM password policy prevents password reuse", 1, IAM),
    ("1.10", "Ensure MFA is enabled for all IAM users that have a console password", 1, IAM),
    ("1.11", "Do not setup access keys during initial user setup for all IAM users that have a console password", 1, IAM),
    ("1.12", "Ensure credentials unused for 45 days or greater are disabled", 1, IAM),
    ("1.13", "Ensure there is only one active access key available for any single IAM user", 1, IAM),
    ("1.14", "Ensure access keys are rotated every 90 days or less", 1, IAM),
    ("1.15", "Ensure IAM users receive permissions only through groups", 1, IAM),
    ("1.16", "Ensure IAM policies that allow full \"*:*\" administrative privileges are not attached", 1, IAM),
    ("1.17", "Ensure a support role has been created to manage incidents with AWS Support", 1, IAM),
    ("1.18", "Ensure IAM instance roles are used for AWS resource access from instances", 2, IAM),
    ("1.19", "Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed", 1, IAM),
    ("1.20", "Ensure that IAM Access Analyzer is enabled for all regions", 1, IAM),
    ("1.21", "Ensure IAM users are managed centrally via identity federation or AWS Organizations", 2, IAM),
    # ── 2 Storage ───────────────────────────────────────────────────────────
    ("2.1.1", "Ensure all S3 buckets employ encryption-at-rest", 2, STORAGE),
    ("2.1.2", "Ensure S3 bucket policy is set to deny HTTP requests", 2, STORAGE),
    ("2.1.3", "Ensure MFA Delete is enabled on S3 buckets", 1, STORAGE),
    ("2.1.4", "Ensure all data in Amazon S3 has been discovered, classified and secured when required", 2, STORAGE),
    ("2.1.5", "Ensure that S3 buckets are configured with 'Block public access (bucket settings)'", 1, STORAGE),
    ("2.2.1", "Ensure EBS volume encryption is enabled in all regions", 1, STORAGE),
    ("2.3.1", "Ensure that encryption is enabled for RDS instances", 1, STORAGE),
    ("2.3.2", "Ensure Auto Minor Version Upgrade feature is enabled for RDS instances", 1, STORAGE),
    ("2.3.3", "Ensure that public access is not given to RDS instances", 1, STORAGE),
    # ── 3 Logging ───────────────────────────────────────────────────────────
    ("3.1",  "Ensure CloudTrail is enabled in all regions", 1, LOGGING),
    ("3.2",  "Ensure CloudTrail log file validation is enabled", 2, LOGGING),
    ("3.3",  "Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible", 1, LOGGING),
    ("3.4",  "Ensure CloudTrail trails are integrated with CloudWatch Logs", 1, LOGGING),
    ("3.5",  "Ensure AWS Config is enabled in all regions", 2, LOGGING),
    ("3.6",  "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket", 1, LOGGING),
    ("3.7",  "Ensure CloudTrail logs are encrypted at rest using KMS CMKs", 2, LOGGING),
    ("3.8",  "Ensure rotation for customer-created symmetric CMKs is enabled", 2, LOGGING),
    ("3.9",  "Ensure VPC flow logging is enabled in all VPCs", 2, LOGGING),
    ("3.10", "Ensure that Object-level logging for write events is enabled for S3 buckets", 2, LOGGING),
    ("3.11", "Ensure that Object-level logging for read events is enabled for S3 buckets", 2, LOGGING),
    # ── 4 Monitoring (CloudWatch metric filters + alarms) ───────────────────
    ("4.1",  "Ensure a log metric filter and alarm exist for unauthorized API calls", 1, MONITORING),
    ("4.2",  "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA", 1, MONITORING),
    ("4.3",  "Ensure a log metric filter and alarm exist for usage of 'root' account", 1, MONITORING),
    ("4.4",  "Ensure a log metric filter and alarm exist for IAM policy changes", 1, MONITORING),
    ("4.5",  "Ensure a log metric filter and alarm exist for CloudTrail configuration changes", 1, MONITORING),
    ("4.6",  "Ensure a log metric filter and alarm exist for AWS Management Console authentication failures", 2, MONITORING),
    ("4.7",  "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer-created CMKs", 2, MONITORING),
    ("4.8",  "Ensure a log metric filter and alarm exist for S3 bucket policy changes", 1, MONITORING),
    ("4.9",  "Ensure a log metric filter and alarm exist for AWS Config configuration changes", 2, MONITORING),
    ("4.10", "Ensure a log metric filter and alarm exist for security group changes", 2, MONITORING),
    ("4.11", "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)", 2, MONITORING),
    ("4.12", "Ensure a log metric filter and alarm exist for changes to network gateways", 2, MONITORING),
    ("4.13", "Ensure a log metric filter and alarm exist for route table changes", 2, MONITORING),
    ("4.14", "Ensure a log metric filter and alarm exist for VPC changes", 2, MONITORING),
    ("4.15", "Ensure a log metric filter and alarm exist for AWS Organizations changes", 1, MONITORING),
    # ── 5 Networking ────────────────────────────────────────────────────────
    ("5.1",  "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports", 1, NETWORKING),
    ("5.2",  "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports", 1, NETWORKING),
    ("5.3",  "Ensure no security groups allow ingress from ::/0 to remote server administration ports", 1, NETWORKING),
    ("5.4",  "Ensure the default security group of every VPC restricts all traffic", 2, NETWORKING),
    ("5.5",  "Ensure routing tables for VPC peering are 'least access'", 2, NETWORKING),
    ("5.6",  "Ensure that EC2 Metadata Service only allows IMDSv2", 1, NETWORKING),
]


# Curated map of CIS control → the platform checks that evidence it. Only controls
# our checks can actually assess are listed; the rest stay Manual. Merged at
# score/SoA time (the same overlay mechanism the ISO 27001 catalog uses) so we
# don't have to thread CIS ids through every check class.
CHECK_MAP: dict[str, list[str]] = {
    "1.4":   ["iam_aws_004"],                          # no root access keys
    "1.5":   ["iam_aws_001"],                          # root MFA
    # 1.6 (root *hardware* MFA) stays Manual — our check verifies any root MFA,
    # not specifically a hardware token, so claiming it would be a false pass.
    "1.8":   ["iam_aws_002"],                          # password length
    "1.9":   ["iam_aws_002"],                          # password reuse
    "1.10":  ["iam_aws_005"],                          # MFA for all console users
    "1.14":  ["iam_aws_003"],                          # access key rotation
    "1.15":  ["iam_aws_006"],                          # permissions via groups (no inline)
    "1.16":  ["iam_aws_007"],                          # no full admin *:* policies
    "1.17":  ["iam_aws_008"],                          # support role
    "2.1.1": ["storage_aws_002"],                      # S3 encryption at rest
    "2.1.2": ["storage_aws_003"],                      # S3 deny HTTP (SSL only)
    "2.1.5": ["storage_aws_001"],                      # S3 block public access
    "2.2.1": ["compute_aws_002"],                      # EBS encryption
    "2.3.1": ["storage_aws_005"],                      # RDS encryption
    "2.3.3": ["network_aws_005"],                      # RDS not publicly accessible
    "3.1":   ["logging_aws_001"],                      # CloudTrail multi-region
    "3.2":   ["logging_aws_003"],                      # log file validation
    "3.5":   ["logging_aws_006"],                      # Config enabled
    "3.7":   ["logging_aws_002"],                      # CloudTrail KMS encryption
    "3.8":   ["encryption_aws_001"],                   # CMK rotation
    "3.9":   ["network_aws_002"],                      # VPC flow logs
    "4.3":   ["logging_aws_007"],                      # root-account-usage alarm
    "5.1":   ["network_aws_004"],                      # NACL admin-port ingress
    "5.2":   ["network_aws_001", "network_aws_003"],   # SG SSH/RDP from 0.0.0.0/0
    # 5.3 (ingress from ::/0, IPv6) stays Manual — our SG checks inspect 0.0.0.0/0
    # (IPv4) only, so claiming the IPv6 control would be a false pass.
    "5.6":   ["compute_aws_001"],                      # IMDSv2 required
}


def merge_check_map(ctrl_checks: dict[str, set]) -> None:
    """Merge CHECK_MAP into a {control_id: set(check_ids)} map, in place."""
    for ctrl, cids in CHECK_MAP.items():
        ctrl_checks.setdefault(ctrl, set()).update(cids)


def _build() -> dict[str, Any]:
    return {cid: {"title": title, "section": section, "level": level}
            for cid, title, level, section in _CONTROLS}


CIS_AWS_FOUNDATIONS: dict[str, Any] = _build()


def _demo() -> None:
    cat = CIS_AWS_FOUNDATIONS
    assert len(cat) == 62, len(cat)
    counts = {IAM: 21, STORAGE: 9, LOGGING: 11, MONITORING: 15, NETWORKING: 6}
    for sec, n in counts.items():
        got = sum(1 for m in cat.values() if m["section"] == sec)
        assert got == n, (sec, got, n)
    assert cat["1.5"]["title"].startswith("Ensure MFA is enabled for the 'root'")
    assert cat["5.6"]["section"] == NETWORKING
    # every mapped control is a real control in the catalog (no dangling ids)
    for ctrl in CHECK_MAP:
        assert ctrl in cat, ctrl
    print(f"cis_aws_catalog self-check passed: {len(cat)} controls, "
          f"{len(CHECK_MAP)} auto-assessed")


if __name__ == "__main__":
    _demo()
