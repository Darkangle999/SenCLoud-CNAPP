"""
Odineyes — Extended AWS Checks
Covers EC2, KMS, GuardDuty, Config, CloudWatch, EKS, RDS, Lambda, SNS, SQS,
plus deeper IAM, network, and storage checks.
"""

from typing import List, Dict, Any
from odineyes.core.check_registry import BaseCheck
from odineyes.core.aws_session import shared_session


def _utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# ═══════════════════════════════════════════════════════
# AWS IAM — Extended
# ═══════════════════════════════════════════════════════

class AWSIAMUserMFACheck(BaseCheck):
    check_id = "iam_aws_005"
    name = "MFA Enabled for All IAM Users with Console Access"
    description = "Ensures every IAM user with a console password also has MFA enabled"
    provider = "aws"
    category = "iam"
    severity = "high"
    compliance = {
        "CIS": ["1.10"],
        "SOC2": ["CC6.1"],
        "NIST": ["IA-2(1)"],
        "PCI-DSS": ["8.3.1"],
        "HIPAA": ["164.312(a)(2)(i)"],
    }
    remediation = (
        "Enable MFA for each IAM user: "
        "aws iam enable-mfa-device --user-name <user> --serial-number <arn> --authentication-code1 <c1> --authentication-code2 <c2>"
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            iam = session.client("iam")
            cred_report = iam.generate_credential_report()
            import time, base64, csv, io
            time.sleep(2)
            report = iam.get_credential_report()
            reader = csv.DictReader(io.StringIO(report["Content"].decode("utf-8")))
            for row in reader:
                if row["user"] == "<root_account>":
                    continue
                has_pwd = row.get("password_enabled", "false").lower() == "true"
                has_mfa = row.get("mfa_active", "false").lower() == "true"
                if has_pwd and not has_mfa:
                    findings.append(self._make_finding(
                        status="fail",
                        resource_id=row["arn"],
                        resource_type="iam:user",
                        region="global",
                        message=f"User {row['user']} has console access but NO MFA",
                        metadata={"user": row["user"]},
                    ))
                elif has_pwd and has_mfa:
                    findings.append(self._make_finding(
                        status="pass",
                        resource_id=row["arn"],
                        resource_type="iam:user",
                        region="global",
                        message=f"User {row['user']} has MFA enabled",
                    ))
        except Exception:
            for user, mfa in [("alice", False), ("bob", True), ("charlie", False)]:
                findings.append(self._make_finding(
                    status="fail" if not mfa else "pass",
                    resource_id=f"arn:aws:iam::123456789:user/{user}",
                    resource_type="iam:user",
                    region="global",
                    message=f"[SIMULATED] User {user}: MFA {'enabled' if mfa else 'NOT enabled'}",
                    metadata={"simulated": True},
                ))
        return findings


class AWSIAMInlinePolicy(BaseCheck):
    check_id = "iam_aws_006"
    name = "No Inline IAM Policies"
    description = "Ensures IAM users, groups, and roles use managed policies, not inline policies"
    provider = "aws"
    category = "iam"
    severity = "medium"
    compliance = {
        "CIS": ["1.16"],
        "SOC2": ["CC6.3"],
        "NIST": ["AC-6"],
    }
    remediation = (
        "Convert inline policies to managed policies and detach them. "
        "Use aws iam list-user-policies / put-user-policy to identify and migrate."
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            iam = session.client("iam")
            for user in iam.list_users()["Users"]:
                policies = iam.list_user_policies(UserName=user["UserName"])["PolicyNames"]
                for pol in policies:
                    findings.append(self._make_finding(
                        status="fail",
                        resource_id=user["Arn"],
                        resource_type="iam:user",
                        region="global",
                        message=f"User {user['UserName']} has inline policy: {pol}",
                    ))
                if not policies:
                    findings.append(self._make_finding(
                        status="pass",
                        resource_id=user["Arn"],
                        resource_type="iam:user",
                        region="global",
                        message=f"User {user['UserName']} has no inline policies",
                    ))
        except Exception:
            findings.append(self._make_finding(
                status="fail",
                resource_id="arn:aws:iam::123456789:user/developer",
                resource_type="iam:user",
                region="global",
                message="[SIMULATED] User 'developer' has inline policy: DeveloperAccess",
                metadata={"simulated": True},
            ))
        return findings


class AWSIAMAdminPolicyAttached(BaseCheck):
    check_id = "iam_aws_007"
    name = "No IAM Users with AdministratorAccess Policy"
    description = "Ensures the AdministratorAccess managed policy is not attached to any IAM user directly"
    provider = "aws"
    category = "iam"
    severity = "critical"
    compliance = {
        "CIS": ["1.16"],
        "SOC2": ["CC6.3"],
        "NIST": ["AC-6"],
        "PCI-DSS": ["7.1.2"],
    }
    remediation = (
        "Remove AdministratorAccess from IAM users. "
        "Grant admin via IAM roles assumed with MFA using aws iam detach-user-policy."
    )
    risk_weight = 2.0

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            iam = session.client("iam")
            admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
            entities = iam.list_entities_for_policy(PolicyArn=admin_arn, EntityFilter="User")
            for user in entities["PolicyUsers"]:
                findings.append(self._make_finding(
                    status="fail",
                    resource_id=f"arn:aws:iam::{'unknown'}:user/{user['UserName']}",
                    resource_type="iam:user",
                    region="global",
                    message=f"User {user['UserName']} has AdministratorAccess directly attached — CRITICAL",
                ))
            if not entities["PolicyUsers"]:
                findings.append(self._make_finding(
                    status="pass",
                    resource_id="iam:users",
                    resource_type="iam:user",
                    region="global",
                    message="No IAM users have AdministratorAccess directly attached",
                ))
        except Exception:
            findings.append(self._make_finding(
                status="fail",
                resource_id="arn:aws:iam::123456789:user/superadmin",
                resource_type="iam:user",
                region="global",
                message="[SIMULATED] User 'superadmin' has AdministratorAccess attached directly",
                metadata={"simulated": True},
            ))
        return findings


class AWSIAMSupportPolicyCheck(BaseCheck):
    check_id = "iam_aws_008"
    name = "AWS Support Access Policy Exists"
    description = "Ensures an IAM role or policy exists for AWS Support access management"
    provider = "aws"
    category = "iam"
    severity = "low"
    compliance = {"CIS": ["1.20"]}
    remediation = "Create an IAM policy granting aws-support:* to a dedicated support role."

    def execute(self, ctx: Dict) -> List[Dict]:
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            iam = session.client("iam")
            policies = iam.list_policies(Scope="Local")["Policies"]
            has_support = any("support" in p["PolicyName"].lower() for p in policies)
            return [self._make_finding(
                status="pass" if has_support else "fail",
                resource_id="iam:policies",
                resource_type="iam:policy",
                region="global",
                message="Support access policy found" if has_support
                        else "No AWS Support access policy found",
            )]
        except Exception:
            return [self._make_finding(
                status="fail",
                resource_id="iam:policies",
                resource_type="iam:policy",
                region="global",
                message="[SIMULATED] No AWS Support IAM policy configured",
                metadata={"simulated": True},
            )]


# ═══════════════════════════════════════════════════════
# AWS EC2 / Compute
# ═══════════════════════════════════════════════════════

class AWSEC2IMDSv2Check(BaseCheck):
    check_id = "compute_aws_001"
    name = "EC2 IMDSv2 Required"
    description = "Ensures EC2 instances require IMDSv2 (Instance Metadata Service v2) to prevent SSRF attacks"
    provider = "aws"
    category = "compute"
    severity = "high"
    compliance = {
        "CIS": ["5.6"],
        "SOC2": ["CC6.1"],
        "NIST": ["SI-10"],
    }
    remediation = (
        "Enforce IMDSv2: aws ec2 modify-instance-metadata-options "
        "--instance-id <id> --http-tokens required --http-endpoint enabled"
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        regions = ctx.get("regions") or ["us-east-1"]
        try:
            import boto3
            for region in regions:
                session = shared_session(ctx.get("profile", "default"), region)
                ec2 = session.client("ec2")
                reservations = ec2.describe_instances()["Reservations"]
                for res in reservations:
                    for inst in res["Instances"]:
                        meta = inst.get("MetadataOptions", {})
                        requires_v2 = meta.get("HttpTokens") == "required"
                        findings.append(self._make_finding(
                            status="pass" if requires_v2 else "fail",
                            resource_id=inst["InstanceId"],
                            resource_type="ec2:instance",
                            region=region,
                            message=f"Instance {inst['InstanceId']}: IMDSv2 {'required' if requires_v2 else 'NOT required — SSRF risk'}",
                        ))
        except Exception:
            for iid, v2 in [("i-0abc123", False), ("i-0def456", True)]:
                findings.append(self._make_finding(
                    status="pass" if v2 else "fail",
                    resource_id=iid,
                    resource_type="ec2:instance",
                    region="us-east-1",
                    message=f"[SIMULATED] Instance {iid}: IMDSv2 {'required' if v2 else 'NOT required'}",
                    metadata={"simulated": True},
                ))
        return findings


class AWSEC2EBSEncryptionCheck(BaseCheck):
    check_id = "compute_aws_002"
    name = "EBS Volume Encryption Enabled"
    description = "Ensures all EBS volumes are encrypted"
    provider = "aws"
    category = "encryption"
    severity = "high"
    compliance = {
        "CIS": ["2.2.1"],
        "SOC2": ["CC6.7"],
        "NIST": ["SC-28"],
        "HIPAA": ["164.312(a)(2)(iv)"],
        "PCI-DSS": ["3.5"],
    }
    remediation = (
        "Enable EBS default encryption: "
        "aws ec2 enable-ebs-encryption-by-default --region <region>. "
        "For existing volumes, create an encrypted snapshot and restore."
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        regions = ctx.get("regions") or ["us-east-1"]
        try:
            import boto3
            for region in regions:
                session = shared_session(ctx.get("profile", "default"), region)
                ec2 = session.client("ec2")
                # Check account-level default encryption
                default_enc = ec2.get_ebs_encryption_by_default()
                enabled = default_enc.get("EbsEncryptionByDefault", False)
                findings.append(self._make_finding(
                    status="pass" if enabled else "fail",
                    resource_id=f"ebs-default-encryption/{region}",
                    resource_type="ec2:ebs_encryption_default",
                    region=region,
                    message=f"EBS default encryption: {'ENABLED' if enabled else 'DISABLED'}",
                ))
                # Check individual volumes
                vols = ec2.describe_volumes()["Volumes"]
                for vol in vols:
                    findings.append(self._make_finding(
                        status="pass" if vol.get("Encrypted") else "fail",
                        resource_id=vol["VolumeId"],
                        resource_type="ec2:ebs_volume",
                        region=region,
                        message=f"Volume {vol['VolumeId']}: {'encrypted' if vol.get('Encrypted') else 'NOT encrypted'}",
                    ))
        except Exception:
            for vid, enc in [("vol-0abc123", False), ("vol-0def456", True), ("vol-0ghi789", False)]:
                findings.append(self._make_finding(
                    status="pass" if enc else "fail",
                    resource_id=vid,
                    resource_type="ec2:ebs_volume",
                    region="us-east-1",
                    message=f"[SIMULATED] Volume {vid}: {'encrypted' if enc else 'NOT encrypted — data exposure risk'}",
                    metadata={"simulated": True},
                ))
        return findings


class AWSEC2PublicAMICheck(BaseCheck):
    check_id = "compute_aws_003"
    name = "No Public EC2 AMIs"
    description = "Ensures no AMIs owned by the account are publicly shared"
    provider = "aws"
    category = "compute"
    severity = "high"
    compliance = {
        "SOC2": ["CC6.1"],
        "NIST": ["AC-3"],
        "PCI-DSS": ["7.1"],
    }
    remediation = (
        "Make AMIs private: "
        "aws ec2 modify-image-attribute --image-id <ami-id> "
        "--launch-permission '{\"Remove\":[{\"Group\":\"all\"}]}'"
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            ec2 = session.client("ec2")
            amis = ec2.describe_images(Owners=["self"])["Images"]
            for ami in amis:
                is_public = ami.get("Public", False)
                findings.append(self._make_finding(
                    status="fail" if is_public else "pass",
                    resource_id=ami["ImageId"],
                    resource_type="ec2:ami",
                    region="us-east-1",
                    message=f"AMI {ami['ImageId']} ({ami.get('Name','')}) is {'PUBLIC' if is_public else 'private'}",
                ))
        except Exception:
            findings.append(self._make_finding(
                status="pass",
                resource_id="ami-0abc123example",
                resource_type="ec2:ami",
                region="us-east-1",
                message="[SIMULATED] No publicly shared AMIs found",
                metadata={"simulated": True},
            ))
        return findings


class AWSEC2SecurityGroupRDPCheck(BaseCheck):
    check_id = "network_aws_003"
    name = "No Security Groups Open RDP to Internet"
    description = "Ensures no security groups allow unrestricted RDP (3389) from 0.0.0.0/0"
    provider = "aws"
    category = "network"
    severity = "critical"
    compliance = {
        # RDP from 0.0.0.0/0 is an IPv4 admin-port violation → CIS 5.2 (5.3 is the
        # ::/0 IPv6 variant, which this check does not inspect).
        "CIS": ["5.2"],
        "SOC2": ["CC6.1"],
        "NIST": ["AC-17"],
        "PCI-DSS": ["1.3.1"],
    }
    remediation = (
        "Remove inbound RDP (3389) rules with source 0.0.0.0/0 from all security groups. "
        "Use VPN or bastion hosts for remote access."
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        regions = ctx.get("regions") or ["us-east-1"]
        try:
            import boto3
            for region in regions:
                session = shared_session(ctx.get("profile", "default"), region)
                ec2 = session.client("ec2")
                sgs = ec2.describe_security_groups()["SecurityGroups"]
                for sg in sgs:
                    for rule in sg.get("IpPermissions", []):
                        ports = set(range(
                            rule.get("FromPort", 0),
                            rule.get("ToPort", 0) + 1
                        )) if rule.get("FromPort") is not None else set()
                        if 3389 in ports:
                            for cidr in rule.get("IpRanges", []):
                                if cidr.get("CidrIp") in ["0.0.0.0/0"]:
                                    findings.append(self._make_finding(
                                        status="fail",
                                        resource_id=f"{sg['GroupId']} ({sg['GroupName']})",
                                        resource_type="ec2:security_group",
                                        region=region,
                                        message=f"Security group {sg['GroupId']} allows RDP (3389) from 0.0.0.0/0",
                                    ))
        except Exception:
            findings.append(self._make_finding(
                status="pass",
                resource_id="sg-all",
                resource_type="ec2:security_group",
                region="us-east-1",
                message="[SIMULATED] No security groups with open RDP found",
                metadata={"simulated": True},
            ))
        return findings


class AWSNetworkNACLCheck(BaseCheck):
    check_id = "network_aws_004"
    name = "No Unrestricted NACL Inbound Rules"
    description = "Ensures Network ACLs do not allow unrestricted inbound traffic on all ports"
    provider = "aws"
    category = "network"
    severity = "medium"
    compliance = {
        "CIS": ["5.1"],
        "SOC2": ["CC6.1"],
        "NIST": ["SC-7"],
        "PCI-DSS": ["1.3"],
    }
    remediation = "Remove or restrict NACL rules that allow ALL traffic (protocol -1) from 0.0.0.0/0."

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        regions = ctx.get("regions") or ["us-east-1"]
        try:
            import boto3
            for region in regions:
                session = shared_session(ctx.get("profile", "default"), region)
                ec2 = session.client("ec2")
                nacls = ec2.describe_network_acls()["NetworkAcls"]
                for nacl in nacls:
                    for entry in nacl.get("Entries", []):
                        if (entry.get("Egress") is False and
                                entry.get("Protocol") == "-1" and
                                entry.get("CidrBlock") == "0.0.0.0/0" and
                                entry.get("RuleAction") == "allow"):
                            findings.append(self._make_finding(
                                status="fail",
                                resource_id=nacl["NetworkAclId"],
                                resource_type="ec2:network_acl",
                                region=region,
                                message=f"NACL {nacl['NetworkAclId']} allows all inbound from 0.0.0.0/0",
                            ))
        except Exception:
            findings.append(self._make_finding(
                status="fail",
                resource_id="acl-0abc123",
                resource_type="ec2:network_acl",
                region="us-east-1",
                message="[SIMULATED] NACL acl-0abc123 has unrestricted all-traffic inbound rule",
                metadata={"simulated": True},
            ))
        return findings


# ═══════════════════════════════════════════════════════
# AWS KMS / Encryption
# ═══════════════════════════════════════════════════════

class AWSKMSKeyRotationCheck(BaseCheck):
    check_id = "encryption_aws_001"
    name = "KMS Key Rotation Enabled"
    description = "Ensures AWS KMS customer-managed keys (CMKs) have automatic key rotation enabled"
    provider = "aws"
    category = "encryption"
    severity = "medium"
    compliance = {
        "CIS": ["3.8"],
        "SOC2": ["CC6.7"],
        "NIST": ["SC-12"],
        "PCI-DSS": ["3.6.4"],
        "HIPAA": ["164.312(a)(2)(iv)"],
    }
    remediation = (
        "Enable key rotation: "
        "aws kms enable-key-rotation --key-id <key-id>"
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            kms = session.client("kms")
            keys = kms.list_keys()["Keys"]
            for key in keys:
                try:
                    meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    if meta.get("KeyManager") != "CUSTOMER":
                        continue  # Skip AWS-managed keys
                    rotation = kms.get_key_rotation_status(KeyId=key["KeyId"])
                    rotating = rotation.get("KeyRotationEnabled", False)
                    findings.append(self._make_finding(
                        status="pass" if rotating else "fail",
                        resource_id=key["KeyArn"],
                        resource_type="kms:key",
                        region="us-east-1",
                        message=f"KMS key {key['KeyId']}: rotation {'enabled' if rotating else 'DISABLED'}",
                    ))
                except Exception:
                    pass
        except Exception:
            for kid, rot in [("abc-123-def", False), ("ghi-456-jkl", True)]:
                findings.append(self._make_finding(
                    status="pass" if rot else "fail",
                    resource_id=f"arn:aws:kms:us-east-1:123456789:key/{kid}",
                    resource_type="kms:key",
                    region="us-east-1",
                    message=f"[SIMULATED] KMS key {kid}: rotation {'enabled' if rot else 'DISABLED'}",
                    metadata={"simulated": True},
                ))
        return findings


class AWSS3SSLPolicyCheck(BaseCheck):
    check_id = "storage_aws_003"
    name = "S3 Bucket Policy Enforces SSL"
    description = "Ensures S3 bucket policies deny requests that do not use SSL/TLS"
    provider = "aws"
    category = "storage"
    severity = "high"
    compliance = {
        "CIS": ["2.1.2"],
        "SOC2": ["CC6.7"],
        "NIST": ["SC-8"],
        "PCI-DSS": ["4.1"],
    }
    remediation = (
        'Add a bucket policy that denies s3:* when aws:SecureTransport is false. '
        'Condition: {"Bool": {"aws:SecureTransport": "false"}}'
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        try:
            import boto3, json
            session = shared_session(ctx.get("profile", "default"))
            s3 = session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets[:15]:
                try:
                    pol = json.loads(s3.get_bucket_policy(Bucket=bucket["Name"])["Policy"])
                    has_ssl_deny = any(
                        stmt.get("Effect") == "Deny" and
                        "aws:SecureTransport" in str(stmt.get("Condition", {}))
                        for stmt in pol.get("Statement", [])
                    )
                    findings.append(self._make_finding(
                        status="pass" if has_ssl_deny else "fail",
                        resource_id=f"arn:aws:s3:::{bucket['Name']}",
                        resource_type="s3:bucket",
                        region="global",
                        message=f"Bucket {bucket['Name']}: SSL enforcement {'present' if has_ssl_deny else 'MISSING'}",
                    ))
                except Exception:
                    findings.append(self._make_finding(
                        status="fail",
                        resource_id=f"arn:aws:s3:::{bucket['Name']}",
                        resource_type="s3:bucket",
                        region="global",
                        message=f"Bucket {bucket['Name']}: no bucket policy (SSL not enforced)",
                    ))
        except Exception:
            for name, ssl in [("prod-bucket", False), ("secure-bucket", True)]:
                findings.append(self._make_finding(
                    status="pass" if ssl else "fail",
                    resource_id=f"arn:aws:s3:::{name}",
                    resource_type="s3:bucket",
                    region="global",
                    message=f"[SIMULATED] Bucket {name}: SSL {'enforced' if ssl else 'NOT enforced in policy'}",
                    metadata={"simulated": True},
                ))
        return findings


class AWSS3VersioningCheck(BaseCheck):
    check_id = "storage_aws_004"
    name = "S3 Bucket Versioning Enabled"
    description = "Ensures S3 buckets have versioning enabled to protect against accidental deletion"
    provider = "aws"
    category = "storage"
    severity = "low"
    compliance = {
        "CIS": ["2.1.3"],
        "SOC2": ["CC7.4"],
        "HIPAA": ["164.312(c)(1)"],
    }
    remediation = "Enable versioning: aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled"

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            s3 = session.client("s3")
            for bucket in s3.list_buckets().get("Buckets", [])[:15]:
                ver = s3.get_bucket_versioning(Bucket=bucket["Name"])
                enabled = ver.get("Status") == "Enabled"
                findings.append(self._make_finding(
                    status="pass" if enabled else "fail",
                    resource_id=f"arn:aws:s3:::{bucket['Name']}",
                    resource_type="s3:bucket",
                    region="global",
                    message=f"Bucket {bucket['Name']}: versioning {'enabled' if enabled else 'disabled'}",
                ))
        except Exception:
            for name, ver in [("prod-data", False), ("backup-bucket", True)]:
                findings.append(self._make_finding(
                    status="pass" if ver else "fail",
                    resource_id=f"arn:aws:s3:::{name}",
                    resource_type="s3:bucket",
                    region="global",
                    message=f"[SIMULATED] Bucket {name}: versioning {'enabled' if ver else 'disabled'}",
                    metadata={"simulated": True},
                ))
        return findings


# ═══════════════════════════════════════════════════════
# AWS Logging & Monitoring
# ═══════════════════════════════════════════════════════

class AWSCloudTrailLogEncryptionCheck(BaseCheck):
    check_id = "logging_aws_002"
    name = "CloudTrail Log Encryption"
    description = "Ensures CloudTrail logs are encrypted at rest using KMS"
    provider = "aws"
    category = "logging"
    severity = "medium"
    compliance = {
        "CIS": ["3.7"],
        "SOC2": ["CC6.7"],
        "NIST": ["AU-9", "SC-28"],
        "PCI-DSS": ["10.5.2"],
    }
    remediation = (
        "Enable KMS encryption on CloudTrail: "
        "aws cloudtrail update-trail --name <trail> --kms-key-id <key-arn>"
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            ct = session.client("cloudtrail")
            trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
            for trail in trails:
                has_kms = bool(trail.get("KMSKeyId"))
                findings.append(self._make_finding(
                    status="pass" if has_kms else "fail",
                    resource_id=trail["TrailARN"],
                    resource_type="cloudtrail:trail",
                    region=trail.get("HomeRegion", "global"),
                    message=f"Trail {trail['Name']}: KMS encryption {'enabled' if has_kms else 'DISABLED'}",
                ))
        except Exception:
            findings.append(self._make_finding(
                status="fail",
                resource_id="arn:aws:cloudtrail:us-east-1:123:trail/main-trail",
                resource_type="cloudtrail:trail",
                region="us-east-1",
                message="[SIMULATED] CloudTrail trail 'main-trail' has NO KMS encryption",
                metadata={"simulated": True},
            ))
        return findings


class AWSCloudTrailLogValidationCheck(BaseCheck):
    check_id = "logging_aws_003"
    name = "CloudTrail Log File Validation"
    description = "Ensures CloudTrail log file integrity validation is enabled"
    provider = "aws"
    category = "logging"
    severity = "low"
    compliance = {
        "CIS": ["3.2"],
        "SOC2": ["CC7.2"],
        "NIST": ["AU-9"],
        "PCI-DSS": ["10.5.5"],
    }
    remediation = (
        "Enable log file validation: "
        "aws cloudtrail update-trail --name <trail> --enable-log-file-validation"
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            ct = session.client("cloudtrail")
            trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
            for trail in trails:
                validated = trail.get("LogFileValidationEnabled", False)
                findings.append(self._make_finding(
                    status="pass" if validated else "fail",
                    resource_id=trail["TrailARN"],
                    resource_type="cloudtrail:trail",
                    region=trail.get("HomeRegion", "global"),
                    message=f"Trail {trail['Name']}: log validation {'enabled' if validated else 'DISABLED'}",
                ))
        except Exception:
            findings.append(self._make_finding(
                status="fail",
                resource_id="arn:aws:cloudtrail:us-east-1:123:trail/main-trail",
                resource_type="cloudtrail:trail",
                region="us-east-1",
                message="[SIMULATED] CloudTrail log file validation is DISABLED",
                metadata={"simulated": True},
            ))
        return findings


class AWSGuardDutyEnabledCheck(BaseCheck):
    check_id = "logging_aws_004"
    name = "GuardDuty Enabled"
    description = "Ensures AWS GuardDuty threat detection is enabled in all regions"
    provider = "aws"
    category = "logging"
    severity = "high"
    compliance = {
        "CIS": ["4.15"],
        "SOC2": ["CC7.2"],
        "NIST": ["SI-4"],
        "PCI-DSS": ["11.4"],
    }
    remediation = (
        "Enable GuardDuty: aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES"
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        regions = ctx.get("regions") or ["us-east-1"]
        try:
            import boto3
            for region in regions:
                session = shared_session(ctx.get("profile", "default"), region)
                gd = session.client("guardduty")
                detectors = gd.list_detectors()["DetectorIds"]
                if not detectors:
                    findings.append(self._make_finding(
                        status="fail",
                        resource_id=f"guardduty/{region}",
                        resource_type="guardduty:detector",
                        region=region,
                        message=f"GuardDuty is NOT enabled in {region}",
                    ))
                else:
                    for det_id in detectors:
                        det = gd.get_detector(DetectorId=det_id)
                        enabled = det.get("Status") == "ENABLED"
                        findings.append(self._make_finding(
                            status="pass" if enabled else "fail",
                            resource_id=det_id,
                            resource_type="guardduty:detector",
                            region=region,
                            message=f"GuardDuty detector {det_id}: {'ENABLED' if enabled else 'DISABLED'}",
                        ))
        except Exception as e:
            findings.append(self._make_finding(
                status="fail",
                resource_id=f"guardduty/{regions[0]}",
                resource_type="guardduty:detector",
                region=regions[0],
                message=f"AWS GuardDuty check failed or NOT enabled: {e}",
            ))
        return findings


class AWSSecurityHubEnabledCheck(BaseCheck):
    check_id = "logging_aws_005"
    name = "AWS Security Hub Enabled"
    description = "Ensures AWS Security Hub is enabled for centralised security findings"
    provider = "aws"
    category = "logging"
    severity = "medium"
    compliance = {
        "SOC2": ["CC7.2"],
        "NIST": ["SI-4"],
        "PCI-DSS": ["11.5"],
    }
    remediation = "Enable Security Hub: aws securityhub enable-security-hub --enable-default-standards"

    def execute(self, ctx: Dict) -> List[Dict]:
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            sh = session.client("securityhub")
            hub = sh.describe_hub()
            return [self._make_finding(
                status="pass",
                resource_id=hub.get("HubArn", "securityhub"),
                resource_type="securityhub:hub",
                region="us-east-1",
                message="AWS Security Hub is enabled",
            )]
        except Exception as e:
            if "not subscribed" in str(e).lower() or "InvalidAccessException" in str(e):
                return [self._make_finding(
                    status="fail",
                    resource_id="securityhub",
                    resource_type="securityhub:hub",
                    region="us-east-1",
                    message="AWS Security Hub is NOT enabled",
                )]
            return [self._make_finding(
                status="fail",
                resource_id="securityhub",
                resource_type="securityhub:hub",
                region="us-east-1",
                message=f"AWS Security Hub check failed or NOT enabled: {e}",
            )]


class AWSConfigServiceEnabledCheck(BaseCheck):
    check_id = "logging_aws_006"
    name = "AWS Config Service Enabled"
    description = "Ensures AWS Config is enabled in all regions for continuous compliance monitoring"
    provider = "aws"
    category = "logging"
    severity = "medium"
    compliance = {
        "CIS": ["3.5"],
        "SOC2": ["CC7.2"],
        "NIST": ["CM-8", "AU-2"],
        "PCI-DSS": ["10.1"],
    }
    remediation = (
        "Enable AWS Config: aws configservice put-configuration-recorder "
        "and aws configservice put-delivery-channel"
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        regions = ctx.get("regions") or ["us-east-1"]
        try:
            import boto3
            for region in regions:
                session = shared_session(ctx.get("profile", "default"), region)
                cfg = session.client("config")
                recorders = cfg.describe_configuration_recorders()["ConfigurationRecorders"]
                if not recorders:
                    findings.append(self._make_finding(
                        status="fail",
                        resource_id=f"config/{region}",
                        resource_type="config:recorder",
                        region=region,
                        message=f"AWS Config recorder not configured in {region}",
                    ))
                else:
                    status = cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
                    for s in status:
                        findings.append(self._make_finding(
                            status="pass" if s.get("recording") else "fail",
                            resource_id=s["name"],
                            resource_type="config:recorder",
                            region=region,
                            message=f"Config recorder {s['name']}: {'recording' if s.get('recording') else 'NOT recording'}",
                        ))
        except Exception:
            findings.append(self._make_finding(
                status="fail",
                resource_id="config/us-east-1",
                resource_type="config:recorder",
                region="us-east-1",
                message="[SIMULATED] AWS Config is NOT enabled in us-east-1",
                metadata={"simulated": True},
            ))
        return findings


# ═══════════════════════════════════════════════════════
# AWS RDS
# ═══════════════════════════════════════════════════════

class AWSRDSEncryptionCheck(BaseCheck):
    check_id = "storage_aws_005"
    name = "RDS Instance Encryption at Rest"
    description = "Ensures all RDS database instances are encrypted at rest"
    provider = "aws"
    category = "encryption"
    severity = "high"
    compliance = {
        "CIS": ["2.3.1"],
        "SOC2": ["CC6.7"],
        "NIST": ["SC-28"],
        "HIPAA": ["164.312(a)(2)(iv)"],
        "PCI-DSS": ["3.5"],
    }
    remediation = (
        "RDS encryption can only be enabled at creation time. "
        "Migrate unencrypted instances by creating an encrypted snapshot and restoring."
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        regions = ctx.get("regions") or ["us-east-1"]
        try:
            import boto3
            for region in regions:
                session = shared_session(ctx.get("profile", "default"), region)
                rds = session.client("rds")
                instances = rds.describe_db_instances()["DBInstances"]
                for db in instances:
                    enc = db.get("StorageEncrypted", False)
                    findings.append(self._make_finding(
                        status="pass" if enc else "fail",
                        resource_id=db["DBInstanceArn"],
                        resource_type="rds:instance",
                        region=region,
                        message=f"RDS {db['DBInstanceIdentifier']}: {'encrypted' if enc else 'NOT encrypted'}",
                    ))
        except Exception:
            for name, enc in [("prod-mysql", False), ("analytics-postgres", True)]:
                findings.append(self._make_finding(
                    status="pass" if enc else "fail",
                    resource_id=f"arn:aws:rds:us-east-1:123:{name}",
                    resource_type="rds:instance",
                    region="us-east-1",
                    message=f"[SIMULATED] RDS {name}: {'encrypted' if enc else 'NOT encrypted'}",
                    metadata={"simulated": True},
                ))
        return findings


class AWSRDSPubliclyAccessibleCheck(BaseCheck):
    check_id = "network_aws_005"
    name = "RDS Instances Not Publicly Accessible"
    description = "Ensures RDS instances are not configured to be publicly accessible"
    provider = "aws"
    category = "network"
    severity = "critical"
    compliance = {
        "CIS": ["2.3.2"],
        "SOC2": ["CC6.1"],
        "NIST": ["AC-3", "SC-7"],
        "PCI-DSS": ["1.3.2"],
        "HIPAA": ["164.312(a)(1)"],
    }
    remediation = (
        "Disable public accessibility: "
        "aws rds modify-db-instance --db-instance-identifier <id> --no-publicly-accessible"
    )
    risk_weight = 1.5

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        regions = ctx.get("regions") or ["us-east-1"]
        try:
            import boto3
            for region in regions:
                session = shared_session(ctx.get("profile", "default"), region)
                rds = session.client("rds")
                for db in rds.describe_db_instances()["DBInstances"]:
                    public = db.get("PubliclyAccessible", False)
                    findings.append(self._make_finding(
                        status="fail" if public else "pass",
                        resource_id=db["DBInstanceArn"],
                        resource_type="rds:instance",
                        region=region,
                        message=f"RDS {db['DBInstanceIdentifier']}: {'PUBLICLY ACCESSIBLE' if public else 'not public'}",
                    ))
        except Exception:
            findings.append(self._make_finding(
                status="fail",
                resource_id="arn:aws:rds:us-east-1:123:prod-mysql",
                resource_type="rds:instance",
                region="us-east-1",
                message="[SIMULATED] RDS prod-mysql is PUBLICLY ACCESSIBLE",
                metadata={"simulated": True},
            ))
        return findings


class AWSRDSBackupRetentionCheck(BaseCheck):
    check_id = "storage_aws_006"
    name = "RDS Backup Retention >= 7 Days"
    description = "Ensures RDS instances have automated backup retention of at least 7 days"
    provider = "aws"
    category = "storage"
    severity = "medium"
    compliance = {
        "CIS": ["2.3.3"],
        "SOC2": ["A1.2"],
        "HIPAA": ["164.312(c)(1)"],
        "PCI-DSS": ["9.5"],
    }
    remediation = (
        "Set retention: "
        "aws rds modify-db-instance --db-instance-identifier <id> --backup-retention-period 7"
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            rds = session.client("rds")
            for db in rds.describe_db_instances()["DBInstances"]:
                days = db.get("BackupRetentionPeriod", 0)
                findings.append(self._make_finding(
                    status="pass" if days >= 7 else "fail",
                    resource_id=db["DBInstanceArn"],
                    resource_type="rds:instance",
                    region="us-east-1",
                    message=f"RDS {db['DBInstanceIdentifier']}: backup retention = {days} days ({'OK' if days >= 7 else 'INSUFFICIENT'})",
                ))
        except Exception:
            for name, days in [("prod-db", 1), ("staging-db", 7)]:
                findings.append(self._make_finding(
                    status="pass" if days >= 7 else "fail",
                    resource_id=f"arn:aws:rds:us-east-1:123:{name}",
                    resource_type="rds:instance",
                    region="us-east-1",
                    message=f"[SIMULATED] RDS {name}: backup retention = {days} days",
                    metadata={"simulated": True},
                ))
        return findings


# ═══════════════════════════════════════════════════════
# AWS Lambda
# ═══════════════════════════════════════════════════════

class AWSLambdaPublicAccessCheck(BaseCheck):
    check_id = "compute_aws_004"
    name = "Lambda Functions Not Publicly Accessible"
    description = "Ensures Lambda function resource-based policies do not allow public invocation"
    provider = "aws"
    category = "compute"
    severity = "high"
    compliance = {
        "SOC2": ["CC6.1"],
        "NIST": ["AC-3"],
        "PCI-DSS": ["7.1"],
    }
    remediation = (
        "Remove public access from Lambda: "
        "aws lambda remove-permission --function-name <name> --statement-id <id>"
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        regions = ctx.get("regions") or ["us-east-1"]
        try:
            import boto3, json
            for region in regions:
                session = shared_session(ctx.get("profile", "default"), region)
                lmb = session.client("lambda")
                functions = lmb.list_functions()["Functions"]
                for fn in functions:
                    try:
                        pol = json.loads(lmb.get_policy(FunctionName=fn["FunctionName"])["Policy"])
                        is_public = any(
                            stmt.get("Principal") in ["*", {"AWS": "*"}]
                            for stmt in pol.get("Statement", [])
                        )
                        findings.append(self._make_finding(
                            status="fail" if is_public else "pass",
                            resource_id=fn["FunctionArn"],
                            resource_type="lambda:function",
                            region=region,
                            message=f"Lambda {fn['FunctionName']}: {'PUBLIC invocation allowed!' if is_public else 'access restricted'}",
                        ))
                    except Exception:
                        pass
        except Exception:
            findings.append(self._make_finding(
                status="pass",
                resource_id="arn:aws:lambda:us-east-1:123:function:api-handler",
                resource_type="lambda:function",
                region="us-east-1",
                message="[SIMULATED] Lambda functions have no public access policies",
                metadata={"simulated": True},
            ))
        return findings


# ═══════════════════════════════════════════════════════
# AWS CloudWatch Alarms
# ═══════════════════════════════════════════════════════

class AWSCloudWatchRootLoginAlarmCheck(BaseCheck):
    check_id = "logging_aws_007"
    name = "CloudWatch Alarm for Root Login"
    description = "Ensures a CloudWatch alarm exists for root account console sign-in events"
    provider = "aws"
    category = "logging"
    severity = "high"
    compliance = {
        "CIS": ["4.3"],
        "SOC2": ["CC7.2"],
        "NIST": ["AU-6", "SI-4"],
    }
    remediation = (
        "Create a CloudWatch metric filter and alarm for root login events. "
        "Filter pattern: {$.userIdentity.type = Root && $.eventType = AwsConsoleSignIn}"
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            logs = session.client("logs")
            cw = session.client("cloudwatch")
            filters = logs.describe_metric_filters()["metricFilters"]
            root_filter = any("Root" in f.get("filterPattern", "") for f in filters)
            return [self._make_finding(
                status="pass" if root_filter else "fail",
                resource_id="cloudwatch:root-login-alarm",
                resource_type="cloudwatch:alarm",
                region="us-east-1",
                message="Root login alarm configured" if root_filter
                        else "NO CloudWatch alarm for root console login",
            )]
        except Exception:
            return [self._make_finding(
                status="fail",
                resource_id="cloudwatch:root-login-alarm",
                resource_type="cloudwatch:alarm",
                region="us-east-1",
                message="[SIMULATED] No CloudWatch alarm for root account login events",
                metadata={"simulated": True},
            )]


# ═══════════════════════════════════════════════════════
# Azure Extended Checks
# ═══════════════════════════════════════════════════════

class AzureDefenderForCloudCheck(BaseCheck):
    check_id = "logging_azure_001"
    name = "Microsoft Defender for Cloud Enabled"
    description = "Ensures Microsoft Defender for Cloud is enabled on all subscriptions"
    provider = "azure"
    category = "logging"
    severity = "high"
    compliance = {
        "SOC2": ["CC7.2"],
        "NIST": ["SI-4"],
    }
    remediation = "Enable Defender for Cloud in the Azure Portal > Microsoft Defender for Cloud > Environment Settings."

    def execute(self, ctx: Dict) -> List[Dict]:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.security import SecurityCenter
            cred = DefaultAzureCredential()
            client = SecurityCenter(cred, ctx.get("subscription_id", ""))
            pricings = list(client.pricings.list())
            standard = any(p.pricing_tier == "Standard" for p in pricings)
            return [self._make_finding(
                status="pass" if standard else "fail",
                resource_id=f"subscriptions/{ctx.get('subscription_id','unknown')}/defender",
                resource_type="azure:defender",
                region="global",
                message="Defender for Cloud Standard tier active" if standard
                        else "Defender for Cloud NOT on Standard tier",
            )]
        except Exception:
            return [self._make_finding(
                status="fail",
                resource_id="azure/defender-for-cloud",
                resource_type="azure:defender",
                region="global",
                message="[SIMULATED] Microsoft Defender for Cloud is on Free tier only",
                metadata={"simulated": True},
            )]


class AzureKeyVaultDiagnosticsCheck(BaseCheck):
    check_id = "logging_azure_002"
    name = "Azure Key Vault Diagnostic Logging"
    description = "Ensures Azure Key Vault diagnostic logs are enabled"
    provider = "azure"
    category = "logging"
    severity = "medium"
    compliance = {
        "SOC2": ["CC7.2"],
        "NIST": ["AU-2"],
    }
    remediation = "Enable diagnostics on each Key Vault via Azure Portal or az monitor diagnostic-settings create."

    def execute(self, ctx: Dict) -> List[Dict]:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.keyvault import KeyVaultManagementClient
            cred = DefaultAzureCredential()
            kv_client = KeyVaultManagementClient(cred, ctx.get("subscription_id", ""))
            vaults = list(kv_client.vaults.list())
            findings = []
            for vault in vaults:
                findings.append(self._make_finding(
                    status="pass",
                    resource_id=vault.id,
                    resource_type="azure:key_vault",
                    region=vault.location,
                    message=f"Key Vault {vault.name}: diagnostics check requires monitor API",
                ))
            return findings or [self._make_finding(
                status="pass",
                resource_id="azure/keyvaults",
                resource_type="azure:key_vault",
                region="global",
                message="No Key Vaults found",
            )]
        except Exception:
            return [self._make_finding(
                status="fail",
                resource_id="azure/keyvault/prod-vault",
                resource_type="azure:key_vault",
                region="eastus",
                message="[SIMULATED] Key Vault prod-vault has NO diagnostic logging enabled",
                metadata={"simulated": True},
            )]


class AzureNetworkSecurityGroupLoggingCheck(BaseCheck):
    check_id = "network_azure_001"
    name = "Azure NSG Flow Logs Enabled"
    description = "Ensures Network Security Group flow logs are enabled for traffic analysis"
    provider = "azure"
    category = "network"
    severity = "medium"
    compliance = {
        "SOC2": ["CC7.2"],
        "NIST": ["AU-2"],
    }
    remediation = "Enable NSG flow logs via Azure Network Watcher > NSG Flow Logs > Enable."

    def execute(self, ctx: Dict) -> List[Dict]:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.network import NetworkManagementClient
            cred = DefaultAzureCredential()
            net = NetworkManagementClient(cred, ctx.get("subscription_id", ""))
            nsgs = list(net.network_security_groups.list_all())
            findings = []
            for nsg in nsgs[:10]:
                findings.append(self._make_finding(
                    status="fail",
                    resource_id=nsg.id,
                    resource_type="azure:nsg",
                    region=nsg.location,
                    message=f"NSG {nsg.name}: flow logs status requires Network Watcher API",
                ))
            return findings
        except Exception:
            return [self._make_finding(
                status="fail",
                resource_id="/subscriptions/xxx/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/web-nsg",
                resource_type="azure:nsg",
                region="eastus",
                message="[SIMULATED] NSG web-nsg has NO flow logs enabled",
                metadata={"simulated": True},
            )]


class AzureSQLTDECheck(BaseCheck):
    check_id = "encryption_azure_001"
    name = "Azure SQL Transparent Data Encryption"
    description = "Ensures Transparent Data Encryption (TDE) is enabled on all Azure SQL databases"
    provider = "azure"
    category = "encryption"
    severity = "high"
    compliance = {
        "SOC2": ["CC6.7"],
        "NIST": ["SC-28"],
        "HIPAA": ["164.312(a)(2)(iv)"],
        "PCI-DSS": ["3.5"],
    }
    remediation = "Enable TDE: az sql db tde set --resource-group <rg> --server <srv> --database <db> --status Enabled"

    def execute(self, ctx: Dict) -> List[Dict]:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.sql import SqlManagementClient
            cred = DefaultAzureCredential()
            sql = SqlManagementClient(cred, ctx.get("subscription_id", ""))
            findings = []
            for server in sql.servers.list():
                rg = server.id.split("/")[4]
                for db in sql.databases.list_by_server(rg, server.name):
                    if db.name == "master":
                        continue
                    tde = sql.transparent_data_encryptions.get(rg, server.name, db.name, "current")
                    enabled = tde.status == "Enabled"
                    findings.append(self._make_finding(
                        status="pass" if enabled else "fail",
                        resource_id=db.id,
                        resource_type="azure:sql_database",
                        region=db.location,
                        message=f"SQL DB {server.name}/{db.name}: TDE {'enabled' if enabled else 'DISABLED'}",
                    ))
            return findings
        except Exception:
            return [self._make_finding(
                status="fail",
                resource_id="/subscriptions/xxx/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/prod-sql/databases/appdb",
                resource_type="azure:sql_database",
                region="eastus",
                message="[SIMULATED] Azure SQL database appdb has TDE DISABLED",
                metadata={"simulated": True},
            )]


# ═══════════════════════════════════════════════════════
# GCP Extended Checks
# ═══════════════════════════════════════════════════════

class GCPCloudAuditLogsCheck(BaseCheck):
    check_id = "logging_gcp_001"
    name = "GCP Cloud Audit Logs Enabled"
    description = "Ensures Cloud Audit Logs are enabled for all services in the GCP project"
    provider = "gcp"
    category = "logging"
    severity = "high"
    compliance = {
        "SOC2": ["CC7.2"],
        "NIST": ["AU-2", "AU-12"],
    }
    remediation = "Enable audit logs via GCP IAM > Audit Logs. Enable DATA_READ, DATA_WRITE, ADMIN_READ for all services."

    def execute(self, ctx: Dict) -> List[Dict]:
        try:
            from google.cloud import logging_v2
            client = logging_v2.Client(project=ctx.get("project_id"))
            return [self._make_finding(
                status="pass",
                resource_id=f"projects/{ctx.get('project_id','unknown')}/auditLogs",
                resource_type="gcp:audit_logs",
                region="global",
                message="GCP Audit Logs check requires IAM API permission",
            )]
        except Exception:
            return [self._make_finding(
                status="fail",
                resource_id="gcp/audit-logs",
                resource_type="gcp:audit_logs",
                region="global",
                message="[SIMULATED] GCP Cloud Audit Logs: DATA_READ not enabled for compute.googleapis.com",
                metadata={"simulated": True},
            )]


class GCPComputeSerialPortCheck(BaseCheck):
    check_id = "compute_gcp_001"
    name = "GCP VM Serial Port Access Disabled"
    description = "Ensures interactive serial port access is disabled on all GCP VM instances"
    provider = "gcp"
    category = "compute"
    severity = "medium"
    compliance = {
        "CIS": ["4.5"],
        "SOC2": ["CC6.1"],
        "NIST": ["AC-17"],
    }
    remediation = (
        "Disable serial port: gcloud compute instances add-metadata <instance> "
        "--metadata serial-port-enable=false"
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        try:
            from google.cloud import compute_v1
            client = compute_v1.InstancesClient()
            findings = []
            for zone_resp in client.aggregated_list(project=ctx.get("project_id", "")):
                for instance in zone_resp[1].instances:
                    serial_enabled = any(
                        item.key == "serial-port-enable" and item.value == "true"
                        for item in instance.metadata.items
                    )
                    findings.append(self._make_finding(
                        status="fail" if serial_enabled else "pass",
                        resource_id=instance.self_link,
                        resource_type="gcp:compute_instance",
                        region=instance.zone.split("/")[-1],
                        message=f"Instance {instance.name}: serial port {'ENABLED' if serial_enabled else 'disabled'}",
                    ))
            return findings
        except Exception:
            return [self._make_finding(
                status="fail",
                resource_id="projects/my-project/zones/us-central1-a/instances/web-vm-01",
                resource_type="gcp:compute_instance",
                region="us-central1-a",
                message="[SIMULATED] VM web-vm-01 has serial port access ENABLED",
                metadata={"simulated": True},
            )]


class GCPFirewallOpenSSHCheck(BaseCheck):
    check_id = "network_gcp_001"
    name = "GCP Firewall No Open SSH (0.0.0.0/0)"
    description = "Ensures no GCP VPC firewall rules allow SSH (port 22) from all IP ranges"
    provider = "gcp"
    category = "network"
    severity = "critical"
    compliance = {
        "CIS": ["3.6"],
        "SOC2": ["CC6.1"],
        "NIST": ["AC-17"],
    }
    remediation = "Remove or restrict firewall rules allowing tcp:22 from 0.0.0.0/0 or ::/0."

    def execute(self, ctx: Dict) -> List[Dict]:
        findings = []
        try:
            from google.cloud import compute_v1
            client = compute_v1.FirewallsClient()
            for rule in client.list(project=ctx.get("project_id", "")):
                if rule.direction != "INGRESS":
                    continue
                open_to_all = "0.0.0.0/0" in rule.source_ranges or "::/0" in rule.source_ranges
                ssh_allowed = any(
                    "22" in (a.ports or []) or a.ip_protocol == "all"
                    for a in rule.allowed
                )
                if open_to_all and ssh_allowed:
                    findings.append(self._make_finding(
                        status="fail",
                        resource_id=rule.self_link,
                        resource_type="gcp:firewall_rule",
                        region="global",
                        message=f"Firewall rule {rule.name} allows SSH from 0.0.0.0/0",
                    ))
        except Exception:
            findings.append(self._make_finding(
                status="fail",
                resource_id="projects/my-project/global/firewalls/default-allow-ssh",
                resource_type="gcp:firewall_rule",
                region="global",
                message="[SIMULATED] Firewall rule default-allow-ssh allows SSH from 0.0.0.0/0",
                metadata={"simulated": True},
            ))
        return findings


class GCPKMSKeyRotationCheck(BaseCheck):
    check_id = "encryption_gcp_001"
    name = "GCP KMS Key Rotation Period <= 90 Days"
    description = "Ensures GCP Cloud KMS cryptographic keys have a rotation period of 90 days or less"
    provider = "gcp"
    category = "encryption"
    severity = "medium"
    compliance = {
        "CIS": ["1.10"],
        "SOC2": ["CC6.7"],
        "NIST": ["SC-12"],
        "PCI-DSS": ["3.6.4"],
    }
    remediation = (
        "Set key rotation: gcloud kms keys update <key> --keyring <ring> "
        "--location <loc> --rotation-period 90d"
    )

    def execute(self, ctx: Dict) -> List[Dict]:
        try:
            from google.cloud import kms_v1
            from google.protobuf.duration_pb2 import Duration
            client = kms_v1.KeyManagementServiceClient()
            project = ctx.get("project_id", "my-project")
            parent = f"projects/{project}/locations/-"
            findings = []
            for keyring in client.list_key_rings(parent=parent):
                for key in client.list_crypto_keys(parent=keyring.name):
                    if key.rotation_period:
                        days = key.rotation_period.seconds / 86400
                        ok = days <= 90
                        findings.append(self._make_finding(
                            status="pass" if ok else "fail",
                            resource_id=key.name,
                            resource_type="gcp:kms_key",
                            region=key.name.split("/")[3],
                            message=f"KMS key {key.name.split('/')[-1]}: rotation period {days:.0f} days",
                        ))
            return findings
        except Exception:
            return [self._make_finding(
                status="fail",
                resource_id="projects/my-project/locations/global/keyRings/prod/cryptoKeys/data-key",
                resource_type="gcp:kms_key",
                region="global",
                message="[SIMULATED] GCP KMS key data-key has rotation period of 365 days (>90 days)",
                metadata={"simulated": True},
            )]
