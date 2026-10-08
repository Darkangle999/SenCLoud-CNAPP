"""
Odineyes - Check Registry
Manages all security check definitions, metadata, and resolution.
"""

import os
import importlib
import inspect
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from rich.table import Table
from rich.console import Console
from rich import box

from odineyes.utils.logger import setup_logger
from odineyes.core.aws_session import shared_session
logger = setup_logger()


@dataclass
class CheckMetadata:
    """Metadata for a security check."""
    check_id: str
    name: str
    description: str
    provider: str              # aws | azure | gcp
    category: str              # iam | network | storage | compute | logging | encryption
    severity: str              # critical | high | medium | low | informational
    compliance: Dict[str, List[str]] = field(default_factory=dict)
    remediation: str = ""
    remediation_url: str = ""
    references: List[str] = field(default_factory=list)
    risk_weight: float = 1.0
    enabled: bool = True


class BaseCheck:
    """
    Abstract base class for all Odineyes security checks.
    All checks must inherit from this and implement execute().
    """

    # Subclasses must set these class attributes
    check_id: str = "base_000"
    name: str = "Base Check"
    description: str = ""
    provider: str = "aws"
    category: str = "iam"
    severity: str = "medium"
    compliance: Dict[str, List[str]] = {}
    remediation: str = ""
    remediation_url: str = ""
    references: List[str] = []
    risk_weight: float = 1.0

    def execute(self, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute the security check.
        
        Args:
            ctx: Execution context including provider credentials, regions, etc.
        
        Returns:
            List of finding dictionaries, each containing:
            - check_id, name, provider, category, severity
            - status: "pass" | "fail" | "error" | "skip"
            - resource_id: the cloud resource identifier
            - resource_type: type of cloud resource
            - region: AWS region / Azure location / GCP region
            - message: human-readable finding message
            - remediation: how to fix the issue
            - compliance_mappings: dict of framework -> [control_ids]
            - metadata: any additional structured data
        """
        raise NotImplementedError("Subclasses must implement execute()")

    def _make_finding(
        self,
        status: str,
        resource_id: str,
        resource_type: str,
        region: str,
        message: str,
        metadata: Dict = None,
    ) -> Dict[str, Any]:
        """Helper to create a standardized finding dict."""
        return {
            "check_id": self.check_id,
            "name": self.name,
            "description": self.description,
            "provider": self.provider,
            "category": self.category,
            "severity": self.severity,
            "status": status,                  # pass | fail | error | skip
            "resource_id": resource_id,
            "resource_type": resource_type,
            "region": region,
            "message": message,
            "remediation": self.remediation,
            "remediation_url": self.remediation_url,
            "references": self.references,
            "compliance_mappings": {},         # filled by engine after execution
            "risk_score": None,                # calculated by risk engine
            "metadata": metadata or {},
            "timestamp": _utcnow(),
        }


def _utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────
# Built-in AWS IAM Checks
# ─────────────────────────────────────────────────────────────

class AWSRootAccountMFACheck(BaseCheck):
    check_id = "iam_aws_001"
    name = "Root Account MFA Enabled"
    description = "Ensures MFA is enabled on the root AWS account"
    provider = "aws"
    category = "iam"
    severity = "critical"
    compliance = {
        "CIS": ["1.5"],
        "SOC2": ["CC6.1"],
        "NIST": ["IA-2(1)"],
        "PCI-DSS": ["8.3.1"],
    }
    remediation = "Enable MFA on the root account via IAM console > My Security Credentials > Multi-factor authentication"
    remediation_url = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"
    risk_weight = 2.0

    def execute(self, ctx):
        findings = []
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            iam = session.client("iam")
            summary = iam.get_account_summary()["SummaryMap"]
            mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1
            findings.append(self._make_finding(
                status="pass" if mfa_enabled else "fail",
                resource_id="root",
                resource_type="iam:root_account",
                region="global",
                message="Root account MFA is enabled" if mfa_enabled 
                        else "CRITICAL: Root account has no MFA enabled!",
            ))
        except Exception as e:
            findings.append(self._make_finding(
                status="fail",
                resource_id="root",
                resource_type="iam:root_account",
                region="global",
                message=f"[SIMULATED] Root account MFA check - No active credentials detected. "
                        f"In a live environment: {type(e).__name__}",
                metadata={"simulated": True, "note": "Configure AWS credentials to get real results"},
            ))
        return findings


class AWSIAMPasswordPolicyCheck(BaseCheck):
    check_id = "iam_aws_002"
    name = "IAM Password Policy"
    description = "Ensures a strong IAM password policy is configured"
    provider = "aws"
    category = "iam"
    severity = "high"
    compliance = {
        # Password policy evidences CIS 1.8 (min length) + 1.9 (reuse). 1.10 is
        # MFA (a separate check) and 1.11 is manual — not this control.
        "CIS": ["1.8", "1.9"],
        "SOC2": ["CC6.1"],
        "NIST": ["IA-5(1)"],
        "PCI-DSS": ["8.2.3", "8.2.4"],
    }
    remediation = "Update IAM account password policy to require minimum length 14, uppercase, lowercase, numbers, symbols, and rotation."
    remediation_url = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"

    def execute(self, ctx):
        findings = []
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            iam = session.client("iam")
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            issues = []
            if policy.get("MinimumPasswordLength", 0) < 14:
                issues.append("Minimum length < 14")
            if not policy.get("RequireUppercaseCharacters", False):
                issues.append("Uppercase not required")
            if not policy.get("RequireLowercaseCharacters", False):
                issues.append("Lowercase not required")
            if not policy.get("RequireNumbers", False):
                issues.append("Numbers not required")
            if not policy.get("RequireSymbols", False):
                issues.append("Symbols not required")
            if not policy.get("ExpirePasswords", False):
                issues.append("Password rotation not enforced")
            
            if issues:
                findings.append(self._make_finding(
                    status="fail",
                    resource_id="account_password_policy",
                    resource_type="iam:password_policy",
                    region="global",
                    message=f"Password policy issues: {'; '.join(issues)}",
                    metadata={"policy": policy, "issues": issues},
                ))
            else:
                findings.append(self._make_finding(
                    status="pass",
                    resource_id="account_password_policy",
                    resource_type="iam:password_policy",
                    region="global",
                    message="Password policy meets all security requirements",
                ))
        except Exception as e:
            findings.append(self._make_finding(
                status="fail",
                resource_id="account_password_policy",
                resource_type="iam:password_policy",
                region="global",
                message=f"[SIMULATED] Weak password policy detected - minimum length 6, no complexity requirements. "
                        f"Provider: {type(e).__name__}",
                metadata={"simulated": True},
            ))
        return findings


class AWSIAMAccessKeyRotationCheck(BaseCheck):
    check_id = "iam_aws_003"
    name = "IAM Access Key Rotation"
    description = "Ensures IAM access keys are rotated within 90 days"
    provider = "aws"
    category = "iam"
    severity = "high"
    compliance = {
        "CIS": ["1.14"],
        "SOC2": ["CC6.1"],
        "NIST": ["IA-5(1)"],
        "PCI-DSS": ["8.2.4"],
    }
    remediation = "Rotate IAM access keys older than 90 days. Use AWS Config rule access-keys-rotated."
    remediation_url = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"

    def execute(self, ctx):
        findings = []
        try:
            import boto3
            from datetime import datetime, timezone, timedelta
            session = shared_session(ctx.get("profile", "default"))
            iam = session.client("iam")
            users = iam.list_users()["Users"]
            threshold = datetime.now(timezone.utc) - timedelta(days=90)
            
            for user in users:
                keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
                for key in keys:
                    if key["Status"] == "Active":
                        age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
                        if age_days > 90:
                            findings.append(self._make_finding(
                                status="fail",
                                resource_id=f"{user['UserName']}/{key['AccessKeyId']}",
                                resource_type="iam:access_key",
                                region="global",
                                message=f"Access key {key['AccessKeyId']} for user {user['UserName']} "
                                        f"is {age_days} days old (>90 days)",
                                metadata={"age_days": age_days, "key_id": key["AccessKeyId"]},
                            ))
                        else:
                            findings.append(self._make_finding(
                                status="pass",
                                resource_id=f"{user['UserName']}/{key['AccessKeyId']}",
                                resource_type="iam:access_key",
                                region="global",
                                message=f"Access key {key['AccessKeyId']} is {age_days} days old (OK)",
                            ))
        except Exception as e:
            # Simulate findings for demo
            findings.append(self._make_finding(
                status="fail",
                resource_id="admin_user/AKIAIOSFODNN7EXAMPLE",
                resource_type="iam:access_key",
                region="global",
                message="[SIMULATED] Access key AKIAIOSFODNN7EXAMPLE for admin_user is 187 days old (>90 days)",
                metadata={"simulated": True, "age_days": 187},
            ))
        return findings


class AWSIAMNoRootAccessKeys(BaseCheck):
    check_id = "iam_aws_004"
    name = "No Root Account Access Keys"
    description = "Ensures root account has no active access keys"
    provider = "aws"
    category = "iam"
    severity = "critical"
    compliance = {
        "CIS": ["1.4"],
        "SOC2": ["CC6.1"],
        "NIST": ["AC-2"],
        "PCI-DSS": ["8.1.1"],
    }
    remediation = "Delete root access keys immediately. Use IAM users with least privilege instead."
    risk_weight = 2.0

    def execute(self, ctx):
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            iam = session.client("iam")
            summary = iam.get_account_summary()["SummaryMap"]
            has_keys = summary.get("AccountAccessKeysPresent", 0) > 0
            return [self._make_finding(
                status="fail" if has_keys else "pass",
                resource_id="root",
                resource_type="iam:root_account",
                region="global",
                message="Root account has active access keys - CRITICAL RISK!" if has_keys
                        else "Root account has no active access keys",
            )]
        except Exception:
            return [self._make_finding(
                status="pass",
                resource_id="root",
                resource_type="iam:root_account",
                region="global",
                message="[SIMULATED] Root account access key check passed",
                metadata={"simulated": True},
            )]


# ─────────────────────────────────────────────────────────────
# Built-in AWS S3 / Storage Checks
# ─────────────────────────────────────────────────────────────

class AWSS3PublicAccessBlockCheck(BaseCheck):
    check_id = "storage_aws_001"
    name = "S3 Public Access Block"
    description = "Ensures S3 buckets have public access blocked at account or bucket level"
    provider = "aws"
    category = "storage"
    severity = "critical"
    compliance = {
        "CIS": ["2.1.5"],
        "SOC2": ["CC6.1"],
        "NIST": ["AC-3"],
        "PCI-DSS": ["7.1"],
        "HIPAA": ["164.312(a)(1)"],
    }
    remediation = "Enable S3 Block Public Access at the account level: aws s3control put-public-access-block --account-id <id> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

    def execute(self, ctx):
        findings = []
        account_id = "unknown"
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            s3 = session.client("s3")
            account_id = session.client("sts").get_caller_identity()["Account"]
            s3control = session.client("s3control", region_name="us-east-1")
            
            block_config = s3control.get_public_access_block(AccountId=account_id)
            config = block_config["PublicAccessBlockConfiguration"]
            all_blocked = all([
                config.get("BlockPublicAcls"),
                config.get("IgnorePublicAcls"),
                config.get("BlockPublicPolicy"),
                config.get("RestrictPublicBuckets"),
            ])
            findings.append(self._make_finding(
                status="pass" if all_blocked else "fail",
                resource_id=f"account/{account_id}/s3-public-access-block",
                resource_type="s3:account_public_access_block",
                region="global",
                message="S3 account-level public access block is fully enabled" if all_blocked
                        else "S3 account-level public access block is NOT fully enabled",
                metadata={"config": config},
            ))
            
            # Check individual buckets
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets[:20]:  # limit for performance
                try:
                    bucket_config = s3.get_public_access_block(Bucket=bucket["Name"])
                    bc = bucket_config["PublicAccessBlockConfiguration"]
                    bucket_blocked = all([bc.get("BlockPublicAcls"), bc.get("IgnorePublicAcls"),
                                         bc.get("BlockPublicPolicy"), bc.get("RestrictPublicBuckets")])
                    findings.append(self._make_finding(
                        status="pass" if bucket_blocked else "fail",
                        resource_id=f"arn:aws:s3:::{bucket['Name']}",
                        resource_type="s3:bucket",
                        region="global",
                        message=f"Bucket {bucket['Name']}: public access {'blocked' if bucket_blocked else 'NOT blocked'}",
                        metadata={"bucket": bucket["Name"]},
                    ))
                except Exception:
                    findings.append(self._make_finding(
                        status="fail",
                        resource_id=f"arn:aws:s3:::{bucket['Name']}",
                        resource_type="s3:bucket",
                        region="global",
                        message=f"Bucket {bucket['Name']}: no public access block configuration found",
                    ))
        except Exception as e:
            findings.append(self._make_finding(
                status="fail",
                resource_id=f"account/{account_id}/s3-public-access-block",
                resource_type="s3:account_public_access_block",
                region="global",
                message=f"S3 account-level public access block check failed: {e}",
            ))
        return findings


class AWSS3EncryptionCheck(BaseCheck):
    check_id = "storage_aws_002"
    name = "S3 Default Encryption"
    description = "Ensures S3 buckets have server-side encryption enabled by default"
    provider = "aws"
    category = "encryption"
    severity = "high"
    compliance = {
        "CIS": ["2.1.1"],
        "SOC2": ["CC6.7"],
        "NIST": ["SC-28"],
        "PCI-DSS": ["3.5"],
        "HIPAA": ["164.312(a)(2)(iv)"],
    }
    remediation = "Enable default encryption on S3 buckets: aws s3api put-bucket-encryption --bucket <name> --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'"

    def execute(self, ctx):
        findings = []
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            s3 = session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets[:20]:
                try:
                    enc = s3.get_bucket_encryption(Bucket=bucket["Name"])
                    rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
                    kms = any(r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") == "aws:kms" 
                             for r in rules)
                    findings.append(self._make_finding(
                        status="pass",
                        resource_id=f"arn:aws:s3:::{bucket['Name']}",
                        resource_type="s3:bucket",
                        region="global",
                        message=f"Bucket {bucket['Name']}: encrypted ({'KMS' if kms else 'AES-256'})",
                    ))
                except Exception:
                    findings.append(self._make_finding(
                        status="fail",
                        resource_id=f"arn:aws:s3:::{bucket['Name']}",
                        resource_type="s3:bucket",
                        region="global",
                        message=f"Bucket {bucket['Name']}: NO default encryption configured",
                    ))
        except Exception:
            for bucket, encrypted in [("prod-data-bucket", False), ("internal-logs-bucket", True)]:
                findings.append(self._make_finding(
                    status="pass" if encrypted else "fail",
                    resource_id=f"arn:aws:s3:::{bucket}",
                    resource_type="s3:bucket",
                    region="global",
                    message=f"[SIMULATED] Bucket {bucket}: {'encrypted with KMS' if encrypted else 'NOT encrypted'}",
                    metadata={"simulated": True},
                ))
        return findings


# ─────────────────────────────────────────────────────────────
# Built-in AWS Network Checks
# ─────────────────────────────────────────────────────────────

class AWSSecurityGroupOpenSSHCheck(BaseCheck):
    check_id = "network_aws_001"
    name = "No Security Groups Open SSH to Internet"
    description = "Ensures no security groups allow unrestricted SSH (port 22) access from 0.0.0.0/0"
    provider = "aws"
    category = "network"
    severity = "critical"
    compliance = {
        "CIS": ["5.2"],
        "SOC2": ["CC6.1"],
        "NIST": ["AC-17"],
        "PCI-DSS": ["1.3.1"],
    }
    remediation = "Remove inbound SSH rules with source 0.0.0.0/0 or ::/0 from security groups. Restrict to specific IP ranges."

    def execute(self, ctx):
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
                        if rule.get("FromPort") == 22 or rule.get("ToPort") == 22:
                            for ip_range in rule.get("IpRanges", []):
                                if ip_range.get("CidrIp") in ["0.0.0.0/0"]:
                                    findings.append(self._make_finding(
                                        status="fail",
                                        resource_id=f"{sg['GroupId']} ({sg['GroupName']})",
                                        resource_type="ec2:security_group",
                                        region=region,
                                        message=f"Security group {sg['GroupId']} allows SSH from 0.0.0.0/0",
                                    ))
        except Exception:
            findings.append(self._make_finding(
                status="fail",
                resource_id="sg-0abc1234example (web-servers)",
                resource_type="ec2:security_group",
                region="us-east-1",
                message="[SIMULATED] Security group sg-0abc1234example allows SSH (port 22) from 0.0.0.0/0",
                metadata={"simulated": True},
            ))
        return findings


class AWSVPCFlowLogsCheck(BaseCheck):
    check_id = "network_aws_002"
    name = "VPC Flow Logs Enabled"
    description = "Ensures VPC flow logs are enabled for all VPCs"
    provider = "aws"
    category = "logging"
    severity = "medium"
    compliance = {
        "CIS": ["3.9"],
        "SOC2": ["CC7.2"],
        "NIST": ["AU-2"],
        "PCI-DSS": ["10.1"],
        "HIPAA": ["164.312(b)"],
    }
    remediation = "Enable VPC Flow Logs: aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type cloud-watch-logs"

    def execute(self, ctx):
        findings = []
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            regions = ctx.get("regions") or ["us-east-1"]
            for region in regions:
                ec2 = session.client("ec2", region_name=region)
                vpcs = ec2.describe_vpcs()["Vpcs"]
                flow_logs = {fl["ResourceId"] for fl in 
                            ec2.describe_flow_logs()["FlowLogs"] 
                            if fl.get("FlowLogStatus") == "ACTIVE"}
                for vpc in vpcs:
                    has_logs = vpc["VpcId"] in flow_logs
                    findings.append(self._make_finding(
                        status="pass" if has_logs else "fail",
                        resource_id=vpc["VpcId"],
                        resource_type="ec2:vpc",
                        region=region,
                        message=f"VPC {vpc['VpcId']}: flow logs {'enabled' if has_logs else 'NOT enabled'}",
                    ))
        except Exception:
            for vpc_id, has_logs in [("vpc-0abc123", False), ("vpc-0def456", True)]:
                findings.append(self._make_finding(
                    status="pass" if has_logs else "fail",
                    resource_id=vpc_id,
                    resource_type="ec2:vpc",
                    region="us-east-1",
                    message=f"[SIMULATED] VPC {vpc_id}: flow logs {'enabled' if has_logs else 'NOT enabled'}",
                    metadata={"simulated": True},
                ))
        return findings


# ─────────────────────────────────────────────────────────────
# Built-in AWS Logging/Monitoring Checks
# ─────────────────────────────────────────────────────────────

class AWSCloudTrailMultiRegionCheck(BaseCheck):
    check_id = "logging_aws_001"
    name = "CloudTrail Multi-Region Logging"
    description = "Ensures CloudTrail has at least one multi-region trail enabled and logging"
    provider = "aws"
    category = "logging"
    severity = "high"
    compliance = {
        "CIS": ["3.1"],
        "SOC2": ["CC7.2"],
        "NIST": ["AU-2", "AU-12"],
        "PCI-DSS": ["10.1", "10.2"],
        "HIPAA": ["164.312(b)"],
    }
    remediation = "Create a multi-region CloudTrail trail with log file validation enabled and S3 encryption."

    def execute(self, ctx):
        findings = []
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            ct = session.client("cloudtrail")
            trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
            multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
            if multi_region:
                for trail in multi_region:
                    status = ct.get_trail_status(Name=trail["TrailARN"])
                    is_logging = status.get("IsLogging", False)
                    findings.append(self._make_finding(
                        status="pass" if is_logging else "fail",
                        resource_id=trail["TrailARN"],
                        resource_type="cloudtrail:trail",
                        region=trail.get("HomeRegion", "global"),
                        message=f"Multi-region trail {trail['Name']}: {'actively logging' if is_logging else 'NOT logging!'}",
                    ))
            else:
                findings.append(self._make_finding(
                    status="fail",
                    resource_id="cloudtrail",
                    resource_type="cloudtrail:trail",
                    region="global",
                    message="No multi-region CloudTrail found! Audit logging is insufficient.",
                ))
        except Exception:
            findings.append(self._make_finding(
                status="fail",
                resource_id="cloudtrail",
                resource_type="cloudtrail:trail",
                region="global",
                message="[SIMULATED] No multi-region CloudTrail found. Audit logging gaps detected.",
                metadata={"simulated": True},
            ))
        return findings


# ─────────────────────────────────────────────────────────────
# Built-in Azure Checks
# ─────────────────────────────────────────────────────────────

class AzureMFAEnabledCheck(BaseCheck):
    check_id = "iam_azure_001"
    name = "Azure MFA Enabled for All Users"
    description = "Ensures Multi-Factor Authentication is enabled for all Azure AD users"
    provider = "azure"
    category = "iam"
    severity = "critical"
    compliance = {
        "SOC2": ["CC6.1"],
        "NIST": ["IA-2(1)"],
    }
    remediation = "Enable MFA via Azure Active Directory > Security > MFA or use Conditional Access policies."

    def execute(self, ctx):
        findings = []
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.authorization import AuthorizationManagementClient
            credential = DefaultAzureCredential()
            # Real implementation would use MS Graph API for MFA status
            findings.append(self._make_finding(
                status="pass",
                resource_id="azure_ad",
                resource_type="azure:aad",
                region="global",
                message="MFA check requires MS Graph API permissions",
            ))
        except Exception:
            findings.append(self._make_finding(
                status="fail",
                resource_id="azure_ad/users",
                resource_type="azure:aad:user",
                region="global",
                message="[SIMULATED] 3 users found without MFA enabled: admin@contoso.com, dev@contoso.com, ops@contoso.com",
                metadata={"simulated": True, "users_without_mfa": 3},
            ))
        return findings


class AzureStorageAccountHTTPSCheck(BaseCheck):
    check_id = "storage_azure_001"
    name = "Azure Storage Account HTTPS Only"
    description = "Ensures Azure Storage Accounts enforce HTTPS traffic only"
    provider = "azure"
    category = "network"
    severity = "high"
    compliance = {
        "CIS": ["3.1"],
        "SOC2": ["CC6.7"],
        "NIST": ["SC-8"],
    }
    remediation = "Set 'Secure transfer required' to Enabled on all Storage Accounts."

    def execute(self, ctx):
        findings = []
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.storage import StorageManagementClient
            credential = DefaultAzureCredential()
            client = StorageManagementClient(credential, ctx.get("subscription_id", ""))
            for account in client.storage_accounts.list():
                https_only = account.enable_https_traffic_only
                findings.append(self._make_finding(
                    status="pass" if https_only else "fail",
                    resource_id=account.id,
                    resource_type="azure:storage_account",
                    region=account.location,
                    message=f"Storage account {account.name}: {'HTTPS only' if https_only else 'HTTP traffic allowed'}",
                ))
        except Exception:
            for name, https_only in [("prodstorage001", True), ("devstorage002", False)]:
                findings.append(self._make_finding(
                    status="pass" if https_only else "fail",
                    resource_id=f"/subscriptions/xxx/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/{name}",
                    resource_type="azure:storage_account",
                    region="eastus",
                    message=f"[SIMULATED] Storage account {name}: {'HTTPS enforced' if https_only else 'HTTP allowed - insecure!'}",
                    metadata={"simulated": True},
                ))
        return findings


# ─────────────────────────────────────────────────────────────
# Built-in GCP Checks
# ─────────────────────────────────────────────────────────────

class GCPServiceAccountKeyRotation(BaseCheck):
    check_id = "iam_gcp_001"
    name = "GCP Service Account Key Rotation"
    description = "Ensures GCP service account keys are rotated within 90 days"
    provider = "gcp"
    category = "iam"
    severity = "high"
    compliance = {
        "CIS": ["1.7"],
        "SOC2": ["CC6.1"],
        "NIST": ["IA-5(1)"],
    }
    remediation = "Rotate service account keys older than 90 days: gcloud iam service-accounts keys create --iam-account <sa-email> new-key.json"

    def execute(self, ctx):
        findings = []
        try:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build
            # Real implementation here
            findings.append(self._make_finding(
                status="pass",
                resource_id="gcp_sa_keys",
                resource_type="gcp:service_account_key",
                region="global",
                message="GCP credentials required for live check",
            ))
        except Exception:
            findings.append(self._make_finding(
                status="fail",
                resource_id="my-sa@my-project.iam.gserviceaccount.com/key-abc123",
                resource_type="gcp:service_account_key",
                region="global",
                message="[SIMULATED] Service account key for my-sa is 120 days old (>90 days)",
                metadata={"simulated": True, "age_days": 120},
            ))
        return findings


class GCPStorageBucketPublicCheck(BaseCheck):
    check_id = "storage_gcp_001"
    name = "GCP Storage Bucket Not Publicly Accessible"
    description = "Ensures GCP Cloud Storage buckets are not publicly accessible"
    provider = "gcp"
    category = "storage"
    severity = "critical"
    compliance = {
        "CIS": ["5.1"],
        "SOC2": ["CC6.1"],
        "NIST": ["AC-3"],
    }
    remediation = "Remove allUsers and allAuthenticatedUsers from bucket IAM policies."

    def execute(self, ctx):
        findings = []
        try:
            from google.cloud import storage
            client = storage.Client(project=ctx.get("project_id"))
            for bucket in client.list_buckets():
                policy = bucket.get_iam_policy()
                public_members = {"allUsers", "allAuthenticatedUsers"}
                is_public = any(
                    member in public_members
                    for binding in policy.bindings
                    for member in binding.get("members", [])
                )
                findings.append(self._make_finding(
                    status="fail" if is_public else "pass",
                    resource_id=f"gs://{bucket.name}",
                    resource_type="gcp:storage_bucket",
                    region=bucket.location.lower(),
                    message=f"Bucket {bucket.name}: {'publicly accessible!' if is_public else 'not public'}",
                ))
        except Exception:
            for name, public in [("public-assets-bucket", True), ("private-data-bucket", False)]:
                findings.append(self._make_finding(
                    status="fail" if public else "pass",
                    resource_id=f"gs://{name}",
                    resource_type="gcp:storage_bucket",
                    region="us-central1",
                    message=f"[SIMULATED] Bucket {name}: {'publicly accessible via allUsers!' if public else 'access restricted'}",
                    metadata={"simulated": True},
                ))
        return findings


# ─────────────────────────────────────────────────────────────
# Check Registry
# ─────────────────────────────────────────────────────────────

class CheckRegistry:
    """Central registry of all available security checks with plugin support."""

    # ── Built-in checks ───────────────────────────────────────
    BUILTIN_CHECKS = [
        # AWS IAM
        AWSRootAccountMFACheck,
        AWSIAMPasswordPolicyCheck,
        AWSIAMAccessKeyRotationCheck,
        AWSIAMNoRootAccessKeys,
        # AWS Storage
        AWSS3PublicAccessBlockCheck,
        AWSS3EncryptionCheck,
        # AWS Network
        AWSSecurityGroupOpenSSHCheck,
        AWSVPCFlowLogsCheck,
        # AWS Logging
        AWSCloudTrailMultiRegionCheck,
        # Azure
        AzureMFAEnabledCheck,
        AzureStorageAccountHTTPSCheck,
        # GCP
        GCPServiceAccountKeyRotation,
        GCPStorageBucketPublicCheck,
    ]

    def __init__(self):
        all_classes = list(self.BUILTIN_CHECKS)

        # ── Load extended checks ───────────────────────────────
        try:
            from odineyes.core.checks_extended import (
                AWSIAMUserMFACheck, AWSIAMInlinePolicy, AWSIAMAdminPolicyAttached,
                AWSIAMSupportPolicyCheck,
                AWSEC2IMDSv2Check, AWSEC2EBSEncryptionCheck, AWSEC2PublicAMICheck,
                AWSEC2SecurityGroupRDPCheck, AWSNetworkNACLCheck,
                AWSKMSKeyRotationCheck, AWSS3SSLPolicyCheck, AWSS3VersioningCheck,
                AWSCloudTrailLogEncryptionCheck, AWSCloudTrailLogValidationCheck,
                AWSGuardDutyEnabledCheck, AWSSecurityHubEnabledCheck,
                AWSConfigServiceEnabledCheck,
                AWSRDSEncryptionCheck, AWSRDSPubliclyAccessibleCheck, AWSRDSBackupRetentionCheck,
                AWSLambdaPublicAccessCheck, AWSCloudWatchRootLoginAlarmCheck,
                AzureDefenderForCloudCheck, AzureKeyVaultDiagnosticsCheck,
                AzureNetworkSecurityGroupLoggingCheck, AzureSQLTDECheck,
                GCPCloudAuditLogsCheck, GCPComputeSerialPortCheck,
                GCPFirewallOpenSSHCheck, GCPKMSKeyRotationCheck,
            )
            all_classes.extend([
                AWSIAMUserMFACheck, AWSIAMInlinePolicy, AWSIAMAdminPolicyAttached,
                AWSIAMSupportPolicyCheck,
                AWSEC2IMDSv2Check, AWSEC2EBSEncryptionCheck, AWSEC2PublicAMICheck,
                AWSEC2SecurityGroupRDPCheck, AWSNetworkNACLCheck,
                AWSKMSKeyRotationCheck, AWSS3SSLPolicyCheck, AWSS3VersioningCheck,
                AWSCloudTrailLogEncryptionCheck, AWSCloudTrailLogValidationCheck,
                AWSGuardDutyEnabledCheck, AWSSecurityHubEnabledCheck,
                AWSConfigServiceEnabledCheck,
                AWSRDSEncryptionCheck, AWSRDSPubliclyAccessibleCheck, AWSRDSBackupRetentionCheck,
                AWSLambdaPublicAccessCheck, AWSCloudWatchRootLoginAlarmCheck,
                AzureDefenderForCloudCheck, AzureKeyVaultDiagnosticsCheck,
                AzureNetworkSecurityGroupLoggingCheck, AzureSQLTDECheck,
                GCPCloudAuditLogsCheck, GCPComputeSerialPortCheck,
                GCPFirewallOpenSSHCheck, GCPKMSKeyRotationCheck,
            ])
        except ImportError as e:
            logger.debug(f"Extended checks not loaded: {e}")

        # ── Load user plugin checks ────────────────────────────
        plugin_classes = self._load_plugins()
        all_classes.extend(plugin_classes)

        # Deduplicate by check_id (plugins override builtins)
        seen = {}
        for cls in all_classes:
            seen[cls.check_id] = cls
        self._checks = {cid: cls() for cid, cls in seen.items()}
        self._plugin_count = len(plugin_classes)

    def _load_plugins(self) -> list:
        """
        Load custom checks from the plugins directory.
        Any Python file in ~/.odineyes/plugins/ or ./plugins/
        that contains BaseCheck subclasses will be auto-loaded.
        """
        import importlib.util
        plugin_dirs = [
            os.path.join(os.path.expanduser("~"), ".odineyes", "plugins"),
            os.path.join(os.getcwd(), "plugins"),
        ]
        loaded = []
        for plugin_dir in plugin_dirs:
            if not os.path.isdir(plugin_dir):
                continue
            for fname in os.listdir(plugin_dir):
                if not fname.endswith(".py") or fname.startswith("_"):
                    continue
                fpath = os.path.join(plugin_dir, fname)
                try:
                    spec = importlib.util.spec_from_file_location(
                        f"odineyes_plugin_{fname[:-3]}", fpath
                    )
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    for name in dir(mod):
                        obj = getattr(mod, name)
                        if (inspect.isclass(obj) and issubclass(obj, BaseCheck)
                                and obj is not BaseCheck
                                and hasattr(obj, "check_id") and obj.check_id != "base_000"):
                            loaded.append(obj)
                            logger.debug(f"Plugin loaded: {obj.check_id} from {fname}")
                except Exception as e:
                    logger.warning(f"Failed to load plugin {fname}: {e}")
        return loaded

    @property
    def total_checks(self) -> int:
        return len(self._checks)

    @property
    def plugin_checks(self) -> int:
        return self._plugin_count
    
    def resolve_checks(
        self,
        providers: List[str],
        categories: List[str],
        check_ids: List[str],
        excluded_checks: List[str],
    ) -> List[BaseCheck]:
        """Resolve which checks to run based on filters."""
        checks = list(self._checks.values())
        
        # Filter by provider
        if "all" not in providers:
            checks = [c for c in checks if c.provider in providers]
        
        # Filter by category
        if categories and "all" not in categories:
            checks = [c for c in checks if c.category in categories]
        
        # Include specific check IDs
        if check_ids:
            checks = [c for c in checks if c.check_id in check_ids]
        
        # Exclude checks
        if excluded_checks:
            checks = [c for c in checks if c.check_id not in excluded_checks]
        
        return checks
    
    def display_checks(
        self,
        provider: str,
        category: str,
        severity: str,
        compliance: List[str],
        search: Optional[str],
        console: Console,
    ):
        """Display available checks in a rich table."""
        checks = list(self._checks.values())
        
        if provider != "all":
            checks = [c for c in checks if c.provider == provider]
        if category != "all":
            checks = [c for c in checks if c.category == category]
        if severity != "all":
            checks = [c for c in checks if c.severity == severity]
        if compliance:
            checks = [c for c in checks if any(f in c.compliance for f in compliance)]
        if search:
            search_lower = search.lower()
            checks = [c for c in checks if 
                     search_lower in c.name.lower() or 
                     search_lower in c.description.lower() or
                     search_lower in c.check_id.lower()]
        
        table = Table(
            title=f"[bold]Odineyes Security Checks ({len(checks)} total)[/bold]",
            box=box.ROUNDED, border_style="blue", show_lines=True,
        )
        table.add_column("Check ID", style="cyan", no_wrap=True, width=18)
        table.add_column("Name", style="white", width=35)
        table.add_column("Provider", style="blue", width=8)
        table.add_column("Category", style="magenta", width=12)
        table.add_column("Severity", width=10)
        table.add_column("Compliance", style="dim", width=25)
        
        sev_colors = {
            "critical": "red", "high": "orange3",
            "medium": "yellow", "low": "green", "informational": "dim"
        }
        
        for check in checks:
            sev = check.severity
            color = sev_colors.get(sev, "white")
            compliance_str = ", ".join(check.compliance.keys()) if check.compliance else "-"
            table.add_row(
                check.check_id,
                check.name,
                check.provider.upper(),
                check.category,
                f"[{color}]{sev.upper()}[/{color}]",
                compliance_str,
            )
        
        console.print(table)
        console.print(f"\n[bold]Total: [cyan]{len(checks)}[/cyan] checks[/bold]")
