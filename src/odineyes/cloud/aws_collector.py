"""
Odineyes — AWS CSPM Collector (Wiz-style, AWS-focused)

Read-only collector that maps a live AWS account into normalized resource
records + relationships, ready to be loaded into the Security Graph.

Every AWS call here is read-only (describe_* / list_* / get_*). Nothing is
ever created, modified, or deleted in the account.

Coverage (the CSPM core that drives toxic-combination attack paths):
  - EC2 instances        (public exposure, attached SGs, attached IAM role)
  - Security Groups       (internet-open ingress ports)
  - S3 buckets            (public access, encryption, policy/ACL exposure)
  - IAM roles             (admin + wildcard + privilege-escalation actions)
  - RDS instances         (public exposure, encryption)
  - Account identity      (account id, principal)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Managed policies / action patterns that grant effective admin.
_ADMIN_MANAGED = {"AdministratorAccess", "IAMFullAccess", "PowerUserAccess"}

# IAM actions that allow a principal to escalate its own privileges.
# (classic privesc primitives — see Rhino Security "AWS IAM privilege escalation")
_PRIVESC_ACTIONS = {
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:UpdateAssumeRolePolicy",
    "iam:PassRole",
    "sts:AssumeRole",
}

_PORT_LABELS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
                80: "HTTP", 443: "HTTPS", 21: "FTP", 23: "Telnet", 0: "ALL"}


# ── Normalized records ─────────────────────────────────────────

@dataclass
class Ec2Record:
    instance_id: str
    instance_type: str
    state: str
    public_ip: Optional[str]
    private_ip: Optional[str]
    vpc_id: str
    subnet_id: str
    image_id: str
    security_group_ids: list[str] = field(default_factory=list)
    iam_role_names: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def is_public(self) -> bool:
        return bool(self.public_ip)


@dataclass
class SecurityGroupRecord:
    sg_id: str
    name: str
    vpc_id: str
    open_ports: list[int] = field(default_factory=list)   # ports open to 0.0.0.0/0
    is_internet_exposed: bool = False


@dataclass
class S3Record:
    name: str
    region: str
    is_public: bool
    public_reason: str
    encrypted: bool
    versioning: bool
    sensitive: bool = False     # heuristic from name/tags


@dataclass
class IamRoleRecord:
    role_name: str
    arn: str
    has_admin: bool
    admin_reason: str
    privesc_actions: list[str] = field(default_factory=list)
    s3_access: list[str] = field(default_factory=list)   # bucket names or ["*"]
    assumable_by_ec2: bool = False
    trust_external: bool = False
    trust_principals: list[str] = field(default_factory=list)   # external AWS principals


@dataclass
class RdsRecord:
    db_id: str
    engine: str
    endpoint: str
    vpc_id: str
    publicly_accessible: bool
    encrypted: bool


@dataclass
class AwsInventory:
    account_id: str
    principal_arn: str
    region: str
    ec2: list[Ec2Record] = field(default_factory=list)
    security_groups: list[SecurityGroupRecord] = field(default_factory=list)
    s3: list[S3Record] = field(default_factory=list)
    iam_roles: list[IamRoleRecord] = field(default_factory=list)
    rds: list[RdsRecord] = field(default_factory=list)


# ── Collector ──────────────────────────────────────────────────

class AwsCollector:
    """Read-only AWS account collector."""

    def __init__(self, region: str = "us-east-1", profile: Optional[str] = None):
        self.region = region
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.ec2 = self.session.client("ec2", region_name=region)
        self.iam = self.session.client("iam", region_name=region)
        self.rds = self.session.client("rds", region_name=region)
        self.s3 = self.session.client("s3", region_name=region)
        self.sts = self.session.client("sts", region_name=region)
        # map instance-profile arn -> [role names], filled lazily
        self._profile_role_cache: dict[str, list[str]] = {}

    # -- identity --------------------------------------------------
    def identity(self) -> tuple[str, str]:
        try:
            ident = self.sts.get_caller_identity()
            return ident.get("Account", "unknown"), ident.get("Arn", "unknown")
        except ClientError as e:
            logger.error("get_caller_identity failed: %s", e)
            return "unknown", "unknown"

    # -- full collect ---------------------------------------------
    def collect(self) -> AwsInventory:
        account_id, principal = self.identity()
        self.account_id = account_id
        inv = AwsInventory(account_id=account_id, principal_arn=principal, region=self.region)
        inv.security_groups = self._collect_security_groups()
        inv.ec2 = self._collect_ec2()
        inv.s3 = self._collect_s3()
        inv.iam_roles = self._collect_iam_roles()
        inv.rds = self._collect_rds()
        return inv

    # -- EC2 -------------------------------------------------------
    def _collect_ec2(self) -> list[Ec2Record]:
        out: list[Ec2Record] = []
        try:
            paginator = self.ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for res in page.get("Reservations", []):
                    for inst in res.get("Instances", []):
                        sg_ids = [g["GroupId"] for g in inst.get("SecurityGroups", [])]
                        roles: list[str] = []
                        prof = inst.get("IamInstanceProfile", {})
                        if prof.get("Arn"):
                            roles = self._roles_for_profile(prof["Arn"])
                        out.append(Ec2Record(
                            instance_id=inst.get("InstanceId", ""),
                            instance_type=inst.get("InstanceType", ""),
                            state=inst.get("State", {}).get("Name", ""),
                            public_ip=inst.get("PublicIpAddress"),
                            private_ip=inst.get("PrivateIpAddress"),
                            vpc_id=inst.get("VpcId", ""),
                            subnet_id=inst.get("SubnetId", ""),
                            image_id=inst.get("ImageId", ""),
                            security_group_ids=sg_ids,
                            iam_role_names=roles,
                            tags={t["Key"]: t["Value"] for t in inst.get("Tags", [])},
                        ))
        except ClientError as e:
            logger.error("describe_instances failed: %s", e)
        return out

    def _roles_for_profile(self, profile_arn: str) -> list[str]:
        if profile_arn in self._profile_role_cache:
            return self._profile_role_cache[profile_arn]
        roles: list[str] = []
        # profile arn: arn:aws:iam::acct:instance-profile/NAME
        name = profile_arn.split("/")[-1]
        try:
            resp = self.iam.get_instance_profile(InstanceProfileName=name)
            roles = [r["RoleName"] for r in resp.get("InstanceProfile", {}).get("Roles", [])]
        except ClientError as e:
            logger.debug("get_instance_profile(%s) failed: %s", name, e)
        self._profile_role_cache[profile_arn] = roles
        return roles

    # -- Security Groups ------------------------------------------
    def _collect_security_groups(self) -> list[SecurityGroupRecord]:
        out: list[SecurityGroupRecord] = []
        try:
            paginator = self.ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    open_ports: set[int] = set()
                    for rule in sg.get("IpPermissions", []):
                        open_to_world = any(
                            r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])
                        ) or any(
                            r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", [])
                        )
                        if not open_to_world:
                            continue
                        frm = rule.get("FromPort")
                        to = rule.get("ToPort")
                        if frm is None and to is None:
                            open_ports.add(0)  # all ports / all protocols
                        else:
                            # record the from-port as representative
                            open_ports.add(int(frm))
                    out.append(SecurityGroupRecord(
                        sg_id=sg.get("GroupId", ""),
                        name=sg.get("GroupName", ""),
                        vpc_id=sg.get("VpcId", ""),
                        open_ports=sorted(open_ports),
                        is_internet_exposed=bool(open_ports),
                    ))
        except ClientError as e:
            logger.error("describe_security_groups failed: %s", e)
        return out

    # -- S3 --------------------------------------------------------
    def _collect_s3(self) -> list[S3Record]:
        out: list[S3Record] = []
        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
        except ClientError as e:
            logger.error("list_buckets failed: %s", e)
            return out

        for b in buckets:
            name = b["Name"]
            is_public, reason = self._bucket_public(name)
            out.append(S3Record(
                name=name,
                region=self._bucket_region(name),
                is_public=is_public,
                public_reason=reason,
                encrypted=self._bucket_encrypted(name),
                versioning=self._bucket_versioning(name),
                sensitive=self._looks_sensitive(name),
            ))
        return out

    def _bucket_region(self, name: str) -> str:
        try:
            loc = self.s3.get_bucket_location(Bucket=name).get("LocationConstraint")
            return loc or "us-east-1"
        except ClientError:
            return "unknown"

    def _bucket_public(self, name: str) -> tuple[bool, str]:
        # 1. Public Access Block — if all four flags true, bucket cannot be public.
        try:
            pab = self.s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if all(pab.get(k) for k in
                   ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
                return False, "blocked by Public Access Block"
        except ClientError:
            pab = {}  # no PAB configured → could be public

        # 2. Policy status
        try:
            ps = self.s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]
            if ps.get("IsPublic"):
                return True, "bucket policy grants public access"
        except ClientError:
            pass

        # 3. ACL grants to AllUsers / AuthenticatedUsers
        try:
            acl = self.s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                uri = grant.get("Grantee", {}).get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    return True, f"ACL grants {uri.split('/')[-1]}"
        except ClientError:
            pass

        if not pab:
            return False, "no public grant found (no Public Access Block set)"
        return False, "not public"

    def _bucket_encrypted(self, name: str) -> bool:
        try:
            self.s3.get_bucket_encryption(Bucket=name)
            return True
        except ClientError:
            return False

    def _bucket_versioning(self, name: str) -> bool:
        try:
            return self.s3.get_bucket_versioning(Bucket=name).get("Status") == "Enabled"
        except ClientError:
            return False

    @staticmethod
    def _looks_sensitive(name: str) -> bool:
        hot = ("backup", "secret", "private", "data", "db", "dump", "prod",
               "customer", "user", "pii", "deploy", "backend", "config")
        n = name.lower()
        return any(h in n for h in hot)

    # -- IAM roles -------------------------------------------------
    def _collect_iam_roles(self) -> list[IamRoleRecord]:
        out: list[IamRoleRecord] = []
        try:
            paginator = self.iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    name = role["RoleName"]
                    # skip AWS service-linked roles (noise, not attacker-controllable)
                    if role.get("Path", "/").startswith("/aws-service-role/"):
                        continue
                    rec = self._analyze_role(name, role)
                    out.append(rec)
        except ClientError as e:
            logger.error("list_roles failed: %s", e)
        return out

    def _analyze_role(self, name: str, role: dict) -> IamRoleRecord:
        arn = role.get("Arn", "")
        has_admin = False
        admin_reason = ""
        privesc: set[str] = set()
        s3_access: set[str] = set()

        # trust policy analysis
        trust = role.get("AssumeRolePolicyDocument", {})
        assumable_ec2, trust_external, trust_principals = self._analyze_trust(
            trust, getattr(self, "account_id", None))

        # attached managed policies
        try:
            for p in self.iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
                pname = p.get("PolicyName", "")
                if pname in _ADMIN_MANAGED:
                    has_admin = True
                    admin_reason = f"managed policy {pname}"
                # inspect document for privesc / s3
                self._scan_managed_policy(p.get("PolicyArn", ""), privesc, s3_access)
        except ClientError as e:
            logger.debug("list_attached_role_policies(%s): %s", name, e)

        # inline policies
        try:
            for pol_name in self.iam.list_role_policies(RoleName=name).get("PolicyNames", []):
                try:
                    doc = self.iam.get_role_policy(RoleName=name, PolicyName=pol_name).get("PolicyDocument", {})
                    a, s = self._scan_doc(doc)
                    privesc |= a
                    s3_access |= s
                    if self._doc_is_admin(doc):
                        has_admin = True
                        admin_reason = admin_reason or f"inline policy {pol_name} (*:*)"
                except ClientError:
                    pass
        except ClientError as e:
            logger.debug("list_role_policies(%s): %s", name, e)

        return IamRoleRecord(
            role_name=name,
            arn=arn,
            has_admin=has_admin,
            admin_reason=admin_reason,
            privesc_actions=sorted(privesc),
            s3_access=sorted(s3_access),
            assumable_by_ec2=assumable_ec2,
            trust_external=trust_external,
            trust_principals=trust_principals,
        )

    def _scan_managed_policy(self, policy_arn: str, privesc: set, s3_access: set):
        if not policy_arn:
            return
        try:
            ver = self.iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            doc = self.iam.get_policy_version(PolicyArn=policy_arn, VersionId=ver)["PolicyVersion"]["Document"]
            a, s = self._scan_doc(doc)
            privesc |= a
            s3_access |= s
        except ClientError as e:
            logger.debug("scan managed policy %s: %s", policy_arn, e)

    @staticmethod
    def _statements(doc) -> list[dict]:
        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
            except json.JSONDecodeError:
                return []
        stmts = doc.get("Statement", []) if isinstance(doc, dict) else []
        return stmts if isinstance(stmts, list) else [stmts]

    @classmethod
    def _scan_doc(cls, doc) -> tuple[set, set]:
        """Return (privesc_actions, s3_buckets) granted by an Allow policy doc."""
        privesc: set[str] = set()
        s3: set[str] = set()
        for st in cls._statements(doc):
            if st.get("Effect") != "Allow":
                continue
            actions = st.get("Action", [])
            actions = [actions] if isinstance(actions, str) else actions
            resources = st.get("Resource", [])
            resources = [resources] if isinstance(resources, str) else resources
            for act in actions:
                if act == "*" or act == "iam:*" or act == "sts:*":
                    privesc.add(act)
                elif act in _PRIVESC_ACTIONS:
                    privesc.add(act)
                if act == "*" or act.lower().startswith("s3:"):
                    for r in resources:
                        if r == "*":
                            s3.add("*")
                        elif r.startswith("arn:aws:s3:::"):
                            s3.add(r.split(":::")[1].split("/")[0])
        return privesc, s3

    @classmethod
    def _doc_is_admin(cls, doc) -> bool:
        for st in cls._statements(doc):
            if st.get("Effect") != "Allow":
                continue
            actions = st.get("Action", [])
            actions = [actions] if isinstance(actions, str) else actions
            resources = st.get("Resource", [])
            resources = [resources] if isinstance(resources, str) else resources
            if "*" in actions and "*" in resources:
                return True
        return False

    @classmethod
    def _analyze_trust(cls, trust, account_id=None) -> tuple[bool, bool, list[str]]:
        """Return (assumable_by_ec2, trust_external, external_principals).

        external = role can be assumed by `*` or by a principal in a *different*
        AWS account than `account_id` (cross-account lateral-movement risk).
        """
        assumable_ec2 = False
        external = False
        principals: set[str] = set()
        for st in cls._statements(trust):
            if st.get("Effect") != "Allow":
                continue
            principal = st.get("Principal", {})
            if principal == "*":
                external = True
                principals.add("*")
                continue
            if not isinstance(principal, dict):
                continue
            svc = principal.get("Service", [])
            svc = [svc] if isinstance(svc, str) else svc
            if any("ec2.amazonaws.com" in s for s in svc):
                assumable_ec2 = True
            aws_p = principal.get("AWS", [])
            aws_p = [aws_p] if isinstance(aws_p, str) else aws_p
            for p in aws_p:
                if p == "*":
                    external = True
                    principals.add("*")
                elif account_id and account_id not in str(p):
                    # ARN like arn:aws:iam::OTHER_ACCT:root/role/user
                    external = True
                    principals.add(str(p))
        return assumable_ec2, external, sorted(principals)

    # -- RDS -------------------------------------------------------
    def _collect_rds(self) -> list[RdsRecord]:
        out: list[RdsRecord] = []
        try:
            paginator = self.rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    out.append(RdsRecord(
                        db_id=db.get("DBInstanceIdentifier", ""),
                        engine=db.get("Engine", ""),
                        endpoint=db.get("Endpoint", {}).get("Address", ""),
                        vpc_id=db.get("DBSubnetGroup", {}).get("VpcId", ""),
                        publicly_accessible=db.get("PubliclyAccessible", False),
                        encrypted=db.get("StorageEncrypted", False),
                    ))
        except ClientError as e:
            logger.error("describe_db_instances failed: %s", e)
        return out


def port_label(port: int) -> str:
    return _PORT_LABELS.get(port, str(port))
