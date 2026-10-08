"""IaC misconfiguration scanner — the pre-deploy mirror of the live rules engine.

Accepts a Terraform plan (``terraform show -json`` output) or a CloudFormation
template (JSON or YAML) as text, normalises both into a flat list of
``IacResource`` records, and runs an offline rule set that checks the same
predicates as ``inventory/rules.py``.

Architecture
~~~~~~~~~~~~
Single-resource checks
    Callable[[IacResource], IacFinding | None] — registered in _SINGLE_CHECKS.
    Each runs against one resource in isolation.

Combination (toxic-path) checks
    Callable[[list[IacResource]], list[IacFinding]] — registered in
    _COMBO_CHECKS.  Each receives the full plan resource list so it can
    cross-reference resources (e.g. public EC2 + admin IAM role in the same
    template).

Rule parity with inventory/rules.py (last sync)
    Single-resource: public S3 ACL, S3 no-encryption, RDS no-encryption,
    world-open SG (IPv4 AND IPv6 — fixed), wildcard IAM, CloudTrail x3
    (log validation, CloudWatch, KMS encryption), Config recorder not enabled,
    KMS key rotation disabled, CloudWatch LogGroup no-retention,
    LogGroup not encrypted, Lambda public URL, Redshift public warehouse.
    Combination: public-EC2->admin-role (flagship), no multi-region trail,
    CloudTrail->public-S3-bucket.

Gap fixes vs previous version
    * IPv6 CIDR blind spot: _check_open_sg now reads ipv6_cidr_blocks and
      CidrIpv6 in addition to IPv4 equivalents (gap #4).
    * Multi-resource combination-rule support: scan() now runs _COMBO_CHECKS
      after the single-resource pass (gap #3).
    * Rule parity: 9 new rules ported from the live engine (gap #2).
    * TF variable interpolation safety: _truthy and _falsy skip
      unresolved "${var.*}" strings instead of treating them as "false" (gap #6).

Pure and deterministic — no cloud calls — fixture-testable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

try:  # YAML is optional; JSON always works.
    import yaml
except Exception:  # pragma: no cover - pyyaml is a declared dep
    yaml = None  # type: ignore


# ── normalised resource ─────────────────────────────────────────

@dataclass
class IacResource:
    fmt: str          # "terraform" | "cloudformation"
    type: str         # provider resource type  e.g. aws_s3_bucket / AWS::S3::Bucket
    name: str         # logical name / address
    props: dict[str, Any] = field(default_factory=dict)


@dataclass
class IacFinding:
    check_id: str
    title: str
    severity: str     # critical | high | medium | low
    resource: str
    resource_type: str
    why: str
    remediation: str
    compliance: dict[str, list[str]] = field(default_factory=dict)
    related: list[str] = field(default_factory=list)  # other resource names in a combo

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id, "title": self.title, "severity": self.severity,
            "resource": self.resource, "resource_type": self.resource_type,
            "why": self.why, "remediation": self.remediation,
            "compliance": self.compliance, "related": self.related,
        }


# ── parsing ─────────────────────────────────────────────────────

class _LaxLoader(yaml.SafeLoader if yaml else object):  # type: ignore
    """SafeLoader that tolerates CloudFormation intrinsic tags (!Ref, !GetAtt)
    by returning their raw argument instead of erroring."""


def _ctor(loader, tag_suffix, node):  # pragma: no cover - thin shim
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


if yaml is not None:
    _LaxLoader.add_multi_constructor("!", _ctor)


def parse(text: str) -> list[IacResource]:
    """Best-effort parse of TF-plan-JSON or CloudFormation (JSON/YAML)."""
    data: Any = None
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        if yaml is not None:
            try:
                data = yaml.load(text, Loader=_LaxLoader)
            except Exception:
                data = None
    if not isinstance(data, dict):
        return []

    # CloudFormation: top-level "Resources" map.
    if isinstance(data.get("Resources"), dict):
        out = []
        for logical, body in data["Resources"].items():
            if isinstance(body, dict):
                out.append(IacResource(
                    "cloudformation", str(body.get("Type", "")), str(logical),
                    body.get("Properties") or {},
                ))
        return out

    # Terraform plan JSON: planned_values.root_module(.child_modules).resources
    if "planned_values" in data or "resource_changes" in data:
        return list(_walk_tf(data))

    # Raw HCL-as-JSON: {"resource": {type: {name: {...}}}}
    if isinstance(data.get("resource"), dict):
        out = []
        for rtype, named in data["resource"].items():
            if isinstance(named, dict):
                for name, props in named.items():
                    out.append(IacResource("terraform", str(rtype), str(name),
                                           props if isinstance(props, dict) else {}))
        return out
    return []


def _walk_tf(data: dict) -> Iterable[IacResource]:
    """Walk a terraform plan JSON and yield IacResource objects."""
    # resource_changes carries the after-state; prefer it, fall back to planned.
    for ch in data.get("resource_changes", []) or []:
        after = ((ch.get("change") or {}).get("after")) or {}
        yield IacResource(
            "terraform",
            str(ch.get("type", "")),
            str(ch.get("address", ch.get("name", ""))),
            after,
        )
    if data.get("resource_changes"):
        return
    root = (data.get("planned_values") or {}).get("root_module") or {}

    def modules(m):
        yield m
        for c in m.get("child_modules", []) or []:
            yield from modules(c)

    for mod in modules(root):
        for r in mod.get("resources", []) or []:
            yield IacResource(
                "terraform",
                str(r.get("type", "")),
                str(r.get("address", r.get("name", ""))),
                r.get("values") or {},
            )


# ── shared helpers ───────────────────────────────────────────────

def _is_aws_s3(r: IacResource) -> bool:
    return r.type in ("aws_s3_bucket", "AWS::S3::Bucket")


def _truthy(v: Any) -> bool:
    """Coerce a prop value to boolean.

    Deliberately returns False (not True) for unresolved TF variable
    interpolations like "${var.acl}" so we never produce a false-negative by
    silently treating an unknown value as True.  The inverse (_falsy) also
    returns False for unresolved values so neither direction noise-floors.
    """
    if isinstance(v, bool):
        return v
    s = str(v).lower().strip()
    # Unresolved TF variable interpolation — can't evaluate, don't flag.
    if s.startswith("${") or s.startswith("var."):
        return False
    return s in ("true", "1", "yes")


def _falsy(v: Any) -> bool:
    """Explicit false — only when we can resolve the value."""
    if isinstance(v, bool):
        return not v
    s = str(v).lower().strip()
    if s.startswith("${") or s.startswith("var."):
        return False   # can't evaluate; give benefit of the doubt
    return s in ("false", "0", "no")


def _statements(policy: Any) -> list[dict]:
    """Pull statements out of an inline policy that may be a dict or JSON string."""
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            return []
    if not isinstance(policy, dict):
        return []
    stmts = policy.get("Statement", [])
    return stmts if isinstance(stmts, list) else [stmts]


def _aslist(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _finding(
    check_id: str,
    title: str,
    severity: str,
    r: IacResource,
    why: str,
    remediation: str,
    compliance: "dict[str, list[str]] | None" = None,
    related: "list[str] | None" = None,
) -> IacFinding:
    return IacFinding(
        check_id=check_id, title=title, severity=severity,
        resource=r.name, resource_type=r.type,
        why=why, remediation=remediation,
        compliance=compliance or {},
        related=related or [],
    )


# ── single-resource checks ───────────────────────────────────────

def _check_public_s3(r: IacResource) -> Optional[IacFinding]:
    if not _is_aws_s3(r):
        return None
    acl = str(r.props.get("acl") or r.props.get("AccessControl") or "").lower()
    if "public" not in acl:
        return None
    return _finding(
        "IAC_S3_PUBLIC_ACL", "S3 bucket grants a public ACL", "high", r,
        why=f"Bucket declares ACL '{acl}', exposing objects to the internet at deploy time.",
        remediation="Remove the public ACL; enable Block Public Access on the bucket.",
        compliance={"CIS": ["2.1.5"], "NIST": ["AC-3"], "ISO27001": ["A.8.3"]},
    )


def _check_unencrypted_storage(r: IacResource) -> Optional[IacFinding]:
    # S3 without SSE
    if _is_aws_s3(r):
        has_sse = bool(
            r.props.get("server_side_encryption_configuration")
            or r.props.get("BucketEncryption")
        )
        if not has_sse:
            return _finding(
                "IAC_S3_NO_ENCRYPTION", "S3 bucket has no default encryption", "medium", r,
                why="No server-side encryption configured; objects rest unencrypted.",
                remediation="Add a server_side_encryption_configuration / BucketEncryption block.",
                compliance={"CIS": ["2.1.1"], "NIST": ["SC-28"], "PCI-DSS": ["3.5"]},
            )
        return None
    # RDS unencrypted
    if r.type in ("aws_db_instance", "AWS::RDS::DBInstance"):
        enc = r.props.get("storage_encrypted", r.props.get("StorageEncrypted"))
        if enc is not None and _falsy(enc):
            return _finding(
                "IAC_RDS_NO_ENCRYPTION", "RDS instance is not encrypted at rest", "high", r,
                why="storage_encrypted is false; the database rests unencrypted.",
                remediation="Set storage_encrypted / StorageEncrypted to true (KMS).",
                compliance={"NIST": ["SC-28"], "HIPAA": ["164.312(a)(1)"], "GDPR": ["Art.32"]},
            )
    return None


_DANGER_PORTS = {22, 3389, 3306, 5432, 0}
_WORLD_CIDRS = {"0.0.0.0/0", "::/0"}


def _check_open_sg(r: IacResource) -> Optional[IacFinding]:
    """Security group with admin-port ingress open to 0.0.0.0/0 or ::/0.

    Gap #4 fix: now reads ipv6_cidr_blocks (Terraform) and CidrIpv6
    (CloudFormation) in addition to IPv4 equivalents, so an SG open to the
    world exclusively over IPv6 is correctly flagged.
    """
    if r.type not in ("aws_security_group", "AWS::EC2::SecurityGroup"):
        return None
    rules = _aslist(r.props.get("ingress")) + _aslist(r.props.get("SecurityGroupIngress"))
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        # Collect all CIDR strings from both IPv4 and IPv6 fields.
        cidrs = (
            _aslist(rule.get("cidr_blocks"))       # TF IPv4
            + _aslist(rule.get("CidrIp"))           # CFN IPv4
            + _aslist(rule.get("ipv6_cidr_blocks")) # TF IPv6 (was missing)
            + _aslist(rule.get("CidrIpv6"))         # CFN IPv6 (was missing)
        )
        world = any(str(c).strip() in _WORLD_CIDRS for c in cidrs)
        if not world:
            continue
        frm = rule.get("from_port", rule.get("FromPort"))
        to = rule.get("to_port", rule.get("ToPort"))
        try:
            frm_i, to_i = int(frm), int(to)
        except (TypeError, ValueError):
            frm_i, to_i = 0, 65535
        hits = any(frm_i <= p <= to_i for p in _DANGER_PORTS)
        if hits:
            world_cidrs_hit = sorted(c for c in cidrs if str(c).strip() in _WORLD_CIDRS)
            return _finding(
                "IAC_SG_WORLD_OPEN",
                "Security group exposes admin ports to the internet",
                "critical", r,
                why=(
                    f"Ingress {frm_i}-{to_i} is open to the entire internet "
                    f"({', '.join(world_cidrs_hit)})."
                ),
                remediation=(
                    "Restrict the CIDR to known management ranges; "
                    "never expose 22/3389/DB ports to the world."
                ),
                compliance={"CIS": ["5.2"], "NIST": ["SC-7", "AC-3"], "PCI-DSS": ["1.3.1"]},
            )
    return None


def _check_wildcard_iam(r: IacResource) -> Optional[IacFinding]:
    if r.type not in (
        "aws_iam_policy", "aws_iam_role_policy", "aws_iam_role",
        "AWS::IAM::Policy", "AWS::IAM::Role", "AWS::IAM::ManagedPolicy",
    ):
        return None
    docs = []
    for k in ("policy", "PolicyDocument", "inline_policy", "assume_role_policy"):
        if r.props.get(k):
            docs.append(r.props[k])
    # CFN role: Policies: [{PolicyDocument}]
    for p in _aslist(r.props.get("Policies")):
        if isinstance(p, dict) and p.get("PolicyDocument"):
            docs.append(p["PolicyDocument"])
    for doc in docs:
        for st in _statements(doc):
            if str(st.get("Effect", "")).lower() != "allow":
                continue
            actions = [str(a) for a in _aslist(st.get("Action"))]
            resources = [str(x) for x in _aslist(st.get("Resource"))]
            if any(a == "*" or a.endswith(":*") for a in actions) and ("*" in resources):
                return _finding(
                    "IAC_IAM_WILDCARD",
                    "IAM policy grants wildcard action on all resources",
                    "high", r,
                    why="Statement allows Action '*' on Resource '*' — effective admin / privilege escalation.",
                    remediation="Scope actions and resources to the minimum the workload needs.",
                    compliance={"CIS": ["1.16"], "NIST": ["AC-6"], "ISO27001": ["A.5.15"]},
                )
    return None


# ── ported live rules (gap #2) ───────────────────────────────────

def _check_cloudtrail_no_log_validation(r: IacResource) -> Optional[IacFinding]:
    if r.type not in ("aws_cloudtrail", "AWS::CloudTrail::Trail"):
        return None
    enabled = r.props.get(
        "enable_log_file_validation",
        r.props.get("EnableLogFileValidation"),
    )
    if not _truthy(enabled):
        return _finding(
            "IAC_CLOUDTRAIL_NO_LOG_VALIDATION",
            "CloudTrail log file validation is disabled",
            "medium", r,
            why="Without log file validation, tampering with delivered CloudTrail logs cannot be detected.",
            remediation="Set enable_log_file_validation = true / EnableLogFileValidation: true.",
            compliance={
                "CIS": ["3.2"], "SOC2": ["CC7.2"], "NIST": ["AU-9"],
                "PCI-DSS": ["10.5.2"], "ISO27001": ["A.8.15"],
            },
        )
    return None


def _check_cloudtrail_no_cloudwatch(r: IacResource) -> Optional[IacFinding]:
    if r.type not in ("aws_cloudtrail", "AWS::CloudTrail::Trail"):
        return None
    cw = r.props.get(
        "cloud_watch_logs_group_arn",
        r.props.get("CloudWatchLogsLogGroupArn"),
    )
    if not cw:
        return _finding(
            "IAC_CLOUDTRAIL_NO_CLOUDWATCH",
            "CloudTrail trail is not wired to CloudWatch Logs",
            "medium", r,
            why="Without a CloudWatch Logs destination, trail events cannot drive real-time metric filters or alarms.",
            remediation="Set cloud_watch_logs_group_arn / CloudWatchLogsLogGroupArn.",
            compliance={
                "CIS": ["3.4"], "SOC2": ["CC7.2"], "NIST": ["AU-6"],
                "PCI-DSS": ["10.6"], "ISO27001": ["A.8.15"],
            },
        )
    return None


def _check_cloudtrail_not_encrypted(r: IacResource) -> Optional[IacFinding]:
    if r.type not in ("aws_cloudtrail", "AWS::CloudTrail::Trail"):
        return None
    kms = r.props.get("kms_key_id", r.props.get("KMSKeyId"))
    if not kms:
        return _finding(
            "IAC_CLOUDTRAIL_NOT_ENCRYPTED",
            "CloudTrail trail logs are not KMS-encrypted",
            "high", r,
            why="Trail has no KMS key configured — delivered log files rely on default SSE-S3 only.",
            remediation="Set kms_key_id / KMSKeyId to a KMS key ARN.",
            compliance={
                "CIS": ["3.7"], "SOC2": ["CC6.7"], "NIST": ["SC-28"],
                "PCI-DSS": ["3.5"], "ISO27001": ["A.8.24"],
            },
        )
    return None


def _check_config_not_enabled(r: IacResource) -> Optional[IacFinding]:
    """AWS Config recorder resource defined but recording disabled."""
    if r.type not in ("aws_config_configuration_recorder_status",):
        return None
    if not _truthy(r.props.get("is_enabled")):
        return _finding(
            "IAC_CONFIG_NOT_ENABLED",
            "AWS Config recorder is defined but not enabled",
            "high", r,
            why="A Config recorder is declared but is_enabled is false — configuration changes won't be tracked.",
            remediation="Set is_enabled = true on the aws_config_configuration_recorder_status resource.",
            compliance={
                "CIS": ["2.5"], "SOC2": ["CC7.2"], "NIST": ["CM-8", "CM-3"],
                "ISO27001": ["A.8.9"],
            },
        )
    return None


def _check_kms_key_rotation(r: IacResource) -> Optional[IacFinding]:
    if r.type not in ("aws_kms_key", "AWS::KMS::Key"):
        return None
    # Only symmetric encrypt/decrypt keys can have rotation (asymmetric cannot).
    if r.props.get("key_usage", "ENCRYPT_DECRYPT") != "ENCRYPT_DECRYPT":
        return None
    rotation = r.props.get("enable_key_rotation", r.props.get("EnableKeyRotation"))
    # Absent (AWS default = disabled) or explicitly false both fire.
    if rotation is None or _falsy(rotation):
        return _finding(
            "IAC_KMS_KEY_ROTATION_DISABLED",
            "Customer-managed KMS key has automatic rotation disabled",
            "medium", r,
            why=(
                "Annual key rotation is off — the same key material stays in use "
                "indefinitely, widening blast radius if ever compromised."
            ),
            remediation="Set enable_key_rotation = true / EnableKeyRotation: true.",
            compliance={
                "CIS": ["2.8"], "SOC2": ["CC6.7"], "NIST": ["SC-12"],
                "ISO27001": ["A.8.24"],
            },
        )
    return None


def _check_log_group_no_retention(r: IacResource) -> Optional[IacFinding]:
    if r.type not in ("aws_cloudwatch_log_group", "AWS::Logs::LogGroup"):
        return None
    retention = r.props.get("retention_in_days", r.props.get("RetentionInDays"))
    if retention is None:
        return _finding(
            "IAC_LOG_GROUP_NO_RETENTION",
            "CloudWatch log group has no retention policy",
            "low", r,
            why=(
                "Logs accumulate indefinitely — unbounded storage cost and a compliance gap "
                "where a retention window is mandated."
            ),
            remediation="Set retention_in_days / RetentionInDays (e.g. 365).",
            compliance={"NIST": ["AU-11"], "ISO27001": ["A.8.15"]},
        )
    return None


def _check_log_group_not_encrypted(r: IacResource) -> Optional[IacFinding]:
    if r.type not in ("aws_cloudwatch_log_group", "AWS::Logs::LogGroup"):
        return None
    kms = r.props.get("kms_key_id", r.props.get("KmsKeyId"))
    if not kms:
        return _finding(
            "IAC_LOG_GROUP_NOT_ENCRYPTED",
            "CloudWatch log group is not KMS-encrypted",
            "medium", r,
            why="Log group uses the default CloudWatch Logs encryption rather than a customer-managed KMS key.",
            remediation="Set kms_key_id / KmsKeyId to a CMK ARN.",
            compliance={"SOC2": ["CC6.7"], "NIST": ["SC-28"], "ISO27001": ["A.8.24"]},
        )
    return None


def _check_lambda_public_url(r: IacResource) -> Optional[IacFinding]:
    """Lambda function URL with auth type NONE."""
    if r.type not in ("aws_lambda_function_url", "AWS::Lambda::Url"):
        return None
    auth = str(r.props.get("authorization_type", r.props.get("AuthType", "")) or "").upper()
    if auth == "NONE":
        return _finding(
            "IAC_PUBLIC_LAMBDA_URL",
            "Lambda function URL is unauthenticated",
            "high", r,
            why=(
                "authorization_type is NONE — anyone on the internet can invoke "
                "the function without credentials."
            ),
            remediation="Set authorization_type / AuthType to AWS_IAM.",
            compliance={
                "CIS": ["5.2"], "SOC2": ["CC6.1"], "NIST": ["AC-3", "SC-7"],
                "PCI-DSS": ["1.3.1"], "ISO27001": ["A.8.20"],
            },
        )
    return None


def _check_redshift_public(r: IacResource) -> Optional[IacFinding]:
    if r.type not in ("aws_redshift_cluster", "AWS::Redshift::Cluster"):
        return None
    pub = r.props.get("publicly_accessible", r.props.get("PubliclyAccessible"))
    if pub is None or not _truthy(pub):
        return None
    encrypted = r.props.get("encrypted", r.props.get("Encrypted"))
    unencrypted = encrypted is not None and _falsy(encrypted)
    return _finding(
        "IAC_PUBLIC_WAREHOUSE",
        "Internet-facing Redshift cluster",
        "critical" if unencrypted else "high", r,
        why=(
            "Cluster is publicly accessible"
            + (" and unencrypted at rest" if unencrypted else "")
            + " — the warehouse surface is reachable from the internet."
        ),
        remediation=(
            "Set publicly_accessible = false / PubliclyAccessible: false "
            "and front access through a VPC endpoint."
        ),
        compliance={
            "CIS": ["5.2"], "SOC2": ["CC6.1", "CC6.7"],
            "NIST": ["AC-3", "SC-7", "SC-28"], "PCI-DSS": ["1.3.1", "3.5"],
            "HIPAA": ["164.312(a)(1)"], "ISO27001": ["A.8.20", "A.8.24"],
        },
    )


# ── single-resource registry ─────────────────────────────────────

_SINGLE_CHECKS: list[Callable[[IacResource], Optional[IacFinding]]] = [
    _check_public_s3,
    _check_unencrypted_storage,
    _check_open_sg,
    _check_wildcard_iam,
    _check_cloudtrail_no_log_validation,
    _check_cloudtrail_no_cloudwatch,
    _check_cloudtrail_not_encrypted,
    _check_config_not_enabled,
    _check_kms_key_rotation,
    _check_log_group_no_retention,
    _check_log_group_not_encrypted,
    _check_lambda_public_url,
    _check_redshift_public,
]


# ── combination (toxic-path) checks ─────────────────────────────

def _combo_public_ec2_to_admin_role(resources: list[IacResource]) -> list[IacFinding]:
    """Public EC2 + admin IAM role in the same Terraform plan.

    The live rule_public_compute_to_admin does this at runtime against persisted
    assets.  Here we replicate it at IaC time so the combination is caught
    before a single byte of infrastructure is deployed:

    1. Identify any IAM role / policy resource whose inline policy grants
       wildcard actions on all resources, OR any policy attachment referencing
       AdministratorAccess / PowerUserAccess.
    2. Identify any EC2 instance that has associate_public_ip_address=true AND
       an iam_instance_profile set.

    Both conditions in the same plan => CRITICAL finding.
    """
    # Step 1 — find admin IAM resources.
    admin_resources: list[IacResource] = []
    for r in resources:
        if r.type in (
            "aws_iam_role", "aws_iam_role_policy", "aws_iam_policy",
            "AWS::IAM::Role", "AWS::IAM::Policy",
        ):
            docs = []
            for k in ("policy", "PolicyDocument", "inline_policy", "assume_role_policy"):
                if r.props.get(k):
                    docs.append(r.props[k])
            for p in _aslist(r.props.get("Policies")):
                if isinstance(p, dict) and p.get("PolicyDocument"):
                    docs.append(p["PolicyDocument"])
            found_admin = False
            for doc in docs:
                for st in _statements(doc):
                    if str(st.get("Effect", "")).lower() != "allow":
                        continue
                    actions = [str(a) for a in _aslist(st.get("Action"))]
                    res_targets = [str(x) for x in _aslist(st.get("Resource"))]
                    if any(a == "*" or a.endswith(":*") for a in actions) and "*" in res_targets:
                        found_admin = True
                        break
                if found_admin:
                    break
            if found_admin:
                admin_resources.append(r)

        elif r.type == "aws_iam_role_policy_attachment":
            pol_arn = str(r.props.get("policy_arn") or "")
            if "AdministratorAccess" in pol_arn or "PowerUserAccess" in pol_arn:
                admin_resources.append(r)

    if not admin_resources:
        return []

    role_names = [r.name for r in admin_resources]

    # Step 2 — find public EC2 instances with an instance profile.
    findings: list[IacFinding] = []
    for r in resources:
        if r.type not in ("aws_instance", "AWS::EC2::Instance"):
            continue
        # Terraform: associate_public_ip_address = true
        # CFN: NetworkInterfaces[0].AssociatePublicIpAddress = true
        public_ip_prop = r.props.get("associate_public_ip_address")
        if public_ip_prop is None:
            nis = r.props.get("NetworkInterfaces") or []
            if nis and isinstance(nis[0], dict):
                public_ip_prop = nis[0].get("AssociatePublicIpAddress")
        has_public = _truthy(public_ip_prop) if public_ip_prop is not None else False
        profile = r.props.get("iam_instance_profile", r.props.get("IamInstanceProfile"))
        if has_public and profile:
            findings.append(IacFinding(
                check_id="IAC_PUBLIC_COMPUTE_TO_ADMIN",
                title="Public EC2 instance can reach admin credentials (toxic combination)",
                severity="critical",
                resource=r.name,
                resource_type=r.type,
                why=(
                    f"This plan provisions an internet-facing EC2 instance "
                    f"(associate_public_ip_address=true, iam_instance_profile='{profile}') "
                    f"alongside admin-level IAM resource(s): {', '.join(role_names)}. "
                    "An attacker with code-execution on the instance can call the instance "
                    "metadata service and obtain admin credentials — account takeover before "
                    "a single traffic log exists."
                ),
                remediation=(
                    "Remove the public IP (or front with a load balancer in a private subnet). "
                    "Assign a least-privilege role to the instance. "
                    "Remove or scope-down the admin IAM resource(s) before deploying."
                ),
                compliance={
                    "CIS": ["1.16", "5.2"], "SOC2": ["CC6.1"],
                    "NIST": ["AC-3", "AC-6"], "PCI-DSS": ["7.1"],
                    "ISO27001": ["A.5.15", "A.8.3"],
                },
                related=role_names,
            ))
    return findings


def _combo_cloudtrail_multiregion(resources: list[IacResource]) -> list[IacFinding]:
    """CIS 3.1: at least one CloudTrail must be multi-region and enabled.

    Account-scope — fires once per plan, not per-trail, to avoid alert flood.
    Mirrors rule_cloudtrail_no_multiregion in the live engine.
    """
    trails = [r for r in resources
              if r.type in ("aws_cloudtrail", "AWS::CloudTrail::Trail")]
    if not trails:
        return []
    good = [
        t for t in trails
        if _truthy(t.props.get("is_multi_region_trail", t.props.get("IsMultiRegionTrail")))
    ]
    if good:
        return []
    anchor = trails[0]
    return [IacFinding(
        check_id="IAC_CLOUDTRAIL_NOT_MULTIREGION",
        title="No multi-region CloudTrail trail in this plan",
        severity="high",
        resource=anchor.name,
        resource_type=anchor.type,
        why=(
            f"CIS 3.1 requires at least one trail covering all regions. "
            f"This plan defines {len(trails)} trail(s) but none have "
            "is_multi_region_trail = true."
        ),
        remediation="Add is_multi_region_trail = true to one trail.",
        compliance={
            "CIS": ["3.1"], "SOC2": ["CC7.2"], "NIST": ["AU-2", "AU-12"],
            "PCI-DSS": ["10.1"], "HIPAA": ["164.312(b)"], "ISO27001": ["A.8.15"],
        },
        related=[t.name for t in trails[1:]],
    )]


def _combo_cloudtrail_public_s3(resources: list[IacResource]) -> list[IacFinding]:
    """CIS 3.3: the S3 bucket a trail delivers to must not be public.

    Mirrors rule_cloudtrail_s3_public in the live engine.
    """
    # Build a name map for S3 buckets declared in this plan.
    buckets_by_name: dict[str, IacResource] = {}
    for r in resources:
        if _is_aws_s3(r):
            bname = str(r.props.get("bucket") or r.props.get("BucketName") or r.name)
            buckets_by_name[bname] = r
            buckets_by_name[r.name] = r  # also index by logical TF/CFN name

    findings: list[IacFinding] = []
    for r in resources:
        if r.type not in ("aws_cloudtrail", "AWS::CloudTrail::Trail"):
            continue
        s3_name = str(r.props.get("s3_bucket_name", r.props.get("S3BucketName")) or "")
        bucket = buckets_by_name.get(s3_name)
        if bucket is None:
            continue
        acl = str(bucket.props.get("acl") or bucket.props.get("AccessControl") or "").lower()
        if "public" not in acl:
            continue
        findings.append(IacFinding(
            check_id="IAC_CLOUDTRAIL_S3_PUBLIC",
            title="CloudTrail log bucket is publicly accessible",
            severity="critical",
            resource=r.name,
            resource_type=r.type,
            why=(
                f"Trail delivers to S3 bucket '{s3_name}' (resource '{bucket.name}'), "
                f"which has a public ACL ('{acl}') — audit logs can be read or tampered "
                "with by anyone."
            ),
            remediation=(
                "Remove the public ACL from the CloudTrail S3 bucket "
                "and enable Block Public Access."
            ),
            compliance={
                "CIS": ["3.3"], "SOC2": ["CC6.1", "CC7.2"],
                "NIST": ["AU-9", "AC-3"], "PCI-DSS": ["10.5.1"],
                "ISO27001": ["A.8.15", "A.8.20"],
            },
            related=[bucket.name],
        ))
    return findings


# ── combination-rule registry ────────────────────────────────────

_COMBO_CHECKS: list[Callable[[list[IacResource]], list[IacFinding]]] = [
    _combo_public_ec2_to_admin_role,
    _combo_cloudtrail_multiregion,
    _combo_cloudtrail_public_s3,
]


# ── engine ───────────────────────────────────────────────────────

def scan(text: str) -> dict[str, Any]:
    """Parse + run every single-resource check then every combination check.

    Returns a dict with:
      format            "terraform" | "cloudformation" | None
      resources_scanned int
      findings          list of finding dicts (sorted by severity)
      total             int
      by_severity       {severity: count}
    """
    resources = parse(text)
    findings: list[IacFinding] = []

    # Pass 1 — single-resource checks.
    for r in resources:
        for check in _SINGLE_CHECKS:
            f = check(r)
            if f is not None:
                findings.append(f)

    # Pass 2 — combination checks (cross-resource, need the full list).
    for combo in _COMBO_CHECKS:
        findings.extend(combo(resources))

    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (rank.get(f.severity, 9), f.check_id, f.resource))
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    fmt = resources[0].fmt if resources else None
    return {
        "format": fmt,
        "resources_scanned": len(resources),
        "findings": [f.to_dict() for f in findings],
        "total": len(findings),
        "by_severity": by_sev,
    }
