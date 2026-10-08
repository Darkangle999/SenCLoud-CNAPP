"""AWS cloud misconfiguration scanning via Trivy (CSPM engine #2).

The in-tree ``inventory/rules.py`` engine is Odineyes' own posture model.
Trivy ``aws`` (aquasecurity/trivy) is a complementary engine with ~200 built-in
AWS checks (AVD-AWS-*) maintained by Aqua's security researchers. This module
runs the *real* trivy binary against a customer account and adapts its FAIL
misconfigurations into the same finding shape the rest of the product persists,
so Trivy coverage and native rules land in one findings list.

Design mirrors ``cloud/trivy_scanner.py`` (the image/VM scanner):

  * read-only, subprocess ``trivy aws --format json``
  * temp assumed-role credentials flow to the child via its environment only
    (never logged, never on the CLI)
  * ``available()`` False or any failure => the step is **skipped, never faked**,
    and stale Trivy findings are *not* resolved on a failed run
  * the JSON parser is pure and fixture-tested - it needs neither the binary
    nor AWS
  * ``--skip-policy-update`` pins the embedded policy bundle so two runs of the
    same release report the same check IDs (deterministic CI/UI)

That policy-bundle choice is deliberate but worth naming: Trivy normally
re-pulls the bundle from GHCR every 24h. The runtime engine wants stability, so
this scanner keeps the shipped bundle until the Odineyes release is redeployed.
Bump the pin by dropping the flag when you want the newest Aqua policies daily.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

import boto3

logger = logging.getLogger(__name__)

# Bound, but generous: `trivy aws` fans across every enabled region and dozens
# of services. Configurable so an operator can squeeze the budget on a small
# host, and capped so a stuck run can never hang the scan worker forever.
_DEFAULT_TIMEOUT = 900
_MAX_TIMEOUT = 3600

_SEV_RANK = {"critical", "high", "medium", "low"}

# trivy "Service" tag -> Odineyes normalized asset_type. Only the services
# whose normalized names we know are mapped; anything else keeps a faithful
# ``aws.<service>.resource`` derived name so the finding still carries truth.
_SERVICE_ASSET_TYPE = {
    "s3": "aws.s3.bucket",
    "iam": "aws.iam.role",
    "ec2": "aws.ec2.instance",
    "ecr": "aws.ecr.repository",
    "ecs": "aws.ecs.cluster",
    "eks": "aws.eks.cluster",
    "rds": "aws.rds.db_instance",
    "lambda": "aws.lambda.function",
    "cloudtrail": "aws.cloudtrail.trail",
    "cloudwatch": "aws.cloudwatch.log_group",
    "kms": "aws.kms.key",
    "redshift": "aws.redshift.cluster",
    "sns": "aws.sns.topic",
    "sqs": "aws.sqs.queue",
    "dynamodb": "aws.dynamodb.table",
    "vpc": "aws.ec2.vpc",
    "elasticloadbalancingv2": "aws.elasticloadbalancingv2.load_balancer",
    "efs": "aws.efs.file_system",
    "guardduty": "aws.guardduty.detector",
    "config": "aws.config.recorder",
    "secretsmanager": "aws.secretsmanager.secret",
    "apigateway": "aws.apigateway.rest_api",
    "autoscaling": "aws.autoscaling.group",
}


@dataclass
class TrivyMisconfigFinding:
    """One FAIL misconfiguration reported by ``trivy aws`` for one resource."""

    rule_id: str          # e.g. AVD-AWS-0086
    title: str
    severity: str         # critical | high | medium | low
    why: str              # Trivy Description (+ PrimaryURL appended by adapter)
    remediation: str      # Trivy Resolution
    primary_url: str = ""
    status: str = "FAIL"


@dataclass
class TrivyMisconfigResult:
    """One scanned resource (identified by ARN) and the checks that failed on it."""

    resource_id: str      # resource ARN / ID as reported by trivy
    asset_type: str       # normalized to the Odineyes inventory naming
    service: str
    region: str
    name: str
    findings: list[TrivyMisconfigFinding] = field(default_factory=list)


def available() -> bool:
    """True iff the trivy binary exists on PATH. `aws` is a subcommand of the
    same binary, so a present binary is sufficient."""
    return shutil.which("trivy") is not None


def misconfig_timeout() -> int:
    raw = os.environ.get("ODINEYES_TRIVY_MISCONFIG_TIMEOUT", str(_DEFAULT_TIMEOUT))
    try:
        return min(_MAX_TIMEOUT, max(60, int(raw)))
    except ValueError:
        return _DEFAULT_TIMEOUT


def _child_aws_env(session: boto3.Session, region: Optional[str]) -> tuple[Optional[dict[str, str]], str]:
    """Build an isolated AWS environment for the trivy child process from the
    given (already assumed-role) boto3 session.

    Removes profile selectors so a local developer profile cannot override the
    temporary role credentials selected by the backend (mirrors
    ``trivy_scanner._aws_child_env``). Never logs credential material.
    """
    try:
        credentials = session.get_credentials()
        frozen = credentials.get_frozen_credentials() if credentials else None
    except Exception as exc:  # noqa: BLE001 - a skipped scan is safer than ambient fallback
        return None, f"could not load scan credentials: {exc}"
    if not frozen or not frozen.access_key or not frozen.secret_key:
        return None, "scan session has no usable AWS credentials"
    env = os.environ.copy()
    env.pop("AWS_PROFILE", None)
    env.pop("AWS_DEFAULT_PROFILE", None)
    env["AWS_ACCESS_KEY_ID"] = frozen.access_key
    env["AWS_SECRET_ACCESS_KEY"] = frozen.secret_key
    if frozen.token:
        env["AWS_SESSION_TOKEN"] = frozen.token
    if region:
        env["AWS_REGION"] = region
        env["AWS_DEFAULT_REGION"] = region
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    return env, ""


def _asset_type_for(service: str, raw_type: str) -> str:
    """Best-effort normalized asset_type from trivy's report envelope."""
    svc = (service or "").lower()
    if svc in _SERVICE_ASSET_TYPE:
        return _SERVICE_ASSET_TYPE[svc]
    # raw Type is often "aws-s3-bucket"; derive svc from it.
    t = (raw_type or "").lower().removeprefix("aws-")
    svc2 = t.split("-")[0] if t else ""
    return _SERVICE_ASSET_TYPE.get(svc2, f"aws.{svc or svc2 or 'resource'}.resource")


def _normalize_finding(mc: dict[str, Any]) -> Optional[TrivyMisconfigFinding]:
    """One trivy misconfiguration entry -> a finding. Only FAIL entries count;
    PASS/UNKNOWN describe healthy resources and would turn into noise."""
    status = str(mc.get("Status") or "").upper()
    if status and status != "FAIL":
        return None
    sev = str(mc.get("Severity") or "").lower()
    if sev not in _SEV_RANK:
        sev = "low"  # UNKNOWN/absent severities must not inflate an alert
    return TrivyMisconfigFinding(
        rule_id=str(mc.get("ID") or mc.get("AVDID") or ""),
        title=str(mc.get("Title") or ""),
        severity=sev,
        why=str(mc.get("Description") or "") or str(mc.get("Message") or ""),
        remediation=str(mc.get("Resolution") or ""),
        primary_url=str(mc.get("PrimaryURL") or ""),
        status="FAIL",
    )


def parse_output(stdout: str) -> list[TrivyMisconfigResult]:
    """Normalize ``trivy aws --format json`` stdout (an array of per-resource
    reports) into result records. Pure - the unit-testable core.

    Each report carries ARN/ID/Name/Service/Region plus a Misconfigurations
    list; only FAIL entries become findings. Any one malformed report is
    skipped so a single odd service never voids the whole account scan.
    """
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    reports = data if isinstance(data, list) else [data]
    results: list[TrivyMisconfigResult] = []
    for rep in reports:
        if not isinstance(rep, dict):
            continue
        resource_id = str(rep.get("ARN") or rep.get("ID") or "")
        if not resource_id:
            continue
        service = str(rep.get("Service") or "")
        region = str(rep.get("Region") or "global")
        result = TrivyMisconfigResult(
            resource_id=resource_id,
            asset_type=_asset_type_for(service, str(rep.get("Type") or "")),
            service=service,
            region=region,
            name=str(rep.get("Name") or ""),
        )
        for mc in rep.get("Misconfigurations") or []:
            if not isinstance(mc, dict):
                continue
            finding = _normalize_finding(mc)
            if finding is not None:
                result.findings.append(finding)
        if result.findings:
            results.append(result)
    return results


def scan_cloud(
    session: boto3.Session,
    *,
    region: Optional[str] = None,
    services: Optional[Sequence[str]] = None,
    timeout: Optional[int] = None,
) -> tuple[list[TrivyMisconfigResult], str]:
    """Run ``trivy aws`` with the given (assumed-role) session's temporary
    credentials.

    Returns (results, "") on success. On any failure returns ([], reason) -
    never raises, never fakes. ``--skip-policy-update`` pins the embedded
    policy bundle (see module docstring).
    """
    if not available():
        return [], "trivy not installed"
    env, err = _child_aws_env(session, region)
    if env is None:
        return [], err
    cmd = ["trivy", "aws", "--format", "json",
           "--scanners", "misconfig", "--skip-policy-update", "--quiet"]
    if region:
        cmd += ["--region", region]
    for svc in services or ():
        cmd += ["--service", svc]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout or misconfig_timeout(), env=env)
    except subprocess.TimeoutExpired:
        return [], f"trivy aws timed out after {misconfig_timeout()}s"
    except Exception as exc:  # noqa: BLE001 - subprocess spawn failure => skip
        return [], f"trivy aws failed to start: {exc}"
    if proc.returncode != 0 and not (proc.stdout or "").strip():
        return [], f"trivy aws exited {proc.returncode}: {proc.stderr[:400]}"
    return parse_output(proc.stdout or ""), ""


def to_findings(results: Sequence[TrivyMisconfigResult]) -> list[Any]:
    """Flatten scan results into finding-like objects matching the contract of
    ``FindingRepository.sync`` (rule_id, resource_id, asset_type, title,
    severity, why, remediation, compliance, related, suppressed_by,
    suppressed_why). SimpleNamespace keeps it dependency-free like the CVE
    adapter in ``inventory/service.py``."""
    from types import SimpleNamespace

    out: list[Any] = []
    for res in results:
        for f in res.findings:
            out.append(SimpleNamespace(
                rule_id=f.rule_id,
                resource_id=res.resource_id,
                asset_type=res.asset_type,
                title=f.title,
                severity=f.severity,
                why=(f.why or f.title) + (f"\nReference: {f.primary_url}" if f.primary_url else ""),
                remediation=f.remediation,
                compliance={},
                related=[],
                suppressed_by="",
                suppressed_why="",
            ))
    return out


if __name__ == "__main__":
    # Offline self-check of the pure parser/adapter (no trivy, no AWS).
    sample = json.dumps([
        {
            "Type": "aws-s3-bucket", "ARN": "arn:aws:s3:::data", "Name": "data",
            "Service": "s3", "Region": "us-east-1",
            "Misconfigurations": [
                {"ID": "AVD-AWS-0086", "Title": "S3 public ACL",
                 "Description": "Bucket grants public access.", "Resolution": "Remove it.",
                 "Severity": "CRITICAL", "Status": "FAIL",
                 "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0086"},
                {"ID": "AVD-AWS-0020", "Title": "S3 logging",
                 "Severity": "MEDIUM", "Status": "PASS"},
            ],
        },
        {"Type": "aws-iam", "ARN": "arn:aws:iam::123:role/r",
         "Service": "iam", "Region": "global",
         "Misconfigurations": [
             {"ID": "AVD-AWS-0057", "Title": "wildcard", "Severity": "UNKNOWN", "Status": "FAIL"},
         ]},
    ])
    parsed = parse_output(sample)
    assert len(parsed) == 2, parsed
    assert parsed[0].findings[0].rule_id == "AVD-AWS-0086"
    assert parsed[0].findings[0].severity == "critical"
    assert parsed[0].asset_type == "aws.s3.bucket"
    assert parsed[1].asset_type == "aws.iam.role"
    assert parsed[1].findings[0].severity == "low", "UNKNOWN severity must not inflate"
    adapted = to_findings(parsed)
    assert len(adapted) == 2
    assert adapted[0].rule_id == "AVD-AWS-0086" and adapted[0].severity == "critical"
    assert "Reference:" in adapted[0].why
    print("trivy_misconfig self-check OK")
