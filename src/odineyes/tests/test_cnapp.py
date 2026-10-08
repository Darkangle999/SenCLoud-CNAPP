"""Phase 3/4/5 CNAPP-sweep tests: vulnerability lifecycle, runtime-event
persistence, and the IaC misconfiguration scanner."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from odineyes.iac.scanner import scan
from odineyes.inventory.service import InventoryService

ACCOUNT = "123456789012"


@pytest.fixture()
def svc(tmp_path):
    return InventoryService(database_url=f"sqlite:///{tmp_path}/cnapp.db")


def _vf(resource_id, cve, package, version="1.0", severity="high"):
    return SimpleNamespace(
        resource_id=resource_id, cve_id=cve, package=package,
        installed_version=version, severity=severity, cvss=7.5,
        summary=None, fixed_version="1.1",
    )


# ── vulnerabilities ────────────────────────────────────────────

def _sync_vulns(svc, vulns):
    from odineyes.db.base import session_scope
    from odineyes.inventory.repository import AccountRepository, VulnerabilityRepository
    with session_scope(svc._url) as session:
        account = AccountRepository.get_or_create(session, "aws", ACCOUNT)
        return VulnerabilityRepository.sync(session, account, vulns)


def test_vuln_sync_opens_then_idempotent(svc):
    arn = "arn:aws:ec2:us-east-1:x:instance/i-1"
    stats = _sync_vulns(svc, [_vf(arn, "CVE-2021-44228", "log4j"), _vf(arn, "CVE-2020-0001", "openssl")])
    assert stats.new == 2 and stats.total == 2
    again = _sync_vulns(svc, [_vf(arn, "CVE-2021-44228", "log4j"), _vf(arn, "CVE-2020-0001", "openssl")])
    assert again.new == 0 and again.reopened == 0 and again.resolved == 0


def test_vuln_patched_resolves_then_regresses(svc):
    arn = "arn:aws:ec2:us-east-1:x:instance/i-1"
    _sync_vulns(svc, [_vf(arn, "CVE-2021-44228", "log4j")])
    stats = _sync_vulns(svc, [])  # package patched away
    assert stats.resolved == 1
    stats = _sync_vulns(svc, [_vf(arn, "CVE-2021-44228", "log4j")])  # regression
    assert stats.reopened == 1 and stats.new == 0


def test_vuln_summary_counts_by_severity_and_assets(svc):
    a, b = "arn:...:instance/i-1", "arn:...:instance/i-2"
    _sync_vulns(svc, [_vf(a, "CVE-1", "p", severity="critical"), _vf(a, "CVE-2", "q", severity="high"),
                      _vf(b, "CVE-3", "r", severity="high")])
    from odineyes.db.base import session_scope
    from odineyes.inventory import queries
    with session_scope(svc._url) as session:
        s = queries.vulnerabilities_summary(session)
    assert s["open"] == 3 and s["affected_assets"] == 2
    assert s["by_severity"]["high"] == 2 and s["by_severity"]["critical"] == 1


# ── runtime events ─────────────────────────────────────────────

def test_runtime_event_persist_and_list(svc):
    from odineyes.db.base import session_scope
    from odineyes.inventory import queries
    from odineyes.inventory.repository import RuntimeEventRepository
    with session_scope(svc._url) as session:
        RuntimeEventRepository.record(
            session, event_type="process_execution", severity="medium",
            workload="web-1", process="curl /usr/bin/curl", pid=4242, raw={"container": "web-1"},
        )
    with session_scope(svc._url) as session:
        listing = queries.list_runtime_events(session)
        summary = queries.runtime_events_summary(session)
    assert listing["total"] == 1
    assert listing["items"][0]["workload"] == "web-1"
    assert summary["by_type"]["process_execution"] == 1


# ── IaC scanner ────────────────────────────────────────────────

def test_iac_terraform_flags_all_misconfigs():
    tf = """
    {"resource": {
      "aws_s3_bucket": {"b": {"acl": "public-read"}},
      "aws_security_group": {"sg": {"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]}},
      "aws_iam_role_policy": {"p": {"policy": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}}
    }}
    """
    r = scan(tf)
    ids = {f["check_id"] for f in r["findings"]}
    assert r["format"] == "terraform"
    assert {"IAC_S3_PUBLIC_ACL", "IAC_SG_WORLD_OPEN", "IAC_IAM_WILDCARD"} <= ids
    # the world-open admin port is the worst finding and sorts first
    assert r["findings"][0]["severity"] == "critical"


def test_iac_cloudformation_yaml_flags_encryption_and_acl():
    cfn = (
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      AccessControl: PublicRead\n"
        "  DB:\n"
        "    Type: AWS::RDS::DBInstance\n"
        "    Properties:\n"
        "      StorageEncrypted: false\n"
    )
    r = scan(cfn)
    ids = {f["check_id"] for f in r["findings"]}
    assert r["format"] == "cloudformation"
    assert {"IAC_S3_PUBLIC_ACL", "IAC_RDS_NO_ENCRYPTION"} <= ids


def test_iac_clean_template_has_no_findings():
    tf = '{"resource": {"aws_s3_bucket": {"ok": {"acl": "private", "server_side_encryption_configuration": {"rule": {}}}}}}'
    r = scan(tf)
    assert r["total"] == 0


def test_iac_empty_input_is_safe():
    assert scan("")["total"] == 0
    assert scan("not json or yaml :::")["resources_scanned"] == 0
