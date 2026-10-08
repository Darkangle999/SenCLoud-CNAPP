"""Trivy AWS misconfig engine: parser/adapter purity + pipeline integration.

The parser needs neither the trivy binary nor AWS (fixture-tested). The
integration tests prove the two safety invariants the engine depends on:

  1. a skipped/failed Trivy run never touches existing findings;
  2. a Trivy-only sync resolves stale ``AVD-*`` findings but can NEVER resolve
     a native finding it did not evaluate (``resolve_prefix`` scoping).
"""

from __future__ import annotations

import json

from sqlalchemy import select

from odineyes.cloud import trivy_misconfig

ACCOUNT = "123456789012"


def _payload() -> str:
    return json.dumps([
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


def test_parse_output_normalizes_aws_json():
    parsed = trivy_misconfig.parse_output(_payload())
    assert [r.resource_id for r in parsed] == [
        "arn:aws:s3:::data", "arn:aws:iam::123:role/r"]
    assert parsed[0].asset_type == "aws.s3.bucket"
    assert parsed[0].region == "us-east-1"
    assert [f.rule_id for f in parsed[0].findings] == ["AVD-AWS-0086"]
    assert parsed[0].findings[0].severity == "critical"


def test_parse_output_skips_pass_and_downgrades_unknown_severity():
    parsed = trivy_misconfig.parse_output(_payload())
    iam = parsed[1]
    assert iam.asset_type == "aws.iam.role"
    assert iam.findings[0].severity == "low", "UNKNOWN must not inflate an alert"



def _service(tmp_path):
    from odineyes.inventory.service import InventoryService

    url = f"sqlite:///{tmp_path}/misconfig.db"
    return InventoryService(database_url=url), url


def _finding_row(url, rule_id: str, resource_id: str, status: str = "open") -> None:
    from odineyes.db.base import session_scope
    from odineyes.db.models import CloudAccount, Finding

    with session_scope(url) as s:
        acct = s.query(CloudAccount).filter(
            CloudAccount.provider == "aws",
            CloudAccount.account_identifier == ACCOUNT).one()
        s.add(Finding(
            account_id=acct.id, rule_id=rule_id, resource_id=resource_id,
            asset_type="aws.s3.bucket", title="t", severity="high",
            status=status, why="w", remediation="r",
        ))


def _finding_status(url, rule_id: str):
    from odineyes.db.base import session_scope
    from odineyes.db.models import CloudAccount, Finding

    with session_scope(url) as s:
        acct = s.query(CloudAccount).filter(
            CloudAccount.provider == "aws",
            CloudAccount.account_identifier == ACCOUNT).one()
        row = s.execute(
            select(Finding).where(
                Finding.account_id == acct.id, Finding.rule_id == rule_id)
        ).scalars().one()
        return row.status


def test_engine_skips_without_touching_findings(tmp_path, monkeypatch):
    """Trivy absent -> skipped result AND the findings table is untouched."""
    svc, url = _service(tmp_path)
    svc.persist_scan("aws", ACCOUNT, [("s3:bucket", {"Name": "data", "Region": "us-east-1"})])
    _finding_row(url, "AVD-AWS-0086", "arn:aws:s3:::data")
    monkeypatch.setattr(trivy_misconfig, "available", lambda: False)

    out = svc.scan_trivy_misconfig("aws", ACCOUNT)

    assert out["status"] == "skipped"
    assert _finding_status(url, "AVD-AWS-0086") == "open"


def test_sync_resolves_stale_avd_but_never_native(tmp_path, monkeypatch):
    """A successful empty Trivy scan resolves only the AVD-* family."""
    svc, url = _service(tmp_path)
    svc.persist_scan("aws", ACCOUNT, [("s3:bucket", {"Name": "data", "Region": "us-east-1"})])
    _finding_row(url, "AVD-AWS-0086", "arn:aws:s3:::data")
    _finding_row(url, "PUBLIC_BUCKET", "arn:aws:s3:::data")

    monkeypatch.setattr(trivy_misconfig, "available", lambda: True)
    monkeypatch.setattr(trivy_misconfig, "scan_cloud", lambda *a, **k: ([], ""))

    out = svc.scan_trivy_misconfig("aws", ACCOUNT)

    assert out["status"] == "completed"
    assert _finding_status(url, "AVD-AWS-0086") == "resolved"
    assert _finding_status(url, "PUBLIC_BUCKET") == "open"


def test_completed_scan_persists_avd_findings(tmp_path, monkeypatch):
    svc, url = _service(tmp_path)
    svc.persist_scan("aws", ACCOUNT, [("s3:bucket", {"Name": "data", "Region": "us-east-1"})])
    parsed = trivy_misconfig.parse_output(_payload())

    monkeypatch.setattr(trivy_misconfig, "available", lambda: True)
    monkeypatch.setattr(trivy_misconfig, "scan_cloud", lambda *a, **k: (parsed, ""))

    out = svc.scan_trivy_misconfig("aws", ACCOUNT)

    assert out["status"] == "completed" and out["findings"] == 2
    assert out["by_severity"] == {"critical": 1, "low": 1}
    assert _finding_status(url, "AVD-AWS-0086") == "open"
    assert _finding_status(url, "AVD-AWS-0057") == "open"

def test_parse_output_returns_empty_on_garbage():
    assert trivy_misconfig.parse_output("not json at all") == []


def test_to_findings_matches_finding_like_contract():
    adapted = trivy_misconfig.to_findings(trivy_misconfig.parse_output(_payload()))
    for f in adapted:
        for attr in ("rule_id", "resource_id", "asset_type", "title", "severity",
                     "why", "remediation", "compliance", "related",
                     "suppressed_by", "suppressed_why"):
            assert hasattr(f, attr), attr
    assert adapted[0].suppressed_by == "" and adapted[0].compliance == {}
    assert "avd.aquasec.com" in adapted[0].why


def test_scan_cloud_skips_without_binary(monkeypatch):
    monkeypatch.setattr(trivy_misconfig, "available", lambda: False)
    results, reason = trivy_misconfig.scan_cloud(object(), region="us-east-1")
    assert results == [] and "not installed" in reason
