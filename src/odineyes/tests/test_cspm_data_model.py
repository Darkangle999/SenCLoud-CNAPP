"""Contract tests for the relational CSPM evidence model."""

from __future__ import annotations

from sqlalchemy import inspect, select

from odineyes.db.base import init_db, session_scope
from odineyes.db.models import Asset, Issue, IssueHop, ScanScope
from odineyes.inventory.issues import Issue as EvaluatedIssue
from odineyes.inventory.repository import (
    AccountRepository,
    IssueRepository,
    ScanJobRepository,
)
from odineyes.inventory.service import InventoryService


ACCOUNT = "123456789012"


def _s3(name: str) -> tuple[str, dict]:
    return "s3:bucket", {
        "Name": name,
        "Region": "us-east-1",
        "PublicAccessBlock": {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        },
        "Encryption": {"enabled": True, "algorithm": "AES256"},
    }


def test_scan_scope_and_asset_observation_are_persisted(tmp_path):
    url = f"sqlite:///{tmp_path}/model.db"
    service = InventoryService(database_url=url)

    result = service.persist_scan(
        "aws", ACCOUNT, [_s3("evidence-bucket")],
        authoritative_scopes={("s3:bucket", "us-east-1")},
    )

    with session_scope(url) as session:
        asset = session.execute(select(Asset)).scalar_one()
        scope = session.execute(select(ScanScope)).scalar_one()
        assert asset.last_seen_scan_id == result.scan_job_id
        assert (scope.source_type, scope.region, scope.status, scope.resource_count) == (
            "s3:bucket", "us-east-1", "complete", 1,
        )


def test_issue_path_is_normalized_into_queryable_hops(tmp_path):
    url = f"sqlite:///{tmp_path}/model.db"
    init_db(url)
    resource_id = "arn:aws:ec2:us-east-1:123456789012:instance/i-exposed"

    with session_scope(url) as session:
        account = AccountRepository.get_or_create(session, "aws", ACCOUNT)
        job = ScanJobRepository.create(session, account)
        ScanJobRepository.start(job)
        asset = Asset(
            account_id=account.id, resource_id=resource_id, cloud_provider="aws",
            asset_type="aws.ec2.instance", region="us-east-1", tags={}, raw={},
            normalized={}, properties={}, relationships={}, last_seen_scan_id=job.id,
        )
        session.add(asset)
        session.flush()

        evaluated = EvaluatedIssue(
            issue_type="PUBLIC_COMPUTE_TO_DATA",
            title="Public workload reaches data",
            severity="critical",
            risk_score=95.0,
            resource_id=resource_id,
            why="Public entry point reaches a sensitive bucket.",
            remediation="Remove public exposure.",
            path=[
                {"id": "internet", "kind": "external", "name": "Internet"},
                {"id": resource_id, "kind": "compute", "name": "i-exposed"},
            ],
            evidence=[{"source": "test", "observation": "public", "effect": "entry"}],
        )
        IssueRepository.sync(session, account, [evaluated], {resource_id: asset.last_scanned_at})
        session.flush()

        issue = session.execute(select(Issue)).scalar_one()
        hops = session.execute(
            select(IssueHop).where(IssueHop.issue_id == issue.id).order_by(IssueHop.hop_order)
        ).scalars().all()
        assert issue.entry_asset_id == asset.id
        assert issue.evidence == evaluated.evidence
        assert [(hop.node_id, hop.asset_id) for hop in hops] == [
            ("internet", None),
            (resource_id, asset.id),
        ]


def test_schema_exposes_relational_evidence_tables_and_foreign_keys(tmp_path):
    url = f"sqlite:///{tmp_path}/model.db"
    engine = init_db(url)
    inspector = inspect(engine)

    assert {"scan_scopes", "issue_hops"}.issubset(inspector.get_table_names())
    assert "last_seen_scan_id" in {c["name"] for c in inspector.get_columns("assets")}
    assert "asset_id" in {c["name"] for c in inspector.get_columns("findings")}
    assert "entry_asset_id" in {c["name"] for c in inspector.get_columns("issues")}
    assert any(fk["referred_table"] == "assets" for fk in inspector.get_foreign_keys("issue_hops"))
