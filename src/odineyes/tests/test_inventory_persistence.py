"""Phase 1 persistence spine — Definition-of-Done coverage.

Runs against an isolated sqlite file per test (same models/codepath as Postgres).
Asserts: idempotent rescans, drift events, soft-delete, reactivation, per-resource
error isolation, and S3 public detection.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from odineyes.db.base import get_sessionmaker
from odineyes.db.models import Asset, AssetEvent, ScanError, ScanJob
from odineyes.inventory.collection import CollectionError
from odineyes.inventory.normalizers import normalize_ec2_instance, normalize_s3_bucket
from odineyes.inventory.orchestrator import AccountRef, MultiAccountOrchestrator
from odineyes.inventory.service import InventoryService

ACCOUNT = "123456789012"


def s3_raw(name: str, *, public: bool = False, encrypted: bool = True, region: str = "us-east-1") -> dict:
    blocked = {
        "BlockPublicAcls": True, "BlockPublicPolicy": True,
        "IgnorePublicAcls": True, "RestrictPublicBuckets": True,
    }
    return {
        "Name": name,
        "Region": region,
        "PolicyStatus": {"IsPublic": public},
        "Encryption": {"enabled": encrypted, "algorithm": "AES256"},
        "Versioning": "Enabled",
        "PublicAccessBlock": {} if public else blocked,
        "Tags": {"env": "prod"},
    }


def res(name: str, **kw) -> tuple[str, dict]:
    return ("s3:bucket", s3_raw(name, **kw))


@pytest.fixture()
def service(tmp_path):
    url = f"sqlite:///{tmp_path}/inventory.db"
    return InventoryService(database_url=url), url


def _count(url, model) -> int:
    Session = get_sessionmaker(url)
    with Session() as s:
        return s.execute(select(func.count()).select_from(model)).scalar_one()


def _events(url, event_type: str) -> int:
    Session = get_sessionmaker(url)
    with Session() as s:
        return s.execute(
            select(func.count()).select_from(AssetEvent).where(AssetEvent.event_type == event_type)
        ).scalar_one()


def test_first_scan_creates_assets(service):
    svc, url = service
    result = svc.persist_scan("aws", ACCOUNT, [res("alpha"), res("beta")])

    assert (result.found, result.new, result.changed, result.deleted) == (2, 2, 0, 0)
    assert result.status == "completed"
    assert _count(url, Asset) == 2
    assert _events(url, "created") == 2
    assert _count(url, ScanJob) == 1


def test_idempotent_rescan_changes_nothing(service):
    svc, url = service
    svc.persist_scan("aws", ACCOUNT, [res("alpha"), res("beta")])
    second = svc.persist_scan("aws", ACCOUNT, [res("alpha"), res("beta")])

    # Same input → no new assets, no drift, no deletions.
    assert (second.new, second.changed, second.deleted) == (0, 0, 0)
    assert _count(url, Asset) == 2
    assert _events(url, "created") == 2       # not 4
    assert _events(url, "config_change") == 0


def test_drift_is_recorded(service):
    svc, url = service
    svc.persist_scan("aws", ACCOUNT, [res("alpha", public=False)])
    result = svc.persist_scan("aws", ACCOUNT, [res("alpha", public=True)])

    assert result.changed == 1
    assert _events(url, "config_change") == 1

    Session = get_sessionmaker(url)
    with Session() as s:
        asset = s.execute(select(Asset).where(Asset.resource_id == "arn:aws:s3:::alpha")).scalar_one()
        assert asset.is_public is True
        event = s.execute(
            select(AssetEvent).where(AssetEvent.event_type == "config_change")
        ).scalar_one()
        assert event.previous_value["is_public"] is False
        assert event.new_value["is_public"] is True


def test_missing_resource_is_soft_deleted(service):
    svc, url = service
    svc.persist_scan("aws", ACCOUNT, [res("alpha"), res("beta")])
    result = svc.persist_scan("aws", ACCOUNT, [res("alpha")])  # beta gone

    assert result.deleted == 1
    assert _events(url, "deleted") == 1

    Session = get_sessionmaker(url)
    with Session() as s:
        beta = s.execute(select(Asset).where(Asset.resource_id == "arn:aws:s3:::beta")).scalar_one()
        alpha = s.execute(select(Asset).where(Asset.resource_id == "arn:aws:s3:::alpha")).scalar_one()
        assert beta.is_active is False
        assert alpha.is_active is True
    # soft delete, not hard delete — row remains for compliance history
    assert _count(url, Asset) == 2


def test_reappearing_resource_is_reactivated(service):
    svc, url = service
    svc.persist_scan("aws", ACCOUNT, [res("alpha"), res("beta")])
    svc.persist_scan("aws", ACCOUNT, [res("alpha")])            # beta soft-deleted
    result = svc.persist_scan("aws", ACCOUNT, [res("alpha"), res("beta")])  # beta back

    assert result.reactivated == 1
    assert _events(url, "reactivated") == 1
    Session = get_sessionmaker(url)
    with Session() as s:
        beta = s.execute(select(Asset).where(Asset.resource_id == "arn:aws:s3:::beta")).scalar_one()
        assert beta.is_active is True


def test_partial_collection_retires_only_authoritative_scope(service):
    svc, url = service
    svc.persist_scan(
        "aws", ACCOUNT,
        [res("east", region="us-east-1"), res("west", region="eu-west-1")],
    )

    result = svc.persist_scan(
        "aws",
        ACCOUNT,
        [],
        authoritative_scopes={("aws.s3.bucket", "us-east-1")},
        collection_errors=[CollectionError(
            source_type="aws.s3.bucket",
            operation="s3.list_buckets",
            region="eu-west-1",
            message="AccessDenied",
        )],
    )

    assert result.deleted == 1
    assert result.errors == 1
    assert result.partial is True
    Session = get_sessionmaker(url)
    with Session() as s:
        east = s.execute(select(Asset).where(Asset.resource_id.endswith(":east"))).scalar_one()
        west = s.execute(select(Asset).where(Asset.resource_id.endswith(":west"))).scalar_one()
        assert east.is_active is False
        assert west.is_active is True


def test_duplicate_rows_in_one_scan_are_deduplicated(service):
    svc, url = service
    result = svc.persist_scan("aws", ACCOUNT, [res("alpha"), res("alpha")])

    assert (result.found, result.new) == (1, 1)
    assert _count(url, Asset) == 1
    assert _events(url, "created") == 1


def test_account_scoped_resource_ids_do_not_collide(service):
    svc, url = service
    raw = {"InstanceId": "i-shared", "Region": "us-east-1", "State": {"Name": "running"}}
    first = normalize_ec2_instance(raw, ACCOUNT)
    second = normalize_ec2_instance(raw, "999999999999")

    svc.persist_normalized("aws", ACCOUNT, [first])
    svc.persist_normalized("aws", "999999999999", [second])

    assert _count(url, Asset) == 2


def test_bad_resource_does_not_fail_job(service):
    svc, url = service
    bad = ("s3:bucket", {"Region": "us-east-1"})        # missing Name
    unknown = ("ec2:instance", {"name": "i-123"})       # no normalizer yet
    result = svc.persist_scan("aws", ACCOUNT, [res("alpha"), bad, unknown])

    assert result.status == "completed"   # job still completes
    assert result.found == 1              # only alpha persisted
    assert result.errors == 2
    assert _count(url, ScanError) == 2
    assert _count(url, Asset) == 1


def test_failed_persistence_keeps_failed_job_for_diagnostics(service):
    svc, url = service
    wrong_tenant = normalize_s3_bucket(s3_raw("alpha"), "999999999999")

    with pytest.raises(ValueError, match="tenant/provider"):
        svc.persist_normalized("aws", ACCOUNT, [wrong_tenant])

    Session = get_sessionmaker(url)
    with Session() as s:
        job = s.execute(select(ScanJob)).scalar_one()
        assert job.status == "failed"
        assert job.error_count == 1
        assert s.execute(select(ScanError)).scalar_one().scan_job_id == job.id


def test_preflight_failure_is_visible_as_a_failed_scan_job(service):
    """AssumeRole/collection failures occur before there are raw resources.

    They still need a durable job for the Accounts UI to render an actionable
    status rather than an empty dashboard.
    """
    svc, url = service

    def denied_session(_account):
        raise RuntimeError("AccessDenied: not authorized to perform sts:AssumeRole")

    # Injecting a collector routes session construction through the supplied
    # factory, allowing this test to simulate a pre-collection AWS failure.
    orch = MultiAccountOrchestrator(
        service=svc,
        session_factory=denied_session,
        collector_factory=lambda session, region: None,
    )
    result = orch.scan_account(AccountRef(
        ACCOUNT, "production", "arn:aws:iam::123456789012:role/OdineyesReadOnly", "aws",
    ))

    assert result.status == "failed"
    Session = get_sessionmaker(url)
    with Session() as s:
        job = s.execute(select(ScanJob)).scalar_one()
        error = s.execute(select(ScanError)).scalar_one()
        assert job.status == "failed"
        assert job.error_count == 1
        assert "AccessDenied" in error.message


def test_s3_public_detection():
    # ACL grant to AllUsers → public even without a public policy status.
    raw = {
        "Name": "acl-public",
        "Acl": {"Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]},
    }
    asset = normalize_s3_bucket(raw, ACCOUNT)
    assert asset.is_public is True
    assert asset.network_exposure == "public"
    assert asset.asset_type == "aws.s3.bucket"
    assert asset.resource_id == "arn:aws:s3:::acl-public"

    # Full public-access block overrides a public policy status.
    blocked = {
        "Name": "blocked",
        "PolicyStatus": {"IsPublic": True},
        "PublicAccessBlock": {
            "BlockPublicAcls": True, "BlockPublicPolicy": True,
            "IgnorePublicAcls": True, "RestrictPublicBuckets": True,
        },
    }
    assert normalize_s3_bucket(blocked, ACCOUNT).is_public is False
