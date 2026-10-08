"""Source-coverage derivation — the honest-negative is the whole point, so the
checks assert the absent/degraded/healthy transitions, not just the happy path.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from odineyes.db.base import get_sessionmaker
from odineyes.db.models import Asset, CloudAccount, RuntimeEvent, Vulnerability
from odineyes.inventory.coverage import compute_coverage
from odineyes.inventory.service import InventoryService


@pytest.fixture()
def url(tmp_path):
    u = f"sqlite:///{tmp_path}/cov.db"
    InventoryService(database_url=u)  # bootstraps the schema
    return u


def _by(cov, pillar):
    return next(p for p in cov["pillars"] if p["pillar"] == pillar)


def _account(session) -> CloudAccount:
    acct = CloudAccount(provider="aws", account_identifier="123456789012")
    session.add(acct)
    session.flush()
    return acct


def test_empty_db_all_absent_or_na(url):
    with get_sessionmaker(url)() as s:
        cov = compute_coverage(s)
    assert _by(cov, "inventory")["status"] == "absent"
    assert _by(cov, "runtime")["status"] == "absent"
    assert _by(cov, "compliance")["status"] == "absent"
    # No workloads at all → vuln pillar is not_applicable, not a false "absent".
    assert _by(cov, "vulnerabilities")["status"] == "not_applicable"
    assert cov["healthy"] == 0


def test_fresh_inventory_healthy_but_vuln_degraded(url):
    now = datetime.now(timezone.utc)
    with get_sessionmaker(url)() as s:
        acct = _account(s)
        s.add(Asset(
            resource_id="arn:aws:ec2:...:i-1", cloud_provider="aws", account_id=acct.id,
            asset_type="aws.ec2.instance", region="us-east-1", last_scanned_at=now))
        s.commit()
        cov = compute_coverage(s, account_id=acct.id)
    assert _by(cov, "inventory")["status"] == "healthy"
    # EC2 present, zero CVE rows → the honest negative: scanner absent.
    assert _by(cov, "vulnerabilities")["status"] == "degraded"


def test_stale_data_degrades(url):
    old = datetime.now(timezone.utc) - timedelta(hours=48)
    with get_sessionmaker(url)() as s:
        acct = _account(s)
        s.add(Asset(
            resource_id="arn:aws:s3:::b", cloud_provider="aws", account_id=acct.id,
            asset_type="aws.s3.bucket", region="us-east-1", last_scanned_at=old))
        s.add(Vulnerability(
            account_id=acct.id, resource_id="arn:aws:ec2:...:i-1",
            cve_id="CVE-2021-1", package="openssl", severity="high", last_seen_at=old))
        s.add(RuntimeEvent(account_id=acct.id, event_type="process_execution", observed_at=old))
        s.commit()
        cov = compute_coverage(s, account_id=acct.id)
    assert _by(cov, "inventory")["status"] == "degraded"
    assert _by(cov, "vulnerabilities")["status"] == "degraded"
    assert _by(cov, "runtime")["status"] == "degraded"
