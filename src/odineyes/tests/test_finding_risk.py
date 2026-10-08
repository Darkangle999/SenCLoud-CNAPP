"""§4.2 + §4.5: list_findings folds asset exposure + DSPM sensitivity into a
risk_score, flags the public+sensitive toxic combo, and ranks by it. The
resource_id↔store_id format join (arn:aws:s3::: vs s3://) must line up.
"""

from __future__ import annotations

import os

import pytest

from odineyes.db.base import init_db, session_scope
from odineyes.db.models import Asset, DspmFinding, Finding
from odineyes.inventory.repository import AccountRepository
from odineyes.inventory import queries


@pytest.fixture()
def db(tmp_path):
    url = f"sqlite:///{tmp_path}/risk.db"
    os.environ["ODINEYES_DATABASE_URL"] = url
    init_db(url)
    return url


def _finding(aid, rid, sev="high", rule="PUBLIC_BUCKET"):
    return Finding(account_id=aid, rule_id=rule, resource_id=rid,
                   asset_type="aws.s3.bucket", title="t", severity=sev,
                   why="w", remediation="r")


def test_public_plus_pii_is_elevated_and_ranks_first(db):
    with session_scope() as s:
        acct = AccountRepository.get_or_create(s, "aws", "111122223333")
        aid = acct.id
        # Bucket "pii": public asset + CRITICAL DSPM. Stored in the two id formats.
        s.add(Asset(account_id=aid, resource_id="arn:aws:s3:::pii",
                    cloud_provider="aws", asset_type="aws.s3.bucket",
                    network_exposure="public"))
        s.add(DspmFinding(account_id=aid, store_id="s3://pii", label="CRITICAL",
                          taxonomies=["PII"]))
        # Bucket "plain": private, no data. Higher raw severity.
        s.add(Asset(account_id=aid, resource_id="arn:aws:s3:::plain",
                    cloud_provider="aws", asset_type="aws.s3.bucket",
                    network_exposure="private"))
        s.add(_finding(aid, "arn:aws:s3:::pii", sev="high"))
        s.add(_finding(aid, "arn:aws:s3:::plain", sev="critical"))
        s.flush()

        out = queries.list_findings(s, account_id=aid)
        by_rid = {f["resource_id"]: f for f in out["items"]}

        pii, plain = by_rid["arn:aws:s3:::pii"], by_rid["arn:aws:s3:::plain"]
        # Cross-signal join worked despite the arn/s3:// format mismatch.
        assert pii["data_sensitivity"]["label"] == "CRITICAL"
        assert pii["elevated"] is True and plain["elevated"] is False
        # public+critical high outranks a plain private critical.
        assert pii["risk_score"] > plain["risk_score"]
        assert out["items"][0]["resource_id"] == "arn:aws:s3:::pii"
        # A finding with no DSPM match carries no data_sensitivity key.
        assert "data_sensitivity" not in plain
