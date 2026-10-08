"""DELETE /accounts/{id}?purge=true removes the account AND every trace of its
data. Soft delete (default) keeps history; purge leaves nothing behind — the
"removed account still shows data" complaint.
"""

from __future__ import annotations

import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from odineyes.db.base import init_db, session_scope
from odineyes.db.models import (
    Asset, ComplianceSnapshot, DspmFinding, Finding, GraphEdge, Vulnerability,
)
from odineyes.inventory.repository import AccountRepository


@pytest.fixture()
def client(tmp_path):
    os.environ["ODINEYES_DATABASE_URL"] = f"sqlite:///{tmp_path}/purge.db"
    init_db(os.environ["ODINEYES_DATABASE_URL"])
    from odineyes.api.inventory_routes import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _seed(ident="111122223333"):
    with session_scope() as s:
        acct = AccountRepository.get_or_create(s, "aws", ident)
        aid = acct.id
        s.add(Asset(account_id=aid, resource_id="arn:aws:s3:::b", cloud_provider="aws",
                    asset_type="aws.s3.bucket"))
        s.add(Finding(account_id=aid, rule_id="PUBLIC_BUCKET", resource_id="arn:aws:s3:::b",
                      asset_type="aws.s3.bucket", title="t", severity="high", why="w", remediation="r"))
        s.add(Vulnerability(account_id=aid, resource_id="i-1", cve_id="CVE-1", package="p", severity="high"))
        s.add(GraphEdge(account_id=aid, src_id="internet", dst_id="arn:aws:s3:::b", edge_type="EXPOSED_TO"))
        s.add(DspmFinding(account_id=aid, store_id="s3://b", label="HIGH"))
        s.add(ComplianceSnapshot(framework="CIS", account=ident, score=50, passing=1, total=2))
        s.flush()
        return aid, ident


def _counts(aid, ident):
    with session_scope() as s:
        return {
            "assets": s.query(Asset).filter_by(account_id=aid).count(),
            "findings": s.query(Finding).filter_by(account_id=aid).count(),
            "vulns": s.query(Vulnerability).filter_by(account_id=aid).count(),
            "edges": s.query(GraphEdge).filter_by(account_id=aid).count(),
            "dspm": s.query(DspmFinding).filter_by(account_id=aid).count(),
            "compliance": s.query(ComplianceSnapshot).filter_by(account=ident).count(),
        }


def test_purge_removes_account_and_all_data(client):
    aid, ident = _seed()
    assert sum(_counts(aid, ident).values()) == 6   # seeded

    r = client.delete(f"/api/inventory/accounts/{aid}?purge=true")
    assert r.status_code == 200 and r.json()["purged"] is True

    assert _counts(aid, ident) == {
        "assets": 0, "findings": 0, "vulns": 0, "edges": 0, "dspm": 0, "compliance": 0,
    }
    # account row itself gone (not just deactivated).
    assert client.get("/api/inventory/accounts").json()["items"] == []


def test_default_delete_is_soft(client):
    aid, ident = _seed("222233334444")
    r = client.delete(f"/api/inventory/accounts/{aid}")   # no purge
    assert r.status_code == 200 and r.json()["is_active"] is False
    # data retained.
    assert _counts(aid, ident)["assets"] == 1


def test_sqlite_enforces_fk_cascade_at_db_level(client):
    # PRAGMA foreign_keys is ON and ON DELETE CASCADE fires even on a RAW account
    # delete (not just the ORM path) — no orphaned child rows can survive.
    from sqlalchemy import text
    from odineyes.db.base import get_engine

    aid, _ = _seed("777788889999")
    with get_engine().connect() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
        conn.execute(text("DELETE FROM cloud_accounts WHERE id = :i"), {"i": aid})
        conn.commit()
        for tbl in ("assets", "findings", "vulnerabilities", "graph_edges", "dspm_findings"):
            n = conn.exec_driver_sql(f"SELECT count(*) FROM {tbl} WHERE account_id = {aid}").scalar()
            assert n == 0, f"{tbl} left orphans after raw account delete"
