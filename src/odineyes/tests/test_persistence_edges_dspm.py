"""Persisted graph edges + DSPM findings — lifecycle + read queries (sqlite).

Edges: derived from assets by AssetGraph but now persisted with an
active/soft-delete lifecycle so the attack-path backbone survives restart and
carries history. DSPM: per-store data-sensitivity, previously live-only.
"""
from __future__ import annotations

from odineyes.db.base import init_db, session_scope
from odineyes.db.models import CloudAccount
from odineyes.dspm.engine import StoreSensitivity
from odineyes.inventory import queries
from odineyes.inventory.graph import Edge
from odineyes.inventory.repository import AccountRepository, GraphEdgeRepository
from odineyes.inventory.service import InventoryService

PROV, ACCT = "aws", "111122223333"


def _account(session) -> CloudAccount:
    return AccountRepository.get_or_create(session, PROV, ACCT)


def test_edge_sync_lifecycle(tmp_path):
    init_db(f"sqlite:///{tmp_path}/edges.db")
    with session_scope() as s:
        acct = _account(s)
        stats = GraphEdgeRepository.sync(s, acct, [
            Edge("i-1", "role-a", "HAS_ROLE"),
            Edge("role-a", "s3://prod", "CAN_ACCESS", {"actions": ["s3:*"]}),
        ])
        assert (stats.new, stats.total, stats.deactivated) == (2, 2, 0)

    with session_scope() as s:
        active = queries.list_graph_edges(s, is_active=True)
        assert active["total"] == 2
        ca = next(e for e in active["items"] if e["type"] == "CAN_ACCESS")
        assert ca["properties"]["actions"] == ["s3:*"]
        first_seen = ca["first_seen_at"]

    # re-sync without the CAN_ACCESS edge -> it deactivates, HAS_ROLE refreshes
    with session_scope() as s:
        acct = _account(s)
        stats = GraphEdgeRepository.sync(s, acct, [Edge("i-1", "role-a", "HAS_ROLE")])
        assert stats.new == 0 and stats.deactivated == 1

    with session_scope() as s:
        assert queries.list_graph_edges(s, is_active=True)["total"] == 1
        gone = queries.list_graph_edges(s, is_active=False)
        assert gone["total"] == 1 and gone["items"][0]["type"] == "CAN_ACCESS"
        # history preserved: first_seen unchanged on the deactivated edge
        assert gone["items"][0]["first_seen_at"] == first_seen

    # filter by type
    with session_scope() as s:
        assert queries.list_graph_edges(s, edge_type="HAS_ROLE")["total"] == 1


def _store(store_id, risk, public, store_type="S3"):
    return StoreSensitivity(
        store_id=store_id, store_name=store_id.split("//")[-1], store_type=store_type,
        posture_findings=["public bucket"] if public else [], risk_score=risk,
        sensitivity_score=risk, exposure_score=1.0 if public else 0.3, public=public,
        record_estimate=1000,
    )


def test_dspm_persist_query_and_idempotent(tmp_path):
    init_db(f"sqlite:///{tmp_path}/dspm.db")
    svc = InventoryService(auto_init=False)
    stores = [_store("s3://prod-pii", 0.9, True), _store("rds://billing", 0.4, False, "RDS")]
    stats = svc.persist_dspm(PROV, ACCT, stores)
    assert (stats.total, stats.new) == (2, 2)

    with session_scope() as s:
        listed = queries.list_dspm(s)
        assert listed["total"] == 2
        # sorted critical-first
        assert listed["items"][0]["store_id"] == "s3://prod-pii"
        assert listed["items"][0]["label"] == "CRITICAL"
        first_seen = listed["items"][0]["first_seen_at"]

        summary = queries.dspm_summary(s)
        assert summary["total"] == 2
        assert summary["by_label"]["critical"] == 1
        assert summary["public_sensitive"] == 1  # the public CRITICAL store

        # label filter
        assert queries.list_dspm(s, label="critical")["total"] == 1
        assert queries.list_dspm(s, store_type="RDS")["total"] == 1

    # re-persist same stores -> upsert, no duplicate rows, first_seen stable
    svc.persist_dspm(PROV, ACCT, stores)
    with session_scope() as s:
        listed = queries.list_dspm(s)
        assert listed["total"] == 2
        assert listed["items"][0]["first_seen_at"] == first_seen
