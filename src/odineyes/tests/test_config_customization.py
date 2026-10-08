"""Customization layer — control overrides, custom frameworks, custom policies.

These are the load-bearing product guarantees: an empty config scores exactly
like the stock build, and each override/custom-definition changes scoring in the
one documented way. The fixture binds the *global* engine to an isolated DB,
which is what ``config_store`` reads (it uses the no-arg session factory).
"""

from __future__ import annotations

import pytest

from odineyes.core import config_store
from odineyes.core.compliance_mapper import ComplianceMapper
from odineyes.core.policy_engine import evaluate


@pytest.fixture()
def db(tmp_path):
    # Rebinds the process-wide engine + creates all tables (incl. the 3 config
    # tables, which live in db.models so create_all picks them up).
    from odineyes.inventory.service import InventoryService
    InventoryService(database_url=f"sqlite:///{tmp_path}/cfg.db")
    yield


def _ctrl_ids(scored):
    return {c["id"] for c in scored["controls"]}


# ── default behaviour is unchanged when config is empty ───────────────────────

def test_empty_config_is_stock(db):
    out = ComplianceMapper().score([], ["CIS"])["CIS"]
    assert "2.1.1" in _ctrl_ids(out)          # curated control present
    cfg = config_store.load_config()
    assert cfg.overrides == {} and cfg.custom_frameworks == {} and cfg.custom_policies == []


# ── layer 1: control overrides ────────────────────────────────────────────────

def test_disable_drops_control_from_scoring(db):
    assert "2.1.1" in _ctrl_ids(ComplianceMapper().score([], ["CIS"])["CIS"])
    config_store.upsert_override("CIS", "2.1.1", enabled=False)
    assert "2.1.1" not in _ctrl_ids(ComplianceMapper().score([], ["CIS"])["CIS"])
    # re-enabling brings it back
    config_store.upsert_override("CIS", "2.1.1", enabled=True)
    assert "2.1.1" in _ctrl_ids(ComplianceMapper().score([], ["CIS"])["CIS"])


def test_severity_and_note_override_surface(db):
    config_store.upsert_override("CIS", "2.1.1", severity="critical", note="PCI scope")
    c = next(x for x in ComplianceMapper().score([], ["CIS"])["CIS"]["controls"] if x["id"] == "2.1.1")
    assert c["severity"] == "critical" and c["note"] == "PCI scope"


# ── layer 2: custom frameworks ────────────────────────────────────────────────

def test_custom_framework_scored_against_inline_checks(db):
    config_store.upsert_framework("ACME", name="ACME Baseline", version="1.0", controls={
        "A1": {"title": "Encrypt buckets", "section": "Data", "checks": ["chk_enc"]}})
    findings = [{"check_id": "chk_enc", "resource_id": "b", "status": "fail", "severity": "high"}]
    out = ComplianceMapper().score(findings, ["ACME"])["ACME"]
    a1 = next(c for c in out["controls"] if c["id"] == "A1")
    assert a1["state"] == "fail" and a1["checks"] == ["chk_enc"]
    assert "ACME" in config_store.available_frameworks()


# ── layer 3: custom policies (engine + control mapping) ───────────────────────

def test_policy_engine_rule_types(db):
    assets = [
        {"resource_id": "b1", "asset_type": "aws.s3.bucket", "tags": {},
         "is_public": True, "encryption_enabled": False, "network_exposure": "public"},
        {"resource_id": "b2", "asset_type": "aws.s3.bucket", "tags": {"owner": "x"},
         "is_public": False, "encryption_enabled": True, "network_exposure": "private"},
    ]
    pol = {"policy_id": "p_enc", "name": "encrypt", "severity": "high", "resource_type": "aws.s3",
           "rule": {"type": "encryption_required", "params": {}}, "frameworks": {}}
    res = {f["resource_id"]: f["status"] for f in evaluate([pol], assets)}
    assert res["b1"] == "fail" and res["b2"] == "pass"


def test_custom_policy_maps_to_control(db):
    config_store.upsert_framework("ACME", name="ACME", controls={})  # A2 is check-only
    config_store.upsert_policy("p_tag", name="Owner tag", severity="low",
                               rule={"type": "tag_required", "params": {"key": "owner"}},
                               frameworks={"ACME": ["A2"]})
    assets = [{"resource_id": "b", "asset_type": "aws.s3.bucket", "tags": {},
               "is_public": True, "encryption_enabled": False, "network_exposure": "public"}]
    findings = evaluate(config_store.load_config().custom_policies, assets)
    out = ComplianceMapper().score(findings, ["ACME"])["ACME"]
    a2 = next((c for c in out["controls"] if c["id"] == "A2"), None)
    assert a2 is not None and a2["state"] == "fail"


# ── CRUD round-trip ───────────────────────────────────────────────────────────

def test_crud_roundtrip(db):
    config_store.upsert_override("CIS", "1.5", enabled=False)
    assert any(o["control_id"] == "1.5" for o in config_store.list_overrides())
    assert config_store.delete_override("CIS", "1.5") is True
    assert config_store.delete_override("CIS", "1.5") is False  # idempotent

    config_store.upsert_policy("p1", name="P1", rule={"type": "no_public", "params": {}}, frameworks={})
    assert any(p["policy_id"] == "p1" for p in config_store.list_policies())
    assert config_store.delete_policy("p1") is True
