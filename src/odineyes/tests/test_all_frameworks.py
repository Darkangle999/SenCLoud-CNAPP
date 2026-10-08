"""All eight compliance frameworks are full catalogs, and the customer
customization layer (control overrides / waivers) works uniformly across every
one of them — the "flexible compliance" guarantee.

Frameworks: CIS, ISO27001, PCI-DSS, NIST, SOC2, HIPAA, GDPR, FedRAMP.
"""

from __future__ import annotations

import pytest
from pytest import fixture

from odineyes.core import config_store
from odineyes.core.compliance_mapper import FRAMEWORKS, ComplianceMapper
from odineyes.core.soa import build_soa

ALL = ["CIS", "ISO27001", "PCI-DSS", "NIST", "SOC2", "HIPAA", "GDPR", "FedRAMP"]


@pytest.fixture()
def db(tmp_path):
    from odineyes.inventory.service import InventoryService
    InventoryService(database_url=f"sqlite:///{tmp_path}/fw.db")
    yield


# ── every framework is a full catalog ─────────────────────────────────────────

def test_all_frameworks_are_substantial():
    sizes = {fw: len(FRAMEWORKS[fw]["controls"]) for fw in ALL}
    # none left as a thin stub
    assert all(n >= 14 for n in sizes.values()), sizes
    assert sizes["CIS"] == 62 and sizes["ISO27001"] == 93
    assert sizes["SOC2"] == 43 and sizes["HIPAA"] == 39


def test_no_phantom_controls_anywhere(db):
    # Every control that scoring emits must belong to its catalog — no leakage
    # from a check that maps to an id the catalog doesn't define.
    for fw in ALL:
        cat = set(FRAMEWORKS[fw]["controls"])
        ids = {c["id"] for c in ComplianceMapper().score([], [fw])[fw]["controls"]}
        assert ids <= cat, f"{fw}: phantom controls {ids - cat}"


def test_every_framework_has_automated_coverage(db):
    # Each framework auto-assesses at least one control (via per-check mapping,
    # CHECK_MAP overlay, or the FedRAMP→NIST alias).
    for fw in ALL:
        soa = build_soa(fw)
        auto = sum(1 for c in soa["controls"] if c["assessment"] == "Automated")
        assert auto >= 1, f"{fw} has no automated coverage"


# ── overlay specifics for the catalogs that need one ──────────────────────────

def test_gdpr_art32_auto_assesses(db):
    soa = {c["id"]: c for c in build_soa("GDPR")["controls"]}
    assert soa["Art.32"]["assessment"] == "Automated"   # via GDPR CHECK_MAP
    assert soa["Art.15"]["assessment"] == "Manual"      # data-subject right


def test_fedramp_inherits_nist_coverage(db):
    # storage_aws_001 declares NIST AC-3; FedRAMP reuses NIST ids → AC-3 fails.
    findings = [{"check_id": "storage_aws_001", "resource_id": "b",
                 "status": "fail", "severity": "high"}]
    c = next(x for x in ComplianceMapper().score(findings, ["FedRAMP"])["FedRAMP"]["controls"]
             if x["id"] == "AC-3")
    assert c["state"] == "fail"


# ── flexibility: customer customization works on every framework ──────────────

def test_customer_override_disables_control_across_frameworks(db):
    # A customer scoping a framework to their environment disables a control;
    # it must drop out of both scoring and the SoA — for any framework.
    cases = {"HIPAA": "164.310(b)", "SOC2": "CC1.1", "PCI-DSS": "12.1", "GDPR": "Art.15"}
    for fw, ctrl in cases.items():
        before = {c["id"] for c in build_soa(fw)["controls"]}
        assert ctrl in before
        config_store.upsert_override(fw, ctrl, enabled=False, note="Out of scope")
        soa = build_soa(fw)
        ids = {c["id"] for c in soa["controls"]}
        excluded = next(c for c in soa["controls"] if c["id"] == ctrl)
        assert excluded["applicable"] is False and excluded["status"] == "excluded"
        assert "Out of scope" in excluded["justification"]
        # and it leaves the scoring universe entirely
        scored = {c["id"] for c in ComplianceMapper().score([], [fw])[fw]["controls"]}
        assert ctrl not in scored


def test_customer_severity_and_waiver_override(db):
    # Customer raises a control's severity and records a waiver note — stamped
    # through on the score output (stock output is untouched when no override).
    config_store.upsert_override("NIST", "AC-6", severity="critical",
                                 note="PCI cardholder scope")
    c = next(x for x in ComplianceMapper().score([], ["NIST"])["NIST"]["controls"]
             if x["id"] == "AC-6")
    assert c.get("severity") == "critical"
    assert c.get("note") == "PCI cardholder scope"
