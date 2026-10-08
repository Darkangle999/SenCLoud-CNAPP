"""CIS AWS Foundations Benchmark catalog — completeness, that the CHECK_MAP
references real checks, and that it drives scoring + the Statement of Applicability
through the same overlay mechanism as ISO 27001."""

from __future__ import annotations

import pytest

from odineyes.core.check_registry import CheckRegistry
from odineyes.core.cis_aws_catalog import CHECK_MAP, CIS_AWS_FOUNDATIONS
from odineyes.core.compliance_mapper import FRAMEWORKS, ComplianceMapper


@pytest.fixture()
def db(tmp_path):
    from odineyes.inventory.service import InventoryService
    InventoryService(database_url=f"sqlite:///{tmp_path}/cis.db")
    yield


# ── catalog ───────────────────────────────────────────────────────────────────

def test_catalog_is_complete_and_wired():
    assert len(CIS_AWS_FOUNDATIONS) == 62
    assert FRAMEWORKS["CIS"]["controls"] is CIS_AWS_FOUNDATIONS
    assert FRAMEWORKS["CIS"]["version"] == "1.5.0"
    sections = {m["section"] for m in CIS_AWS_FOUNDATIONS.values()}
    assert len(sections) == 5  # IAM, Storage, Logging, Monitoring, Networking


def test_check_map_targets_exist():
    # Every control we claim to auto-assess must be a real control, and every
    # check id it points at must be a real registered check (no dangling refs).
    real_checks = set(CheckRegistry()._checks.keys())
    for ctrl, cids in CHECK_MAP.items():
        assert ctrl in CIS_AWS_FOUNDATIONS, f"unknown control {ctrl}"
        for cid in cids:
            assert cid in real_checks, f"{ctrl} → missing check {cid}"


# ── scoring overlay ───────────────────────────────────────────────────────────

def test_full_catalog_is_scored_mostly_not_assessed(db):
    out = ComplianceMapper().score([], ["CIS"])["CIS"]
    # No findings → every one of the 62 controls is not_assessed, none counted.
    assert out["not_assessed"] >= 62
    assert out["total"] == 0


def test_failing_check_fails_mapped_cis_control(db):
    # storage_aws_002 (S3 encryption) → CIS 2.1.1 via CHECK_MAP.
    findings = [{"check_id": "storage_aws_002", "resource_id": "b",
                 "status": "fail", "severity": "high"}]
    out = ComplianceMapper().score(findings, ["CIS"])["CIS"]
    c = next(x for x in out["controls"] if x["id"] == "2.1.1")
    assert c["state"] == "fail"


def test_no_phantom_controls_from_non_aws_checks(db):
    # The dormant Azure/GCP checks used to declare CIS-Azure/GCP numbers
    # (1.1.2, 6.4, 4.1.1 …) — those must not leak into the AWS benchmark.
    ids = {c["id"] for c in ComplianceMapper().score([], ["CIS"])["CIS"]["controls"]}
    assert ids <= set(CIS_AWS_FOUNDATIONS)        # nothing outside the catalog
    assert {"1.1.2", "6.4", "4.1.1", "5.1.5"}.isdisjoint(ids)


# ── Statement of Applicability ────────────────────────────────────────────────

def test_cis_soa_builds_and_auto_assesses(db):
    from odineyes.core.soa import build_soa
    soa = build_soa("CIS")
    assert soa["total"] == 62
    by = {c["id"]: c for c in soa["controls"]}
    assert by["2.1.1"]["assessment"] == "Automated"   # mapped to a check
    assert by["1.1"]["assessment"] == "Manual"        # contact details — manual
