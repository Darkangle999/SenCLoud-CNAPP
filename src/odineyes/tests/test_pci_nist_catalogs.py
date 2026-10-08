"""PCI DSS v3.2.1 + NIST SP 800-53 Rev 5 catalogs — completeness, that the full
control tree drives scoring + the Statement of Applicability, and that no
check-mapped control leaks in as a phantom outside the catalog.

Unlike ISO/CIS, these two need no CHECK_MAP: the checks already declare their
PCI/NIST controls, so the catalog only supplies the denominator + titles.
"""

from __future__ import annotations

import pytest

from odineyes.core.check_registry import CheckRegistry
from odineyes.core.compliance_mapper import FRAMEWORKS, ComplianceMapper
from odineyes.core.nist_80053_catalog import NIST_800_53_REV5
from odineyes.core.pci_dss_catalog import PCI_DSS_V321


@pytest.fixture()
def db(tmp_path):
    from odineyes.inventory.service import InventoryService
    InventoryService(database_url=f"sqlite:///{tmp_path}/pn.db")
    yield


def _registry_declared(framework: str) -> set[str]:
    out: set[str] = set()
    for chk in CheckRegistry()._checks.values():
        out.update(chk.compliance.get(framework, []))
    return out


# ── catalogs wired ────────────────────────────────────────────────────────────

def test_pci_catalog_wired():
    assert FRAMEWORKS["PCI-DSS"]["controls"] is PCI_DSS_V321
    assert FRAMEWORKS["PCI-DSS"]["version"] == "3.2.1"
    assert len(PCI_DSS_V321) == 47


def test_nist_catalog_wired():
    assert FRAMEWORKS["NIST"]["controls"] is NIST_800_53_REV5
    assert len(NIST_800_53_REV5) == 35


# ── no phantom controls (catalog is a superset of what checks declare) ────────

def test_catalogs_are_supersets_of_check_declarations():
    assert _registry_declared("PCI-DSS") <= set(PCI_DSS_V321)
    assert _registry_declared("NIST") <= set(NIST_800_53_REV5)


def test_no_phantom_controls_in_scoring(db):
    for fw, cat in (("PCI-DSS", PCI_DSS_V321), ("NIST", NIST_800_53_REV5)):
        ids = {c["id"] for c in ComplianceMapper().score([], [fw])[fw]["controls"]}
        assert ids <= set(cat), f"{fw} produced controls outside the catalog: {ids - set(cat)}"


# ── automated coverage flows from the per-check declarations ──────────────────

def test_pci_failing_check_fails_its_requirement(db):
    # storage_aws_002 declares PCI 3.5 → a failing finding fails requirement 3.5.
    findings = [{"check_id": "storage_aws_002", "resource_id": "b",
                 "status": "fail", "severity": "high"}]
    c = next(x for x in ComplianceMapper().score(findings, ["PCI-DSS"])["PCI-DSS"]["controls"]
             if x["id"] == "3.5")
    assert c["state"] == "fail"


def test_nist_failing_check_fails_its_control(db):
    # storage_aws_001 declares NIST AC-3.
    findings = [{"check_id": "storage_aws_001", "resource_id": "b",
                 "status": "fail", "severity": "high"}]
    c = next(x for x in ComplianceMapper().score(findings, ["NIST"])["NIST"]["controls"]
             if x["id"] == "AC-3")
    assert c["state"] == "fail"


# ── Statement of Applicability ────────────────────────────────────────────────

def test_soa_builds_for_both(db):
    from odineyes.core.soa import build_soa
    pci = build_soa("PCI-DSS")
    nist = build_soa("NIST")
    assert pci["total"] == 47 and nist["total"] == 35
    pci_by = {c["id"]: c for c in pci["controls"]}
    assert pci_by["3.5"]["assessment"] == "Automated"   # mapped to a check
    assert pci_by["12.1"]["assessment"] == "Manual"     # policy — manual
    nist_by = {c["id"]: c for c in nist["controls"]}
    assert nist_by["AC-3"]["assessment"] == "Automated"
    assert nist_by["AC-5"]["assessment"] == "Manual"    # separation of duties
