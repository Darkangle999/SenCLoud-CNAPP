"""ISO 27001:2022 Annex A catalog + Statement of Applicability generation."""

from __future__ import annotations

import pytest

from odineyes.core import config_store
from odineyes.core.compliance_mapper import FRAMEWORKS, ComplianceMapper
from odineyes.core.framework_import import parse_xlsx
from odineyes.core.iso27001_catalog import ANNEX_A_2022
from odineyes.core.soa import build_soa, soa_to_xlsx


@pytest.fixture()
def db(tmp_path):
    from odineyes.inventory.service import InventoryService
    InventoryService(database_url=f"sqlite:///{tmp_path}/soa.db")
    yield


# ── catalog ───────────────────────────────────────────────────────────────────

def test_catalog_is_complete():
    assert len(ANNEX_A_2022) == 93
    themes = {m["section"] for m in ANNEX_A_2022.values()}
    assert themes == {"Organizational controls", "People controls",
                      "Physical controls", "Technological controls"}


def test_framework_uses_full_catalog():
    assert len(FRAMEWORKS["ISO27001"]["controls"]) == 93
    assert FRAMEWORKS["ISO27001"]["version"] == "2022"


# ── scoring: technological controls auto-assess via the check overlay ─────────

def test_failing_check_fails_mapped_iso_control(db):
    findings = [{"check_id": "storage_aws_002", "resource_id": "b",
                 "status": "fail", "severity": "high"}]   # S3 encryption → A.8.24
    out = ComplianceMapper().score(findings, ["ISO27001"])["ISO27001"]
    a824 = next(c for c in out["controls"] if c["id"] == "A.8.24")
    assert a824["state"] == "fail"


# ── SoA generation ────────────────────────────────────────────────────────────

def test_soa_lists_all_controls_and_exports(db):
    soa = build_soa("ISO27001")
    assert soa["total"] == 93 and soa["applicable"] == 93
    grid = parse_xlsx(soa_to_xlsx(soa))
    assert grid[2][:4] == ["Control", "Title", "Theme", "Applicable"]  # title, subtitle, header
    assert len(grid) == 3 + 93


def test_soa_xlsx_is_styled_and_complete(db):
    # Audit presentation: the export carries styles + freeze pane + autofilter,
    # and is a complete OOXML package (or Excel won't open it).
    import io
    import zipfile

    data = soa_to_xlsx(build_soa("ISO27001"))
    z = zipfile.ZipFile(io.BytesIO(data))
    parts = set(z.namelist())
    assert "xl/styles.xml" in parts
    sheet = z.read("xl/worksheets/sheet1.xml").decode()
    assert "<pane" in sheet and 'state="frozen"' in sheet   # frozen header
    assert "<autoFilter" in sheet                            # filterable
    assert "<mergeCells" in sheet                            # title banner
    styles = z.read("xl/styles.xml").decode()
    assert "FFC6EFCE" in styles and "FFFFC7CE" in styles     # green/red status fills


def test_soa_automated_vs_manual(db):
    by = {c["id"]: c for c in build_soa("ISO27001")["controls"]}
    assert by["A.8.24"]["assessment"] == "Automated"   # cryptography → AWS checks
    assert by["A.6.1"]["assessment"] == "Manual"       # screening → people control


def test_soa_reflects_override_as_exclusion(db):
    config_store.upsert_override("ISO27001", "A.7.1", enabled=False,
                                 note="No physical sites — cloud only")
    soa = build_soa("ISO27001")
    a71 = next(c for c in soa["controls"] if c["id"] == "A.7.1")
    assert a71["applicable"] is False
    assert a71["status"] == "excluded"
    assert "cloud only" in a71["justification"]
    assert soa["applicable"] == 92


def test_soa_unknown_framework_raises(db):
    with pytest.raises(ValueError):
        build_soa("NOPE")


def test_every_automated_control_explains_how_it_is_evidenced(db):
    """An "Automated" row with no explanation of how is the row an auditor
    stops on. Coverage that cannot answer "how do you know?" is worse than
    an honest Manual."""
    soa = build_soa("ISO27001")
    automated = [c for c in soa["controls"] if c["assessment"] == "Automated"]
    assert automated, "ISO27001 should auto-assess some controls"
    unexplained = [c["id"] for c in automated if not c["cloud_guidance"]]
    assert unexplained == [], unexplained
    # Guidance must ride along into the workbook, not stop at the dict.
    assert "How it is evidenced" in _soa_headers()
    assert soa_to_xlsx(soa)


def _soa_headers() -> list[str]:
    from odineyes.core.soa import _HEADERS

    return list(_HEADERS)


def test_people_and_physical_controls_are_never_claimed_as_automated(db):
    """A CSPM cannot evidence background checks or door locks. Claiming it can
    is the dishonest way to make a coverage number look better."""
    soa = build_soa("ISO27001")
    wrongly_automated = [
        c["id"] for c in soa["controls"]
        if c["assessment"] == "Automated" and c["id"].startswith(("A.6.", "A.7."))
    ]
    assert wrongly_automated == [], wrongly_automated


def test_iso_automated_coverage_is_recorded_not_inflated(db):
    """Pins the honest split so a future mapping spree is a deliberate act."""
    soa = build_soa("ISO27001")
    assert soa["total"] == 93
    automated = [c for c in soa["controls"] if c["assessment"] == "Automated"]
    themes = {c["theme"].split()[0] for c in automated}
    assert themes == {"Technological", "Organizational"}
    # Guard the direction of travel, not an exact number: coverage may grow,
    # but a silent collapse means mappings were lost.
    assert len(automated) >= 24, len(automated)
