"""Excel (.xlsx) compliance-framework import — parsing, generic column
detection across vendor templates, best-practice check suggestion, and the
security caps on the upload trust boundary."""

from __future__ import annotations

import io
import zipfile

import pytest

from odineyes.core.framework_import import (
    FrameworkImportError,
    _xlsx_from_rows,
    detect_columns,
    import_workbook,
    parse_xlsx,
    rows_to_controls,
    suggest_checks,
)


# ── parsing real OOXML (shared strings) ───────────────────────────────────────

def test_parse_roundtrips_values():
    rows = [["A", "B"], ["1", "two"], ["", "x"]]
    out = parse_xlsx(_xlsx_from_rows(rows))
    assert out[0] == ["A", "B"]
    assert out[1] == ["1", "two"]


def test_xlsx_is_a_complete_ooxml_package():
    # Our parser is lenient; Excel is not. A valid package needs the full
    # relationship graph + content-type overrides or Excel refuses to open it.
    import xml.etree.ElementTree as ET

    data = _xlsx_from_rows([["A", "B"], ["1", "2"]])
    zf = zipfile.ZipFile(io.BytesIO(data))
    parts = set(zf.namelist())
    for required in ("[Content_Types].xml", "_rels/.rels", "xl/workbook.xml",
                     "xl/_rels/workbook.xml.rels", "xl/sharedStrings.xml",
                     "xl/worksheets/sheet1.xml"):
        assert required in parts, f"missing OOXML part: {required}"
        ET.fromstring(zf.read(required))  # must be well-formed XML
    ct = zf.read("[Content_Types].xml").decode()
    assert "/xl/workbook.xml" in ct and "/xl/worksheets/sheet1.xml" in ct
    wb_rels = zf.read("xl/_rels/workbook.xml.rels").decode()
    assert "worksheets/sheet1.xml" in wb_rels and "sharedStrings.xml" in wb_rels


# ── generic templates: different column names / order / preamble ──────────────

def test_detect_columns_handles_vendor_template():
    rows = [
        ["Vendor Baseline", "", "", ""],                       # preamble
        ["Domain", "Control Ref", "Requirement", "AWS Checks"],  # header
        ["Data", "DP-1", "Encrypt S3 at rest", "s3_encryption"],
    ]
    hi, cols = detect_columns(rows)
    assert hi == 1
    assert cols["section"] == 0 and cols["control_id"] == 1
    assert cols["title"] == 2 and cols["checks"] == 3


def test_rows_to_controls_explicit_checks_win():
    rows = [
        ["ID", "Title", "Section", "Checks"],
        ["C-1", "Encrypt buckets", "Data", "s3_encryption, s3_block_public"],
        ["", "skip blank id", "Data", ""],
    ]
    controls = rows_to_controls(rows)
    assert set(controls) == {"C-1"}
    assert controls["C-1"]["checks"] == ["s3_encryption", "s3_block_public"]
    assert controls["C-1"]["section"] == "Data"


def test_falls_back_to_first_two_columns_without_header():
    rows = [["X-1", "Some requirement text"], ["X-2", "Another"]]
    controls = rows_to_controls(rows)
    assert set(controls) == {"X-1", "X-2"}
    assert controls["X-1"]["title"] == "Some requirement text"


# ── best-practice mapping ─────────────────────────────────────────────────────

def test_suggest_checks_matches_real_registry():
    from odineyes.core.framework_import import _registry_checks
    meta = _registry_checks()
    s3 = suggest_checks("Block public access to S3 storage buckets", "Data", meta)
    assert s3, "expected at least one suggested check"
    assert any("s3" in c or "storage" in c for c in s3)


def test_import_workbook_suggests_when_no_check_column():
    rows = [
        ["Domain", "Control Ref", "Requirement"],
        ["IAM", "AC-1", "Require MFA for the root account"],
    ]
    fw = import_workbook(_xlsx_from_rows(rows), framework_id="ACME", name="ACME")
    assert fw["framework_id"] == "ACME"
    assert fw["controls"]["AC-1"]["checks"], "MFA control should get a suggested check"


# ── security: the upload is a trust boundary ──────────────────────────────────

def test_rejects_non_xlsx():
    with pytest.raises(FrameworkImportError):
        parse_xlsx(b"not a zip at all")


def test_rejects_corrupt_zip():
    with pytest.raises(FrameworkImportError):
        parse_xlsx(b"PK\x03\x04" + b"\x00" * 20)


def test_rejects_dtd_entity_bomb():
    # A worksheet carrying a billion-laughs DTD must be refused before parse.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("xl/worksheets/sheet1.xml",
                   '<!DOCTYPE x [<!ENTITY a "boom">]><worksheet/>')
    with pytest.raises(FrameworkImportError):
        parse_xlsx(buf.getvalue())


def test_rejects_oversize():
    from odineyes.core.framework_import import MAX_FILE_BYTES
    with pytest.raises(FrameworkImportError):
        parse_xlsx(b"PK\x03\x04" + b"\x00" * (MAX_FILE_BYTES + 1))


def test_empty_controls_raises():
    # Title/Section detected but no control-id column → id column is blank → no
    # controls → a clear error rather than silent garbage.
    rows = [["", "Title", "Section"], ["", "blank id row", "Data"]]
    with pytest.raises(FrameworkImportError):
        import_workbook(_xlsx_from_rows(rows), framework_id="X", suggest=False)
