"""Import a compliance framework from an Excel (.xlsx) control matrix.

Compliance teams keep their control sets in spreadsheets, and every framework
ships its own template (different column names/order). This reads any of them:

    bytes → secure parse → detect columns → controls → best-practice check map

An .xlsx is just a zip of XML, so this uses stdlib ``zipfile`` + ``xml.etree``
— no openpyxl/pandas dependency, and a much smaller attack surface we control.

Security (the upload is a trust boundary):
- magic-byte + size cap before unzip
- per-member + total inflate caps (zip-bomb guard)
- reject any sheet XML carrying a DTD/ENTITY (billion-laughs / XXE guard)
- row/col/cell caps so a hostile sheet can't exhaust memory

ponytail: stdlib reads cell *values* (text/number), which is all a control
matrix is. Styles/formulas/charts are ignored on purpose — add a real xlsx lib
only if a customer needs to import those (they won't, for a control list).
"""

from __future__ import annotations

import io
import re
import zipfile
import xml.etree.ElementTree as ET
from typing import Any, Optional

_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"

# ── security caps ─────────────────────────────────────────────────────────────
MAX_FILE_BYTES = 5 * 1024 * 1024        # 5 MB upload
MAX_UNCOMPRESSED = 50 * 1024 * 1024     # 50 MB total inflate (zip-bomb guard)
MAX_MEMBERS = 64                        # parts in the workbook zip
MAX_ROWS = 5000
MAX_COLS = 64
MAX_CELL = 2000                         # chars kept per cell


class FrameworkImportError(ValueError):
    """Any bad/hostile input — the API maps this to HTTP 400."""


# ── column synonyms (template-agnostic) ───────────────────────────────────────
_SYNONYMS: dict[str, set[str]] = {
    "control_id": {"control id", "control", "id", "control number", "ref", "reference",
                   "requirement id", "control ref", "number", "#", "control no", "req id"},
    "title": {"title", "description", "requirement", "control description", "name",
              "statement", "control title", "control objective", "objective", "control name"},
    "section": {"section", "domain", "category", "family", "group", "area",
                "control family", "class", "function"},
    "checks": {"checks", "aws checks", "mapping", "automated check", "check id",
               "check ids", "checks (csv)", "aws check", "automation"},
}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower()).rstrip(":")


# ── secure xlsx → rows ────────────────────────────────────────────────────────

def _col_index(ref: str) -> int:
    """'B7' → 1 (0-based column)."""
    m = re.match(r"[A-Za-z]+", ref or "")
    if not m:
        return 0
    n = 0
    for ch in m.group(0).upper():
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _safe_xml(raw: bytes) -> ET.Element:
    # A control matrix never legitimately carries a DTD/entity — reject it
    # outright rather than trust expat's entity handling.
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise FrameworkImportError("XML DTD/entity not allowed")
    try:
        return ET.fromstring(raw)
    except ET.ParseError as e:
        raise FrameworkImportError(f"malformed sheet XML: {e}") from e


def _si_text(node: ET.Element) -> str:
    """Concatenate every <t> under a shared-string / inline-string node."""
    return "".join(t.text or "" for t in node.iter(f"{_NS}t"))


def _cell_text(c: ET.Element, shared: list[str]) -> str:
    t = c.get("t")
    if t == "s":  # shared string: <v> is an index
        v = c.find(f"{_NS}v")
        if v is not None and v.text and v.text.strip().isdigit():
            i = int(v.text)
            return shared[i] if 0 <= i < len(shared) else ""
        return ""
    if t == "inlineStr":
        is_ = c.find(f"{_NS}is")
        return _si_text(is_) if is_ is not None else ""
    v = c.find(f"{_NS}v")  # number / boolean / plain
    return v.text or "" if v is not None else ""


def parse_xlsx(data: bytes, *, sheet: int = 0) -> list[list[str]]:
    """Parse one sheet of an .xlsx into a grid of strings. Raises
    FrameworkImportError on anything malformed or oversized."""
    if not data:
        raise FrameworkImportError("empty file")
    if len(data) > MAX_FILE_BYTES:
        raise FrameworkImportError(f"file too large (> {MAX_FILE_BYTES // (1024 * 1024)} MB)")
    if data[:4] != b"PK\x03\x04":
        raise FrameworkImportError("not a valid .xlsx (zip) file")

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise FrameworkImportError("corrupt .xlsx file") from e

    members = zf.infolist()
    if len(members) > MAX_MEMBERS:
        raise FrameworkImportError("too many parts in workbook")
    if sum(m.file_size for m in members) > MAX_UNCOMPRESSED:
        raise FrameworkImportError("workbook inflates too large (possible zip bomb)")

    names = set(zf.namelist())

    shared: list[str] = []
    if "xl/sharedStrings.xml" in names:
        root = _safe_xml(zf.read("xl/sharedStrings.xml"))
        shared = [_si_text(si) for si in root.findall(f"{_NS}si")]

    sheets = sorted(n for n in names
                    if n.startswith("xl/worksheets/sheet") and n.endswith(".xml"))
    if not sheets:
        raise FrameworkImportError("no worksheet found in workbook")
    target = sheets[min(max(sheet, 0), len(sheets) - 1)]

    root = _safe_xml(zf.read(target))
    sheet_data = root.find(f"{_NS}sheetData")
    rows: list[list[str]] = []
    if sheet_data is None:
        return rows
    for r in sheet_data.findall(f"{_NS}row"):
        if len(rows) >= MAX_ROWS:
            break
        cells: list[str] = []
        for c in r.findall(f"{_NS}c"):
            idx = _col_index(c.get("r", "A1"))
            if idx >= MAX_COLS:
                continue
            while len(cells) <= idx:
                cells.append("")
            cells[idx] = _cell_text(c, shared)[:MAX_CELL]
        rows.append(cells)
    return rows


# ── rows → controls (generic, template-aware) ─────────────────────────────────

def detect_columns(rows: list[list[str]], max_scan: int = 12) -> tuple[int, dict[str, int]]:
    """Find the header row and map field → column index using synonyms.
    Returns (header_row_index, {field: col}). (-1, {}) if no header found."""
    for ri, row in enumerate(rows[:max_scan]):
        hits: dict[str, int] = {}
        for ci, cell in enumerate(row):
            h = _norm(cell)
            for field, syns in _SYNONYMS.items():
                if h in syns and field not in hits:
                    hits[field] = ci
        if "control_id" in hits or len(hits) >= 2:
            return ri, hits
    return -1, {}


def rows_to_controls(rows: list[list[str]],
                     column_map: Optional[dict[str, int]] = None) -> dict[str, Any]:
    """Build {control_id: {title, section, checks}} from the grid."""
    if column_map:
        header_idx, cols = -1, dict(column_map)
    else:
        header_idx, cols = detect_columns(rows)
    if not cols:
        cols = {"control_id": 0, "title": 1}  # last resort: first two columns

    cid_col = cols.get("control_id", 0)
    title_col = cols.get("title")
    sec_col = cols.get("section")
    chk_col = cols.get("checks")

    def at(row: list[str], col: Optional[int]) -> str:
        return row[col].strip() if col is not None and 0 <= col < len(row) else ""

    controls: dict[str, Any] = {}
    for row in rows[header_idx + 1:]:
        cid = at(row, cid_col)
        if not cid:
            continue
        title = at(row, title_col) or cid
        section = at(row, sec_col) or "General"
        checks_raw = at(row, chk_col)
        checks = [c.strip() for c in re.split(r"[,;]", checks_raw) if c.strip()] if checks_raw else []
        controls[cid] = {"title": title, "section": section, "checks": checks}
    return controls


# ── best-practice mapping: free-text control → existing AWS checks ────────────
_STOP = {"ensure", "is", "are", "the", "a", "an", "of", "to", "for", "all", "that",
         "and", "or", "in", "on", "with", "by", "be", "no", "not", "your", "you",
         "its", "should", "must", "shall", "has", "have", "this", "at", "as", "from"}


def _keywords(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", (text or "").lower())
            if len(w) > 2 and w not in _STOP}


def _registry_checks() -> list[Any]:
    from odineyes.core.check_registry import CheckRegistry
    return list(CheckRegistry()._checks.values())


def suggest_checks(title: str, section: str, checks_meta: list[Any], *, limit: int = 3) -> list[str]:
    """Rank existing checks by keyword overlap with the control text — a generic
    best-practice mapping so an imported control isn't left unassessed."""
    want = _keywords(f"{title} {section}")
    if not want:
        return []
    scored: list[tuple[int, str]] = []
    for chk in checks_meta:
        hay = _keywords(f"{getattr(chk, 'check_id', '')} {getattr(chk, 'name', '')} "
                        f"{getattr(chk, 'description', '')} {getattr(chk, 'category', '')}")
        overlap = len(want & hay)
        if overlap:
            scored.append((overlap, getattr(chk, "check_id", "")))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [cid for _, cid in scored[:limit] if cid]


def import_workbook(data: bytes, *, framework_id: str, name: Optional[str] = None,
                    version: Optional[str] = None, sheet: int = 0,
                    column_map: Optional[dict[str, int]] = None,
                    suggest: bool = True) -> dict[str, Any]:
    """Full pipeline → a CustomFramework-shaped dict (not persisted)."""
    rows = parse_xlsx(data, sheet=sheet)
    controls = rows_to_controls(rows, column_map)
    if not controls:
        raise FrameworkImportError(
            "no controls found — the sheet needs a control-id column (and ideally a title)")
    if suggest:
        meta = _registry_checks()
        for c in controls.values():
            if not c["checks"]:
                c["checks"] = suggest_checks(c["title"], c["section"], meta)
    return {"framework_id": framework_id, "name": name or framework_id,
            "version": version, "controls": controls, "enabled": True}


# ── minimal xlsx writer (round-trips the parser; also the SoA export writer) ──

def _col_letter(c: int) -> str:
    s = ""
    c += 1
    while c:
        c, r = divmod(c - 1, 26)
        s = chr(65 + r) + s
    return s


def _xlsx_from_rows(rows: list[list[str]]) -> bytes:
    """Write a minimal, valid .xlsx (shared-strings) — exercises the real path."""
    shared: list[str] = []
    idx: dict[str, int] = {}

    def sid(s: str) -> int:
        if s not in idx:
            idx[s] = len(shared)
            shared.append(s)
        return idx[s]

    def esc(s: str) -> str:
        return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

    body = []
    for r, row in enumerate(rows, start=1):
        cells = "".join(f'<c r="{_col_letter(c)}{r}" t="s"><v>{sid(v)}</v></c>'
                        for c, v in enumerate(row))
        body.append(f'<row r="{r}">{cells}</row>')

    main = _NS[1:-1]   # spreadsheetml main namespace
    rels = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    pkg_rels = "http://schemas.openxmlformats.org/package/2006/relationships"
    ct_ns = "http://schemas.openxmlformats.org/package/2006/content-types"
    decl = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'

    sheet_xml = (f'{decl}<worksheet xmlns="{main}">'
                 f'<sheetData>{"".join(body)}</sheetData></worksheet>')
    ss_xml = (f'{decl}<sst xmlns="{main}" count="{len(shared)}" uniqueCount="{len(shared)}">'
              + "".join(f'<si><t xml:space="preserve">{esc(s)}</t></si>' for s in shared) + "</sst>")
    workbook_xml = (f'{decl}<workbook xmlns="{main}" xmlns:r="{rels}">'
                    f'<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>')

    # A package Excel will open needs the full relationship graph + content types.
    content_types = (f'{decl}<Types xmlns="{ct_ns}">'
                     '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                     '<Default Extension="xml" ContentType="application/xml"/>'
                     '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                     '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                     '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
                     '</Types>')
    root_rels = (f'{decl}<Relationships xmlns="{pkg_rels}">'
                 f'<Relationship Id="rId1" Type="{rels}/officeDocument" Target="xl/workbook.xml"/>'
                 '</Relationships>')
    workbook_rels = (f'{decl}<Relationships xmlns="{pkg_rels}">'
                     f'<Relationship Id="rId1" Type="{rels}/worksheet" Target="worksheets/sheet1.xml"/>'
                     f'<Relationship Id="rId2" Type="{rels}/sharedStrings" Target="sharedStrings.xml"/>'
                     '</Relationships>')

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", workbook_xml)
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        z.writestr("xl/sharedStrings.xml", ss_xml)
        z.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return buf.getvalue()


# Public production writer (SoA export). Cells are coerced to strings.
def write_xlsx(rows: list[list[Any]]) -> bytes:
    return _xlsx_from_rows([[("" if v is None else str(v)) for v in row] for row in rows])


def _demo() -> None:
    # A made-up vendor template: columns out of order, odd header names, a
    # preamble row before the header.
    rows = [
        ["ACME Security Baseline v2", "", "", ""],
        ["Domain", "Control Ref", "Requirement", "AWS Checks"],
        ["Data", "DP-1", "Ensure S3 buckets are encrypted at rest", "s3_encryption"],
        ["Data", "DP-2", "Block public access to storage buckets", ""],
        ["IAM", "AC-1", "Require MFA for the root account", ""],
        ["", "", "", ""],  # trailing blank
    ]
    data = _xlsx_from_rows(rows)
    assert data[:4] == b"PK\x03\x04"

    hi, cols = detect_columns(rows)
    assert hi == 1 and cols["control_id"] == 1 and cols["section"] == 0 and cols["checks"] == 3

    controls = rows_to_controls(parse_xlsx(data))
    assert set(controls) == {"DP-1", "DP-2", "AC-1"}
    assert controls["DP-1"]["section"] == "Data"
    assert controls["DP-1"]["checks"] == ["s3_encryption"]  # explicit column wins

    fw = import_workbook(data, framework_id="ACME", name="ACME Baseline", version="2")
    assert fw["framework_id"] == "ACME" and len(fw["controls"]) == 3

    # security: bad magic, oversize, and DTD are all rejected
    for bad, kw in [(b"not a zip", "valid"), (b"PK\x03\x04" + b"x" * 10, "corrupt")]:
        try:
            parse_xlsx(bad)
            raise AssertionError("expected rejection")
        except FrameworkImportError as e:
            assert kw in str(e)
    try:
        _safe_xml(b'<!DOCTYPE x [<!ENTITY a "b">]><r/>')
        raise AssertionError("DTD should be rejected")
    except FrameworkImportError:
        pass
    print("framework_import self-check passed")


if __name__ == "__main__":
    _demo()
