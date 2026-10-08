"""A small styled single-sheet .xlsx writer for audit-presentable reports.

Hand-rolled OOXML (stdlib only, same as the importer) but with a real
``styles.xml`` so the output looks like an auditor's document: a title banner,
a bold frozen header, column widths, wrapped text, an autofilter, and
colour-coded status cells. There is no untrusted input on the write path, so the
reasons we avoid an xlsx library for *reading* don't apply here.

Style indices are fixed (see ``_STYLES_XML``); the writer just references them.
"""

from __future__ import annotations

import io
import zipfile
from typing import Any, Callable, Optional

_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PKG = "http://schemas.openxmlformats.org/package/2006/relationships"
_CT = "http://schemas.openxmlformats.org/package/2006/content-types"
_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'

# cellXfs indices (must match the order in _STYLES_XML below).
S_DEFAULT, S_TITLE, S_SUBTITLE, S_HEADER = 0, 1, 2, 3
S_DATA, S_WRAP, S_CENTER = 4, 5, 6
S_GREEN, S_RED, S_GREY, S_AMBER = 7, 8, 9, 10
_FILL_STYLE = {"green": S_GREEN, "red": S_RED, "grey": S_GREY, "amber": S_AMBER}

_STYLES_XML = (
    f'{_DECL}<styleSheet xmlns="{_MAIN}">'
    '<fonts count="5">'
    '<font><sz val="11"/><name val="Calibri"/></font>'
    '<font><b/><sz val="11"/><name val="Calibri"/></font>'
    '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>'
    '<font><b/><sz val="16"/><color rgb="FF1F4E78"/><name val="Calibri"/></font>'
    '<font><i/><sz val="10"/><color rgb="FF595959"/><name val="Calibri"/></font>'
    '</fonts>'
    '<fills count="7">'
    '<fill><patternFill patternType="none"/></fill>'
    '<fill><patternFill patternType="gray125"/></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FF1F4E78"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFC6EFCE"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFFFC7CE"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFD9D9D9"/></patternFill></fill>'
    '<fill><patternFill patternType="solid"><fgColor rgb="FFFFEB9C"/></patternFill></fill>'
    '</fills>'
    '<borders count="2">'
    '<border><left/><right/><top/><bottom/><diagonal/></border>'
    '<border>'
    '<left style="thin"><color rgb="FFBFBFBF"/></left>'
    '<right style="thin"><color rgb="FFBFBFBF"/></right>'
    '<top style="thin"><color rgb="FFBFBFBF"/></top>'
    '<bottom style="thin"><color rgb="FFBFBFBF"/></bottom>'
    '<diagonal/></border>'
    '</borders>'
    '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
    '<cellXfs count="11">'
    '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'                                                                                  # 0 default
    '<xf fontId="3" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1"><alignment vertical="center"/></xf>'                            # 1 title
    '<xf fontId="4" fillId="0" borderId="0" xfId="0" applyFont="1"/>'                                                                                 # 2 subtitle
    '<xf fontId="2" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1">'
    '<alignment horizontal="center" vertical="center" wrapText="1"/></xf>'                                                                            # 3 header
    '<xf fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top"/></xf>'                             # 4 data
    '<xf fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>'                # 5 wrap
    '<xf fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>'      # 6 center
    '<xf fontId="0" fillId="3" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>'  # 7 green
    '<xf fontId="0" fillId="4" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>'  # 8 red
    '<xf fontId="0" fillId="5" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>'  # 9 grey
    '<xf fontId="0" fillId="6" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>'  # 10 amber
    '</cellXfs>'
    '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
    '</styleSheet>'
)


def _col_letter(c: int) -> str:
    s, c = "", c + 1
    while c:
        c, r = divmod(c - 1, 26)
        s = chr(65 + r) + s
    return s


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_report_xlsx(
    *,
    title: str,
    subtitle: str,
    headers: list[str],
    rows: list[list[Any]],
    sheet_name: str = "Report",
    col_widths: Optional[list[float]] = None,
    wrap_cols: Optional[set[int]] = None,
    center_cols: Optional[set[int]] = None,
    cell_fill: Optional[Callable[[int, int, str], Optional[str]]] = None,
) -> bytes:
    """Render a styled, single-sheet workbook.

    Layout: row 1 title banner, row 2 subtitle, row 3 header (frozen + filtered),
    rows 4+ data. ``cell_fill(data_row, col, value)`` may return a fill key
    ('green'|'red'|'grey'|'amber') to colour a data cell (e.g. status).
    """
    wrap_cols = wrap_cols or set()
    center_cols = center_cols or set()
    ncols = max(len(headers), *(len(r) for r in rows)) if rows else len(headers)
    last_col = _col_letter(ncols - 1)

    shared: list[str] = []
    idx: dict[str, int] = {}

    def sid(s: str) -> int:
        s = "" if s is None else str(s)
        if s not in idx:
            idx[s] = len(shared)
            shared.append(s)
        return idx[s]

    def cell(col: int, r: int, value: str, style: int) -> str:
        return f'<c r="{_col_letter(col)}{r}" s="{style}" t="s"><v>{sid(value)}</v></c>'

    body: list[str] = []
    # row 1: title (only first cell carries text; merged across all columns)
    body.append(f'<row r="1" ht="22" customHeight="1">{cell(0, 1, title, S_TITLE)}</row>')
    # row 2: subtitle
    body.append(f'<row r="2">{cell(0, 2, subtitle, S_SUBTITLE)}</row>')
    # row 3: header
    hdr = "".join(cell(c, 3, headers[c] if c < len(headers) else "", S_HEADER) for c in range(ncols))
    body.append(f'<row r="3">{hdr}</row>')
    # rows 4+: data
    for di, row in enumerate(rows):
        r = di + 4
        cells = []
        for c in range(ncols):
            val = str(row[c]) if c < len(row) and row[c] is not None else ""
            style = S_DATA
            if c in wrap_cols:
                style = S_WRAP
            elif c in center_cols:
                style = S_CENTER
            if cell_fill:
                key = cell_fill(di, c, val)
                if key in _FILL_STYLE:
                    style = _FILL_STYLE[key]
            cells.append(cell(c, r, val, style))
        body.append(f'<row r="{r}">{"".join(cells)}</row>')

    cols_xml = ""
    if col_widths:
        parts = [f'<col min="{i + 1}" max="{i + 1}" width="{w}" customWidth="1"/>'
                 for i, w in enumerate(col_widths)]
        cols_xml = f'<cols>{"".join(parts)}</cols>'

    last_data_row = 3 + len(rows)
    sheet_xml = (
        f'{_DECL}<worksheet xmlns="{_MAIN}" xmlns:r="{_REL}">'
        '<sheetViews><sheetView tabSelected="1" workbookViewId="0">'
        '<pane ySplit="3" topLeftCell="A4" activePane="bottomLeft" state="frozen"/>'
        '<selection pane="bottomLeft" activeCell="A4" sqref="A4"/>'
        '</sheetView></sheetViews>'
        '<sheetFormatPr defaultRowHeight="15"/>'
        f'{cols_xml}'
        f'<sheetData>{"".join(body)}</sheetData>'
        f'<autoFilter ref="A3:{last_col}{last_data_row}"/>'
        f'<mergeCells count="2"><mergeCell ref="A1:{last_col}1"/><mergeCell ref="A2:{last_col}2"/></mergeCells>'
        '</worksheet>'
    )
    ss_xml = (f'{_DECL}<sst xmlns="{_MAIN}" count="{len(shared)}" uniqueCount="{len(shared)}">'
              + "".join(f'<si><t xml:space="preserve">{_esc(s)}</t></si>' for s in shared) + "</sst>")
    workbook_xml = (f'{_DECL}<workbook xmlns="{_MAIN}" xmlns:r="{_REL}">'
                    f'<sheets><sheet name="{_esc(sheet_name)[:31]}" sheetId="1" r:id="rId1"/></sheets></workbook>')
    content_types = (
        f'{_DECL}<Types xmlns="{_CT}">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
        '</Types>')
    root_rels = (f'{_DECL}<Relationships xmlns="{_PKG}">'
                 f'<Relationship Id="rId1" Type="{_REL}/officeDocument" Target="xl/workbook.xml"/>'
                 '</Relationships>')
    workbook_rels = (f'{_DECL}<Relationships xmlns="{_PKG}">'
                     f'<Relationship Id="rId1" Type="{_REL}/worksheet" Target="worksheets/sheet1.xml"/>'
                     f'<Relationship Id="rId2" Type="{_REL}/styles" Target="styles.xml"/>'
                     f'<Relationship Id="rId3" Type="{_REL}/sharedStrings" Target="sharedStrings.xml"/>'
                     '</Relationships>')

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", workbook_xml)
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        z.writestr("xl/styles.xml", _STYLES_XML)
        z.writestr("xl/sharedStrings.xml", ss_xml)
        z.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return buf.getvalue()


def _demo() -> None:
    import xml.etree.ElementTree as ET

    data = build_report_xlsx(
        title="Demo Report", subtitle="generated now",
        headers=["A", "Status"], rows=[["x", "pass"], ["y", "fail"]],
        col_widths=[20, 12], center_cols={1},
        cell_fill=lambda r, c, v: {"pass": "green", "fail": "red"}.get(v) if c == 1 else None,
    )
    assert data[:4] == b"PK\x03\x04"
    z = zipfile.ZipFile(io.BytesIO(data))
    for part in ("[Content_Types].xml", "_rels/.rels", "xl/workbook.xml",
                 "xl/_rels/workbook.xml.rels", "xl/styles.xml",
                 "xl/sharedStrings.xml", "xl/worksheets/sheet1.xml"):
        ET.fromstring(z.read(part))  # well-formed
    assert "/xl/styles.xml" in z.read("[Content_Types].xml").decode()
    print("xlsx_report self-check passed")


if __name__ == "__main__":
    _demo()
