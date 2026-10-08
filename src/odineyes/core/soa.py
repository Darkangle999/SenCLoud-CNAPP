"""Statement of Applicability (SoA) — the central ISO 27001 certification
artifact, generated from data we already hold.

For every control in a framework the SoA records: applicable (Y/N) + justification
(from the control override — enabled/note), whether the platform assesses it
Automated vs Manual (does any check map to it), and its latest status. This is
the document an auditor asks for first; here it's a transform over the catalog +
the customization overlay, exportable to the Excel format compliance teams use.

ponytail: status comes from the most recent persisted compliance snapshot when
one exists, else Manual/not_assessed — no live AWS call needed to produce an SoA.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _control_check_map(framework_id: str, fw_controls: dict[str, Any],
                       cfg: Any, checks: dict[str, Any]) -> dict[str, list[str]]:
    """control_id → mapped check/policy ids (registry + inline + custom policy)."""
    ctrl_checks: dict[str, set[str]] = {}
    for cid, chk in checks.items():
        for ctrl in getattr(chk, "compliance", {}).get(framework_id, []):
            ctrl_checks.setdefault(ctrl, set()).add(cid)
    for ctrl, meta in fw_controls.items():
        if isinstance(meta, dict):
            for c in meta.get("checks", []):
                ctrl_checks.setdefault(ctrl, set()).add(c)
    for pol in cfg.custom_policies:
        for ctrl in pol["frameworks"].get(framework_id, []):
            ctrl_checks.setdefault(ctrl, set()).add(pol["policy_id"])
    if framework_id == "ISO27001":
        from odineyes.core.iso27001_catalog import merge_check_map
        merge_check_map(ctrl_checks)
    elif framework_id == "CIS":
        from odineyes.core.cis_aws_catalog import merge_check_map
        merge_check_map(ctrl_checks)
    elif framework_id == "CIS-COMPUTE":
        from odineyes.core.cis_aws_compute_catalog import merge_check_map
        merge_check_map(ctrl_checks)
    elif framework_id == "CIS-STORAGE":
        from odineyes.core.cis_aws_storage_catalog import merge_check_map
        merge_check_map(ctrl_checks)
    elif framework_id == "CIS-EUC":
        from odineyes.core.cis_aws_euc_catalog import merge_check_map
        merge_check_map(ctrl_checks)
    elif framework_id == "GDPR":
        from odineyes.core.gdpr_catalog import merge_check_map
        merge_check_map(ctrl_checks)
    elif framework_id == "FedRAMP":
        # FedRAMP control ids ARE NIST 800-53 ids — reuse the NIST mappings.
        for cid, chk in checks.items():
            for ctrl in getattr(chk, "compliance", {}).get("NIST", []):
                ctrl_checks.setdefault(ctrl, set()).add(cid)
    return {k: sorted(v) for k, v in ctrl_checks.items()}


def build_soa(framework_id: str, *, status_by_control: Optional[dict[str, str]] = None) -> dict[str, Any]:
    """Build the Statement of Applicability for a framework (built-in or custom)."""
    from odineyes.core.check_registry import CheckRegistry
    from odineyes.core.compliance_mapper import FRAMEWORKS
    from odineyes.core.config_store import load_config

    cfg = load_config()
    fw = FRAMEWORKS.get(framework_id) or cfg.custom_frameworks.get(framework_id)
    if not fw:
        raise ValueError(f"unknown framework: {framework_id}")

    fw_controls: dict[str, Any] = fw.get("controls", {}) or {}
    checks = {c.check_id: c for c in CheckRegistry()._checks.values()}
    ctrl_checks = _control_check_map(framework_id, fw_controls, cfg, checks)
    overrides = cfg.overrides.get(framework_id, {})
    status_by_control = status_by_control or {}

    controls: list[dict[str, Any]] = []
    applicable_n = 0
    for cid, meta in fw_controls.items():
        title = meta.get("title", cid) if isinstance(meta, dict) else cid
        theme = meta.get("section", "") if isinstance(meta, dict) else ""
        ov = overrides.get(cid)
        applicable = ov.get("enabled", True) if ov else True
        mapped = ctrl_checks.get(cid, [])

        if applicable:
            applicable_n += 1
            status = status_by_control.get(cid) or ("not_assessed" if mapped else "manual")
            justification = (ov.get("note") if ov else None) or "Applicable to the ISMS scope."
        else:
            status = "excluded"
            justification = (ov.get("note") if ov else None) or "Excluded from the ISMS scope."

        controls.append({
            "id": cid, "title": title, "theme": theme,
            "applicable": applicable, "justification": justification,
            "assessment": "Automated" if mapped else "Manual",
            "status": status, "checks": mapped,
            "severity": ov.get("severity") if ov else None,
            # "How do you know?" — the question an auditor asks straight after
            # seeing "Automated". Empty for manual controls, which is correct:
            # the platform produces no evidence for those.
            "cloud_guidance": (
                meta.get("cloud_guidance", "") if isinstance(meta, dict) else ""
            ),
        })

    return {"framework": framework_id, "name": fw.get("name", framework_id),
            "version": fw.get("version"), "generated_at": _now(),
            "total": len(controls), "applicable": applicable_n, "controls": controls}


# Status / applicability → cell colour, for an at-a-glance audit read.
_STATUS_FILL = {
    "pass": "green", "fail": "red", "excluded": "grey",
    "manual": "grey", "not_assessed": "amber",
}
_HEADERS = ["Control", "Title", "Theme", "Applicable",
            "Justification", "Assessment", "Status", "Mapped checks",
            "How it is evidenced"]
_WIDTHS = [12, 42, 22, 11, 52, 13, 14, 32, 60]


def soa_to_xlsx(soa: dict[str, Any]) -> bytes:
    """Render an SoA dict to a presentable, audit-ready .xlsx workbook:
    title banner, frozen+filtered header, column widths, wrapped text, and
    colour-coded status/applicability."""
    from odineyes.core.xlsx_report import build_report_xlsx

    auto = sum(1 for c in soa["controls"] if c["assessment"] == "Automated")
    title = f"{soa['name']} — Statement of Applicability"
    version = f" v{soa['version']}" if soa.get("version") else ""
    subtitle = (f"Generated {soa['generated_at']}{version} · "
                f"{soa['applicable']}/{soa['total']} controls applicable · "
                f"{auto} automated, {soa['applicable'] - auto} manual")

    rows: list[list[Any]] = []
    for c in soa["controls"]:
        rows.append([
            c["id"], c["title"], c["theme"],
            "Yes" if c["applicable"] else "No",
            c["justification"], c["assessment"], c["status"],
            ", ".join(c["checks"]),
            c.get("cloud_guidance", ""),
        ])

    def fill(_di: int, col: int, value: str) -> Any:
        if col == 6:  # Status
            return _STATUS_FILL.get(value)
        if col == 3 and value == "No":  # Applicable = No → muted
            return "grey"
        return None

    return build_report_xlsx(
        title=title, subtitle=subtitle, headers=_HEADERS, rows=rows,
        sheet_name="SoA", col_widths=_WIDTHS,
        wrap_cols={1, 4, 7, 8}, center_cols={0, 3, 5, 6}, cell_fill=fill,
    )


def _demo() -> None:
    from odineyes.core.framework_import import parse_xlsx

    soa = build_soa("ISO27001")
    assert soa["total"] == 93 and soa["applicable"] == 93
    a824 = next(c for c in soa["controls"] if c["id"] == "A.8.24")
    assert a824["title"] == "Use of cryptography"
    # A.8.24 (cryptography) has checks mapped to it → Automated
    assert a824["assessment"] == "Automated", a824
    # A.6.1 (Screening) is people/manual
    a61 = next(c for c in soa["controls"] if c["id"] == "A.6.1")
    assert a61["assessment"] == "Manual"

    grid = parse_xlsx(soa_to_xlsx(soa))
    assert grid[2][:4] == ["Control", "Title", "Theme", "Applicable"]
    assert len(grid) == 3 + 93  # title + subtitle + header + 93 controls
    print("soa self-check passed: 93-control styled SoA round-trips to xlsx")


if __name__ == "__main__":
    _demo()
