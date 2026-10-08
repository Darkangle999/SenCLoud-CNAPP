"""
Odineyes - Compliance Mapper
Maps security findings to compliance framework controls.
"""

from typing import List, Dict, Any, Optional
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from rich import box

from odineyes.core.cis_aws_catalog import CIS_AWS_FOUNDATIONS
from odineyes.core.cis_aws_compute_catalog import CIS_AWS_COMPUTE
from odineyes.core.cis_aws_euc_catalog import CIS_AWS_EUC
from odineyes.core.cis_aws_storage_catalog import CIS_AWS_STORAGE
from odineyes.core.gdpr_catalog import GDPR_ARTICLES
from odineyes.core.hipaa_catalog import HIPAA_SECURITY_RULE
from odineyes.core.iso27001_catalog import ANNEX_A_2022
from odineyes.core.nist_80053_catalog import NIST_800_53_REV5
from odineyes.core.pci_dss_catalog import PCI_DSS_V321
from odineyes.core.soc2_catalog import SOC2_TSC


# Full compliance framework definitions
FRAMEWORKS = {
    "CIS": {
        "name": "CIS Amazon Web Services Foundations Benchmark",
        "version": "1.5.0",
        # Full 62-control benchmark (5 sections). Controls that map to a config
        # check auto-assess via the CHECK_MAP overlay; the inherently-manual ones
        # (contact details, root-user hygiene, data classification) surface as
        # not_assessed — honest automated coverage, and what the SoA records.
        "controls": CIS_AWS_FOUNDATIONS,
    },
    "CIS-COMPUTE": {
        "name": "CIS AWS Compute Services Benchmark",
        "version": "2.0.0",
        # Service-category benchmark, generated from the published document text
        # (see core/cis_catalog_provenance.json). The CHECK_MAP overlay drives
        # auto-assessment; everything else surfaces as not_assessed.
        "controls": CIS_AWS_COMPUTE,
    },
    "CIS-STORAGE": {
        "name": "CIS AWS Storage Services Benchmark",
        "version": "1.0.0",
        # v1.0.0 is a Manual setup-guidance benchmark — nothing maps 1:1 to a
        # config check, so every control surfaces as not_assessed (honest).
        "controls": CIS_AWS_STORAGE,
    },
    "CIS-EUC": {
        "name": "CIS AWS End User Compute Services Benchmark",
        "version": "1.2.0",
        # Generated from the published document text; CHECK_MAP overlay drives
        # the (small) automated coverage.
        "controls": CIS_AWS_EUC,
    },
    "SOC2": {
        "name": "SOC 2 — Trust Services Criteria",
        "version": "2017",
        # Common Criteria (Security) + Availability/Confidentiality/Processing
        # Integrity. Mapped criteria auto-assess via each check's SOC2 mapping.
        "controls": SOC2_TSC,
    },
    "HIPAA": {
        "name": "HIPAA Security Rule",
        "version": "45 CFR Part 164",
        # Administrative/Physical/Technical/Organizational/Documentation safeguards.
        # A CSPM evidences the Technical Safeguards; the rest surface as Manual.
        "controls": HIPAA_SECURITY_RULE,
    },
    "PCI-DSS": {
        "name": "PCI DSS — Payment Card Industry Data Security Standard",
        "version": "3.2.1",
        # Full 12-requirement control tree. Controls that map to a config check
        # auto-assess via the check's own PCI mapping; the rest surface as Manual.
        "controls": PCI_DSS_V321,
    },
    "NIST": {
        "name": "NIST SP 800-53 Revision 5",
        "version": "Rev 5",
        # Security-relevant control subset (8 families). Mapped controls auto-assess
        # via each check's NIST mapping; unmapped controls surface as Manual.
        "controls": NIST_800_53_REV5,
    },
    "ISO27001": {
        "name": "ISO/IEC 27001:2022 (Annex A)",
        "version": "2022",
        # Full 93-control Annex A catalog (4 themes). A CSPM auto-assesses the
        # Technological (A.8) controls that map to cloud config; the rest surface
        # as not_assessed (manual) — honest, and what the SoA records.
        "controls": ANNEX_A_2022,
    },
    "GDPR": {
        "name": "General Data Protection Regulation (EU 2016/679)",
        "version": "2016/679",
        # Security-relevant articles. Technical-measures articles (Art.32, Art.25…)
        # auto-assess via the GDPR CHECK_MAP overlay; the rest are Manual.
        "controls": GDPR_ARTICLES,
    },
    "FedRAMP": {
        "name": "FedRAMP Moderate Baseline (NIST SP 800-53 Rev 5)",
        "version": "Rev 5",
        # FedRAMP baselines are selections of NIST SP 800-53 controls, so this
        # reuses the 800-53 control tree and inherits the checks' NIST mappings
        # (aliased at score/SoA time) for automated coverage.
        "controls": NIST_800_53_REV5,
    },
}


# Check category → human section name, used to label controls that a check maps
# to but FRAMEWORKS doesn't curate (so they don't all fall under "Other").
_SECTION_BY_CATEGORY = {
    "iam": "Identity and Access Management",
    "storage": "Storage",
    "network": "Networking",
    "networking": "Networking",
    "logging": "Logging",
    "monitoring": "Monitoring",
    "compute": "Compute",
    "encryption": "Encryption",
    "database": "Database",
}


class ComplianceMapper:
    """Maps security findings to compliance framework controls."""
    
    def __init__(self):
        self._registry = None
        self._check_lookup = None
    
    def _get_check_lookup(self) -> dict:
        """Lazily build and cache the check lookup table."""
        if self._check_lookup is None:
            from odineyes.core.check_registry import CheckRegistry
            self._registry = CheckRegistry()
            self._check_lookup = {c.check_id: c for c in self._registry._checks.values()}
        return self._check_lookup
    
    def map_finding(self, finding: Dict, frameworks: List[str]) -> Dict[str, List[str]]:
        """Map a single finding to relevant controls across specified frameworks."""
        check_compliance = finding.get("compliance_mappings_raw") or {}
        
        # Try to get from check metadata via check_id lookup
        checks = self._get_check_lookup()
        check = checks.get(finding.get("check_id"))
        if check:
            check_compliance = check.compliance
        
        result = {}
        for framework in frameworks:
            controls = check_compliance.get(framework, [])
            if controls:
                result[framework] = controls
        return result

    def score(self, findings: List[Dict], frameworks: List[str]) -> Dict[str, Any]:
        """Per-framework compliance score derived from scan findings.

        A control PASSES if every check mapped to it that actually ran passed.
        A control FAILS if any mapped check produced a fail/error finding.
        A control with no mapped check that ran is 'not_assessed' and is
        excluded from the score denominator (only ~39 checks exist, so most
        controls map to nothing — the UI surfaces the not_assessed count so the
        score stays honest).
        """
        checks = self._get_check_lookup()

        # Findings can repeat a check_id (one per resource). A check_id counts as
        # failing if ANY of its findings is fail/error; passing only if it ran and
        # never failed.
        fail_checks = {
            f.get("check_id") for f in findings
            if f.get("status") in ("fail", "error")
        }
        ran_checks = {f.get("check_id") for f in findings if f.get("check_id")}

        # Product customization overlay (sparse; empty = stock behaviour).
        from odineyes.core.config_store import load_config
        cfg = load_config()

        out: Dict[str, Any] = {}
        for fw_id in frameworks:
            fw = FRAMEWORKS.get(fw_id) or cfg.custom_frameworks.get(fw_id)
            if not fw:
                continue
            overrides = cfg.overrides.get(fw_id, {})

            # control -> set of check_ids mapped to it, for this framework
            ctrl_checks: Dict[str, set] = {}
            for cid, chk in checks.items():
                for ctrl in chk.compliance.get(fw_id, []):
                    ctrl_checks.setdefault(ctrl, set()).add(cid)
            # Also merge in compliance mappings carried by the findings themselves
            # (the DB rules engine stores rule_ids like WORLD_OPEN_SENSITIVE_PORT
            # with their own {"CIS": ["5.2"], ...} compliance dicts — these are
            # different IDs from the CheckRegistry and must be wired in here).
            for f in findings:
                cid = f.get("check_id")
                mappings = f.get("compliance_mappings") or {}
                for ctrl in mappings.get(fw_id, []):
                    ctrl_checks.setdefault(ctrl, set()).add(cid)
            # Custom frameworks declare their control→check mapping inline.
            for ctrl, meta in (fw.get("controls", {}) or {}).items():
                if isinstance(meta, dict):
                    for cid in meta.get("checks", []):
                        ctrl_checks.setdefault(ctrl, set()).add(cid)
            # Custom policies map their synthetic check_id (policy_id) to controls.
            for pol in cfg.custom_policies:
                for ctrl in pol["frameworks"].get(fw_id, []):
                    ctrl_checks.setdefault(ctrl, set()).add(pol["policy_id"])
            # Catalog check→control overlays (kept beside the catalog, not
            # threaded through every check class).
            if fw_id == "ISO27001":
                from odineyes.core.iso27001_catalog import merge_check_map
                merge_check_map(ctrl_checks)
            elif fw_id == "CIS":
                from odineyes.core.cis_aws_catalog import merge_check_map
                merge_check_map(ctrl_checks)
            elif fw_id == "CIS-COMPUTE":
                from odineyes.core.cis_aws_compute_catalog import merge_check_map
                merge_check_map(ctrl_checks)
            elif fw_id == "CIS-STORAGE":
                from odineyes.core.cis_aws_storage_catalog import merge_check_map
                merge_check_map(ctrl_checks)
            elif fw_id == "CIS-EUC":
                from odineyes.core.cis_aws_euc_catalog import merge_check_map
                merge_check_map(ctrl_checks)
            elif fw_id == "GDPR":
                from odineyes.core.gdpr_catalog import merge_check_map
                merge_check_map(ctrl_checks)
            elif fw_id == "FedRAMP":
                # FedRAMP control ids ARE NIST 800-53 ids; reuse each check's
                # NIST mapping so the baseline gets the same automated coverage.
                for cid, chk in checks.items():
                    for ctrl in chk.compliance.get("NIST", []):
                        ctrl_checks.setdefault(ctrl, set()).add(cid)

            # Score over the UNION of curated controls and every control a check
            # actually maps to — otherwise a check whose control isn't hand-listed
            # in FRAMEWORKS has its result silently discarded. Curated entries
            # keep their rich title/section; check-only controls borrow the
            # mapped check's name + category so they read as something better than
            # the bare control id.
            defined = fw.get("controls", {})
            universe: Dict[str, Dict[str, Any]] = dict(defined)
            for ctrl, cids in ctrl_checks.items():
                if ctrl in universe:
                    continue
                sample = next((checks[c] for c in sorted(cids) if c in checks), None)
                if sample is not None:
                    title = getattr(sample, "name", None) or ctrl
                    section = _SECTION_BY_CATEGORY.get(
                        (getattr(sample, "category", "") or "").lower(), "Other")
                else:
                    title, section = ctrl, "Other"
                universe[ctrl] = {"title": f"{ctrl} — {title}", "section": section}

            sections: Dict[str, Dict[str, int]] = {}
            passing = total = not_assessed = 0
            controls_out = []

            for ctrl, meta in universe.items():
                ov = overrides.get(ctrl)
                if ov and not ov["enabled"]:
                    continue  # control toggled off — drop from scoring entirely

                mapped = ctrl_checks.get(ctrl, set())
                assessed = mapped & ran_checks
                if not assessed:
                    state = "not_assessed"
                elif assessed & fail_checks:
                    state = "fail"
                else:
                    state = "pass"

                sec = meta.get("section", "Other")
                s = sections.setdefault(sec, {"passing": 0, "total": 0})
                if state == "not_assessed":
                    not_assessed += 1
                else:
                    total += 1
                    s["total"] += 1
                    if state == "pass":
                        passing += 1
                        s["passing"] += 1

                entry = {
                    "id": ctrl,
                    "title": meta.get("title", ctrl),
                    "section": sec,
                    "state": state,
                    "checks": sorted(mapped),
                }
                # Stamp override metadata only when one applies — stock output unchanged.
                if ov:
                    if ov.get("severity"):
                        entry["severity"] = ov["severity"]
                    if ov.get("note"):
                        entry["note"] = ov["note"]
                    if ov.get("waived_until"):
                        entry["waived_until"] = ov["waived_until"]
                controls_out.append(entry)

            for s in sections.values():
                s["pct"] = round(s["passing"] / s["total"] * 100) if s["total"] else 0

            out[fw_id] = {
                "name": fw.get("name", fw_id),
                "version": fw.get("version"),
                "score": round(passing / total * 100) if total else 0,
                "passing": passing,
                "total": total,
                "not_assessed": not_assessed,
                "sections": sections,
                "controls": controls_out,
            }
        return out

    def display_framework(
        self,
        framework: str,
        provider: str,
        output_format: str,
        output_path: Optional[str],
        console: Console,
    ):
        """Display compliance framework controls and check mappings."""
        if framework not in FRAMEWORKS:
            console.print(f"[red]Unknown framework: {framework}[/red]")
            return
        
        fw = FRAMEWORKS[framework]
        
        console.print(Panel(
            f"[bold white]{fw['name']}[/bold white]\n"
            f"Version: [cyan]{fw.get('version', 'N/A')}[/cyan]  |  "
            f"Provider Filter: [cyan]{provider.upper()}[/cyan]",
            title=f"[bold blue]📋 {framework} Compliance Framework[/bold blue]",
            border_style="blue",
        ))
        
        from odineyes.core.check_registry import CheckRegistry
        registry = CheckRegistry()
        all_checks = registry.resolve_checks([provider], ["all"], [], [])
        
        # Build control → checks mapping
        control_checks: Dict[str, List] = {}
        for check in all_checks:
            controls = check.compliance.get(framework, [])
            for ctrl in controls:
                control_checks.setdefault(ctrl, []).append(check)
        
        table = Table(
            title=f"[bold]{framework} Controls[/bold]",
            box=box.ROUNDED, border_style="blue", show_lines=True,
        )
        table.add_column("Control ID", style="cyan", width=12)
        table.add_column("Title", style="white", width=45)
        table.add_column("Checks", style="magenta", width=25)
        table.add_column("Status", width=12)
        
        for ctrl_id, ctrl_info in fw.get("controls", {}).items():
            mapped_checks = control_checks.get(ctrl_id, [])
            check_names = ", ".join(c.check_id for c in mapped_checks[:3])
            if len(mapped_checks) > 3:
                check_names += f" +{len(mapped_checks)-3}"
            
            status = "[green]Covered[/green]" if mapped_checks else "[yellow]Manual[/yellow]"
            table.add_row(
                ctrl_id,
                ctrl_info.get("title", "")[:45],
                check_names or "-",
                status,
            )
        
        console.print(table)
        
        # Coverage stats
        covered = sum(1 for ctrl in fw["controls"] if ctrl in control_checks)
        total = len(fw["controls"])
        pct = (covered / total * 100) if total > 0 else 0
        
        console.print(
            f"\n[bold]Coverage:[/bold] [cyan]{covered}/{total}[/cyan] controls "
            f"([{'green' if pct >= 80 else 'yellow'}]{pct:.0f}%[/])"
        )
        
        if output_path:
            import json
            data = {
                "framework": framework,
                "provider": provider,
                "version": fw.get("version"),
                "coverage": {"covered": covered, "total": total, "percentage": round(pct, 1)},
                "controls": fw["controls"],
                "check_mappings": {k: [c.check_id for c in v] for k, v in control_checks.items()},
            }
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)
            console.print(f"[green]✓ Saved to {output_path}[/green]")
