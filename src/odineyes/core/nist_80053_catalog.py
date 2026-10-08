"""NIST SP 800-53 Revision 5 — security-control catalog (cloud-relevant subset).

The control identifiers (AC-2, AU-9, SC-28 …) and their titles are factual
identifiers of the publicly-released NIST catalog (NIST publications are U.S.
Government works, not subject to copyright). The full catalog is ~1000 controls
across 20 families; reproducing all of it is neither useful nor honest for a
CSPM, so this is the curated subset a cloud-posture tool actually assesses —
the security-relevant families and their baseline controls, plus every control
our checks map to.

Like the PCI catalog (and unlike ISO/CIS), the checks already carry their own
NIST mappings, so no CHECK_MAP overlay is needed: this module supplies the
control tree (denominator + titles); the per-check ``compliance`` dicts supply
automated coverage. Controls no check maps to surface as Manual.
"""

from __future__ import annotations

from typing import Any

AC = "Access Control (AC)"
AU = "Audit and Accountability (AU)"
CM = "Configuration Management (CM)"
CP = "Contingency Planning (CP)"
IA = "Identification and Authentication (IA)"
RA = "Risk Assessment (RA)"
SC = "System and Communications Protection (SC)"
SI = "System and Information Integrity (SI)"

# (control_id, title, family)
_CONTROLS: list[tuple[str, str, str]] = [
    # ── Access Control ──────────────────────────────────────────────────────
    ("AC-2",    "Account Management", AC),
    ("AC-3",    "Access Enforcement", AC),
    ("AC-4",    "Information Flow Enforcement", AC),
    ("AC-5",    "Separation of Duties", AC),
    ("AC-6",    "Least Privilege", AC),
    ("AC-17",   "Remote Access", AC),
    ("AC-18",   "Wireless Access", AC),
    ("AC-19",   "Access Control for Mobile Devices", AC),
    # ── Audit and Accountability ────────────────────────────────────────────
    ("AU-2",    "Event Logging", AU),
    ("AU-3",    "Content of Audit Records", AU),
    ("AU-6",    "Audit Record Review, Analysis, and Reporting", AU),
    ("AU-9",    "Protection of Audit Information", AU),
    ("AU-11",   "Audit Record Retention", AU),
    ("AU-12",   "Audit Record Generation", AU),
    # ── Configuration Management ────────────────────────────────────────────
    ("CM-2",    "Baseline Configuration", CM),
    ("CM-6",    "Configuration Settings", CM),
    ("CM-7",    "Least Functionality", CM),
    ("CM-8",    "System Component Inventory", CM),
    # ── Contingency Planning ────────────────────────────────────────────────
    ("CP-9",    "System Backup", CP),
    # ── Identification and Authentication ───────────────────────────────────
    ("IA-2",    "Identification and Authentication (Organizational Users)", IA),
    ("IA-2(1)", "Multi-Factor Authentication to Privileged Accounts", IA),
    ("IA-5",    "Authenticator Management", IA),
    ("IA-5(1)", "Password-Based Authentication", IA),
    ("IA-8",    "Identification and Authentication (Non-Organizational Users)", IA),
    # ── Risk Assessment ─────────────────────────────────────────────────────
    ("RA-5",    "Vulnerability Monitoring and Scanning", RA),
    # ── System and Communications Protection ────────────────────────────────
    ("SC-7",    "Boundary Protection", SC),
    ("SC-8",    "Transmission Confidentiality and Integrity", SC),
    ("SC-12",   "Cryptographic Key Establishment and Management", SC),
    ("SC-13",   "Cryptographic Protection", SC),
    ("SC-28",   "Protection of Information at Rest", SC),
    # ── System and Information Integrity ────────────────────────────────────
    ("SI-2",    "Flaw Remediation", SI),
    ("SI-3",    "Malicious Code Protection", SI),
    ("SI-4",    "System Monitoring", SI),
    ("SI-7",    "Software, Firmware, and Information Integrity", SI),
    ("SI-10",   "Information Input Validation", SI),
]

# The exact NIST ids our checks declare; the catalog must be a superset so no
# check-mapped control renders as a phantom outside the tree.
_CHECK_DECLARED = frozenset({
    "AC-2", "AC-3", "AC-6", "AC-17", "AU-2", "AU-6", "AU-9", "AU-12", "CM-8",
    "IA-2(1)", "IA-5(1)", "SC-7", "SC-8", "SC-12", "SC-28", "SI-4", "SI-10",
})


def _build() -> dict[str, Any]:
    return {cid: {"title": title, "section": family} for cid, title, family in _CONTROLS}


NIST_800_53_REV5: dict[str, Any] = _build()


def _demo() -> None:
    cat = NIST_800_53_REV5
    assert len(cat) == len(_CONTROLS) == 35, len(cat)
    assert len({m["section"] for m in cat.values()}) == 8  # eight families
    assert cat["SC-28"]["title"] == "Protection of Information at Rest"
    assert cat["IA-2(1)"]["section"] == IA
    missing = _CHECK_DECLARED - set(cat)
    assert not missing, f"checks declare NIST ids absent from catalog: {sorted(missing)}"
    print(f"nist_80053_catalog self-check passed: {len(cat)} controls, 8 families")


if __name__ == "__main__":
    _demo()
