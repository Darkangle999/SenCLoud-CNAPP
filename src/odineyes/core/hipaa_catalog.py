"""HIPAA Security Rule (45 CFR Part 164, Subpart C) — safeguard catalog.

The citation numbers (164.308 … 164.316) and short titles are factual
identifiers of the published U.S. regulation (a Government work, not subject to
copyright). This module lists the standards and implementation specifications a
HIPAA report and SoA need; it does not reproduce interpretive guidance.

The checks already carry their own HIPAA mappings, so no CHECK_MAP is needed:
this module supplies the control tree; per-check ``compliance`` supplies
automated coverage. A CSPM evidences the Technical Safeguards (164.312); the
Administrative/Physical/Organizational safeguards are inherently Manual.
"""

from __future__ import annotations

from typing import Any

ADMIN = "Administrative Safeguards (164.308)"
PHYS = "Physical Safeguards (164.310)"
TECH = "Technical Safeguards (164.312)"
ORG = "Organizational Requirements (164.314)"
DOC = "Documentation Requirements (164.316)"

# (citation, title, section)
_CONTROLS: list[tuple[str, str, str]] = [
    # ── Administrative Safeguards ───────────────────────────────────────────
    ("164.308(a)(1)(i)",      "Security Management Process", ADMIN),
    ("164.308(a)(1)(ii)(A)",  "Risk Analysis (Required)", ADMIN),
    ("164.308(a)(1)(ii)(B)",  "Risk Management (Required)", ADMIN),
    ("164.308(a)(1)(ii)(C)",  "Sanction Policy (Required)", ADMIN),
    ("164.308(a)(1)(ii)(D)",  "Information System Activity Review (Required)", ADMIN),
    ("164.308(a)(2)",         "Assigned Security Responsibility", ADMIN),
    ("164.308(a)(3)(i)",      "Workforce Security", ADMIN),
    ("164.308(a)(4)(i)",      "Information Access Management", ADMIN),
    ("164.308(a)(4)(ii)(B)",  "Access Authorization (Addressable)", ADMIN),
    ("164.308(a)(4)(ii)(C)",  "Access Establishment and Modification (Addressable)", ADMIN),
    ("164.308(a)(5)(i)",      "Security Awareness and Training", ADMIN),
    ("164.308(a)(6)(i)",      "Security Incident Procedures", ADMIN),
    ("164.308(a)(6)(ii)",     "Response and Reporting (Required)", ADMIN),
    ("164.308(a)(7)(i)",      "Contingency Plan", ADMIN),
    ("164.308(a)(7)(ii)(A)",  "Data Backup Plan (Required)", ADMIN),
    ("164.308(a)(7)(ii)(B)",  "Disaster Recovery Plan (Required)", ADMIN),
    ("164.308(a)(8)",         "Evaluation", ADMIN),
    ("164.308(b)(1)",         "Business Associate Contracts", ADMIN),
    # ── Physical Safeguards ─────────────────────────────────────────────────
    ("164.310(a)(1)",         "Facility Access Controls", PHYS),
    ("164.310(b)",            "Workstation Use", PHYS),
    ("164.310(c)",            "Workstation Security", PHYS),
    ("164.310(d)(1)",         "Device and Media Controls", PHYS),
    ("164.310(d)(2)(i)",      "Disposal (Required)", PHYS),
    ("164.310(d)(2)(ii)",     "Media Re-use (Required)", PHYS),
    # ── Technical Safeguards (where a CSPM provides evidence) ───────────────
    ("164.312(a)(1)",         "Access Control", TECH),
    ("164.312(a)(2)(i)",      "Unique User Identification (Required)", TECH),
    ("164.312(a)(2)(ii)",     "Emergency Access Procedure (Required)", TECH),
    ("164.312(a)(2)(iii)",    "Automatic Logoff (Addressable)", TECH),
    ("164.312(a)(2)(iv)",     "Encryption and Decryption (Addressable)", TECH),
    ("164.312(b)",            "Audit Controls", TECH),
    ("164.312(c)(1)",         "Integrity", TECH),
    ("164.312(c)(2)",         "Mechanism to Authenticate ePHI (Addressable)", TECH),
    ("164.312(d)",            "Person or Entity Authentication", TECH),
    ("164.312(e)(1)",         "Transmission Security", TECH),
    ("164.312(e)(2)(i)",      "Integrity Controls (Addressable)", TECH),
    ("164.312(e)(2)(ii)",     "Encryption (Addressable)", TECH),
    # ── Organizational + Documentation ──────────────────────────────────────
    ("164.314(a)(1)",         "Business Associate Contracts or Other Arrangements", ORG),
    ("164.316(a)",            "Policies and Procedures", DOC),
    ("164.316(b)(1)",         "Documentation", DOC),
]

# The exact HIPAA ids our checks declare; the catalog must be a superset.
_CHECK_DECLARED = frozenset({
    "164.312(a)(1)", "164.312(a)(2)(i)", "164.312(a)(2)(iv)",
    "164.312(b)", "164.312(c)(1)",
})


def _build() -> dict[str, Any]:
    return {cid: {"title": title, "section": section} for cid, title, section in _CONTROLS}


HIPAA_SECURITY_RULE: dict[str, Any] = _build()


def _demo() -> None:
    cat = HIPAA_SECURITY_RULE
    assert len(cat) == len(_CONTROLS) == 39, len(cat)
    assert len({m["section"] for m in cat.values()}) == 5
    assert cat["164.312(a)(2)(iv)"]["title"].startswith("Encryption")
    missing = _CHECK_DECLARED - set(cat)
    assert not missing, f"checks declare HIPAA ids absent from catalog: {sorted(missing)}"
    print(f"hipaa_catalog self-check passed: {len(cat)} specifications")


if __name__ == "__main__":
    _demo()
