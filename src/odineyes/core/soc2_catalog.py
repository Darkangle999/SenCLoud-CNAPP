"""SOC 2 — Trust Services Criteria (2017, rev. 2022) control catalog.

The criteria identifiers (CC1.1 … PI1.5) and their short titles are factual
identifiers of the AICPA Trust Services Criteria, reproduced widely (every SOC 2
readiness tool). The copyrighted points-of-focus / illustrative guidance prose
is NOT included — only the criteria list and category tree a SOC 2 report and
SoA need.

Scope: the Common Criteria (Security — required of every SOC 2) plus the
Availability, Confidentiality and Processing Integrity categories. The Privacy
category can be added as a sibling. The checks already carry their own SOC2
mappings, so no CHECK_MAP is needed: this module supplies the control tree;
per-check ``compliance`` supplies automated coverage; unmapped criteria are Manual.
"""

from __future__ import annotations

from typing import Any

CC1 = "CC1: Control Environment"
CC2 = "CC2: Communication and Information"
CC3 = "CC3: Risk Assessment"
CC4 = "CC4: Monitoring Activities"
CC5 = "CC5: Control Activities"
CC6 = "CC6: Logical and Physical Access Controls"
CC7 = "CC7: System Operations"
CC8 = "CC8: Change Management"
CC9 = "CC9: Risk Mitigation"
AV = "Availability"
CO = "Confidentiality"
PI = "Processing Integrity"

# (criterion_id, title, category)
_CONTROLS: list[tuple[str, str, str]] = [
    ("CC1.1", "Demonstrates commitment to integrity and ethical values", CC1),
    ("CC1.2", "Board of directors exercises oversight responsibility", CC1),
    ("CC1.3", "Establishes structures, reporting lines, authorities and responsibilities", CC1),
    ("CC1.4", "Demonstrates commitment to attract, develop and retain competent individuals", CC1),
    ("CC1.5", "Holds individuals accountable for internal control responsibilities", CC1),
    ("CC2.1", "Obtains or generates relevant, quality information to support internal control", CC2),
    ("CC2.2", "Internally communicates information needed to support internal control", CC2),
    ("CC2.3", "Communicates with external parties regarding internal control matters", CC2),
    ("CC3.1", "Specifies objectives with sufficient clarity to identify and assess risks", CC3),
    ("CC3.2", "Identifies and analyzes risk to the achievement of its objectives", CC3),
    ("CC3.3", "Considers the potential for fraud in assessing risks", CC3),
    ("CC3.4", "Identifies and assesses changes that could impact the system of internal control", CC3),
    ("CC4.1", "Selects, develops and performs ongoing/separate evaluations of controls", CC4),
    ("CC4.2", "Evaluates and communicates internal control deficiencies in a timely manner", CC4),
    ("CC5.1", "Selects and develops control activities that mitigate risks", CC5),
    ("CC5.2", "Selects and develops general control activities over technology", CC5),
    ("CC5.3", "Deploys control activities through policies and procedures", CC5),
    ("CC6.1", "Implements logical access security over protected information assets", CC6),
    ("CC6.2", "Registers and authorizes new internal and external users before issuing credentials", CC6),
    ("CC6.3", "Authorizes, modifies or removes access based on roles and least privilege", CC6),
    ("CC6.4", "Restricts physical access to facilities and protected information assets", CC6),
    ("CC6.5", "Discontinues protections over assets only after data has been securely removed", CC6),
    ("CC6.6", "Implements logical access measures against threats from outside system boundaries", CC6),
    ("CC6.7", "Restricts the transmission, movement and removal of information to authorized users", CC6),
    ("CC6.8", "Prevents or detects and acts upon the introduction of unauthorized/malicious software", CC6),
    ("CC7.1", "Uses detection and monitoring procedures to identify configuration changes and vulnerabilities", CC7),
    ("CC7.2", "Monitors system components for anomalies indicative of malicious acts or incidents", CC7),
    ("CC7.3", "Evaluates security events to determine whether they could become incidents", CC7),
    ("CC7.4", "Responds to identified security incidents with a defined incident-response program", CC7),
    ("CC7.5", "Identifies, develops and implements activities to recover from security incidents", CC7),
    ("CC8.1", "Authorizes, designs, develops, tests, approves and implements changes to infrastructure/software", CC8),
    ("CC9.1", "Identifies, selects and develops risk-mitigation activities for disruptions", CC9),
    ("CC9.2", "Assesses and manages risks associated with vendors and business partners", CC9),
    ("A1.1",  "Maintains, monitors and evaluates current processing capacity and use of resources", AV),
    ("A1.2",  "Authorizes, designs, develops and maintains environmental protections, backup and recovery", AV),
    ("A1.3",  "Tests recovery-plan procedures supporting system recovery", AV),
    ("C1.1",  "Identifies and maintains confidential information to meet objectives", CO),
    ("C1.2",  "Disposes of confidential information to meet objectives", CO),
    ("PI1.1", "Obtains/generates quality information about processing objectives", PI),
    ("PI1.2", "Implements policies and procedures over system inputs to meet objectives", PI),
    ("PI1.3", "Implements policies and procedures over system processing to meet objectives", PI),
    ("PI1.4", "Implements policies and procedures to make output available to meet objectives", PI),
    ("PI1.5", "Stores inputs/outputs completely, accurately and timely to meet objectives", PI),
]

# The exact SOC2 ids our checks declare; the catalog must be a superset.
_CHECK_DECLARED = frozenset({"A1.2", "CC6.1", "CC6.3", "CC6.7", "CC7.2", "CC7.4"})


def _build() -> dict[str, Any]:
    return {cid: {"title": title, "section": section} for cid, title, section in _CONTROLS}


SOC2_TSC: dict[str, Any] = _build()


def _demo() -> None:
    cat = SOC2_TSC
    assert len(cat) == len(_CONTROLS) == 43, len(cat)
    assert cat["CC6.1"]["section"] == CC6
    missing = _CHECK_DECLARED - set(cat)
    assert not missing, f"checks declare SOC2 ids absent from catalog: {sorted(missing)}"
    print(f"soc2_catalog self-check passed: {len(cat)} criteria")


if __name__ == "__main__":
    _demo()
