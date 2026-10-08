"""PCI DSS v3.2.1 — Payment Card Industry Data Security Standard control catalog.

The requirement numbers (1.1 … 12.3) and their short titles are factual
identifiers of the published standard, reproduced widely (AWS Audit Manager,
every CSPM). The copyrighted testing-procedure/guidance prose from the PCI SSC
document is NOT included — only the requirement list and the twelve top-level
sections a compliance report and SoA need.

Version note: the platform's checks declare PCI requirement numbers in v3.2.1
form (8.2.3, 10.5.2, 1.3.1 …); this catalog matches that numbering so automated
coverage lines up exactly. v4.0 (renumbered) can be added as a sibling catalog.

The checks already carry their own PCI mappings, so — unlike the ISO/CIS
catalogs — no CHECK_MAP overlay is needed: this module supplies the full control
tree (the scoring denominator + titles); the per-check ``compliance`` dicts
supply the automated coverage. Controls no check maps to surface as Manual.
"""

from __future__ import annotations

from typing import Any

R1 = "Requirement 1: Install and maintain a firewall configuration"
R2 = "Requirement 2: Do not use vendor-supplied defaults"
R3 = "Requirement 3: Protect stored cardholder data"
R4 = "Requirement 4: Encrypt transmission across open, public networks"
R5 = "Requirement 5: Protect all systems against malware"
R6 = "Requirement 6: Develop and maintain secure systems and applications"
R7 = "Requirement 7: Restrict access by business need to know"
R8 = "Requirement 8: Identify and authenticate access to system components"
R9 = "Requirement 9: Restrict physical access to cardholder data"
R10 = "Requirement 10: Track and monitor all access"
R11 = "Requirement 11: Regularly test security systems and processes"
R12 = "Requirement 12: Maintain an information security policy"

# (control_id, title, section)
_CONTROLS: list[tuple[str, str, str]] = [
    # ── Requirement 1 ───────────────────────────────────────────────────────
    ("1.1",   "Establish and implement firewall and router configuration standards", R1),
    ("1.2",   "Build firewall/router configurations that restrict connections to untrusted networks", R1),
    ("1.3",   "Prohibit direct public access between the Internet and any system component in the CDE", R1),
    ("1.3.1", "Implement a DMZ to limit inbound traffic to only authorized services/protocols/ports", R1),
    ("1.3.2", "Limit inbound Internet traffic to IP addresses within the DMZ", R1),
    ("1.3.4", "Do not allow unauthorized outbound traffic from the CDE to the Internet", R1),
    ("1.4",   "Install personal firewall software on portable computing devices", R1),
    # ── Requirement 2 ───────────────────────────────────────────────────────
    ("2.1",   "Always change vendor-supplied defaults before installing a system on the network", R2),
    ("2.2",   "Develop configuration standards for all system components", R2),
    ("2.2.2", "Enable only necessary services, protocols and daemons", R2),
    ("2.3",   "Encrypt all non-console administrative access using strong cryptography", R2),
    ("2.4",   "Maintain an inventory of system components in scope for PCI DSS", R2),
    # ── Requirement 3 ───────────────────────────────────────────────────────
    ("3.1",   "Keep cardholder data storage to a minimum", R3),
    ("3.4",   "Render PAN unreadable anywhere it is stored", R3),
    ("3.5",   "Document and implement procedures to protect keys used to secure stored cardholder data", R3),
    ("3.5.2", "Restrict access to cryptographic keys to the fewest custodians necessary", R3),
    ("3.6",   "Fully document and implement key-management processes and procedures", R3),
    ("3.6.4", "Cryptographic key changes for keys that have reached the end of their cryptoperiod", R3),
    # ── Requirement 4 ───────────────────────────────────────────────────────
    ("4.1",   "Use strong cryptography and security protocols to safeguard cardholder data in transit", R4),
    ("4.2",   "Never send unprotected PANs by end-user messaging technologies", R4),
    # ── Requirement 5 ───────────────────────────────────────────────────────
    ("5.1",   "Deploy anti-virus software on all systems commonly affected by malicious software", R5),
    ("5.2",   "Ensure that all anti-virus mechanisms are maintained and generating audit logs", R5),
    # ── Requirement 6 ───────────────────────────────────────────────────────
    ("6.1",   "Establish a process to identify security vulnerabilities and assign a risk ranking", R6),
    ("6.2",   "Protect all system components from known vulnerabilities by installing security patches", R6),
    ("6.5",   "Address common coding vulnerabilities in software-development processes", R6),
    # ── Requirement 7 ───────────────────────────────────────────────────────
    ("7.1",   "Limit access to system components and cardholder data to only those who need it", R7),
    ("7.1.2", "Restrict access to privileged user IDs to least privileges necessary", R7),
    ("7.2",   "Establish an access-control system that restricts access based on need to know", R7),
    # ── Requirement 8 ───────────────────────────────────────────────────────
    ("8.1.1", "Assign all users a unique ID before allowing them to access system components", R8),
    ("8.2",   "Employ at least one authentication method (something you know/have/are)", R8),
    ("8.2.3", "Passwords/passphrases must meet minimum length and complexity requirements", R8),
    ("8.2.4", "Change user passwords/passphrases at least once every 90 days", R8),
    ("8.3.1", "Incorporate multi-factor authentication for all non-console access into the CDE", R8),
    # ── Requirement 9 ───────────────────────────────────────────────────────
    ("9.1",   "Use appropriate facility entry controls to limit and monitor physical access", R9),
    ("9.5",   "Physically secure all media", R9),
    # ── Requirement 10 ──────────────────────────────────────────────────────
    ("10.1",   "Implement audit trails to link all access to system components to each user", R10),
    ("10.2",   "Implement automated audit trails for all system components", R10),
    ("10.2.2", "Record all actions taken by any individual with root or administrative privileges", R10),
    ("10.5",   "Secure audit trails so they cannot be altered", R10),
    ("10.5.2", "Protect audit trail files from unauthorized modifications", R10),
    ("10.5.5", "Use file-integrity monitoring or change-detection software on logs", R10),
    ("10.7",   "Retain audit trail history for at least one year", R10),
    # ── Requirement 11 ──────────────────────────────────────────────────────
    ("11.2",  "Run internal and external network vulnerability scans regularly", R11),
    ("11.4",  "Use intrusion-detection and/or intrusion-prevention techniques", R11),
    ("11.5",  "Deploy a change-detection mechanism to alert on unauthorized modification of critical files", R11),
    # ── Requirement 12 ──────────────────────────────────────────────────────
    ("12.1",  "Establish, publish, maintain and disseminate a security policy", R12),
    ("12.3",  "Develop usage policies for critical technologies", R12),
]

# The exact PCI ids our checks declare (kept as an invariant: the catalog must be
# a superset, or score() would surface a check-mapped requirement as a phantom).
_CHECK_DECLARED = frozenset({
    "1.3", "1.3.1", "1.3.2", "3.5", "3.6.4", "4.1", "7.1", "7.1.2", "8.1.1",
    "8.2.3", "8.2.4", "8.3.1", "9.5", "10.1", "10.2", "10.5.2", "10.5.5",
    "11.4", "11.5",
})


def _build() -> dict[str, Any]:
    return {cid: {"title": title, "section": section} for cid, title, section in _CONTROLS}


PCI_DSS_V321: dict[str, Any] = _build()


def _demo() -> None:
    cat = PCI_DSS_V321
    assert len(cat) == len(_CONTROLS) == 47, len(cat)
    assert len({m["section"] for m in cat.values()}) == 12  # twelve requirements
    assert cat["8.3.1"]["title"].startswith("Incorporate multi-factor")
    missing = _CHECK_DECLARED - set(cat)
    assert not missing, f"checks declare PCI ids absent from catalog: {sorted(missing)}"
    print(f"pci_dss_catalog self-check passed: {len(cat)} controls, 12 requirements")


if __name__ == "__main__":
    _demo()
