"""ISO/IEC 27001:2022 Annex A control catalog — all 93 controls, 4 themes.

Control reference numbers (A.5.1 … A.8.34) and their short titles are factual
identifiers of the standard, reproduced widely (including MIT-licensed toolkits
such as github.com/PehanIn/ISO-27001-2022-Toolkit, which inspired fleshing this
out). The copyrighted implementation guidance from ISO/IEC 27002 is NOT included
— only the control list a Statement of Applicability needs.

A CSPM can auto-assess the Technological (A.8) controls that map to cloud config;
the Organizational/People/Physical controls are inherently manual and surface as
``not_assessed`` — which is honest, and exactly what an SoA records.
"""

from __future__ import annotations

from typing import Any

ORGANIZATIONAL = "Organizational controls"
PEOPLE = "People controls"
PHYSICAL = "Physical controls"
TECHNOLOGICAL = "Technological controls"

# Titles in control-number order; the index gives the suffix (A.5.1, A.5.2, …).
_ORG = [
    "Policies for information security",
    "Information security roles and responsibilities",
    "Segregation of duties",
    "Management responsibilities",
    "Contact with authorities",
    "Contact with special interest groups",
    "Threat intelligence",
    "Information security in project management",
    "Inventory of information and other associated assets",
    "Acceptable use of information and other associated assets",
    "Return of assets",
    "Classification of information",
    "Labelling of information",
    "Information transfer",
    "Access control",
    "Identity management",
    "Authentication information",
    "Access rights",
    "Information security in supplier relationships",
    "Addressing information security within supplier agreements",
    "Managing information security in the ICT supply chain",
    "Monitoring, review and change management of supplier services",
    "Information security for use of cloud services",
    "Information security incident management planning and preparation",
    "Assessment and decision on information security events",
    "Response to information security incidents",
    "Learning from information security incidents",
    "Collection of evidence",
    "Information security during disruption",
    "ICT readiness for business continuity",
    "Legal, statutory, regulatory and contractual requirements",
    "Intellectual property rights",
    "Protection of records",
    "Privacy and protection of personal identifiable information (PII)",
    "Independent review of information security",
    "Compliance with policies, rules and standards for information security",
    "Documented operating procedures",
]
_PEOPLE = [
    "Screening",
    "Terms and conditions of employment",
    "Information security awareness, education and training",
    "Disciplinary process",
    "Responsibilities after termination or change of employment",
    "Confidentiality or non-disclosure agreements",
    "Remote working",
    "Information security event reporting",
]
_PHYSICAL = [
    "Physical security perimeters",
    "Physical entry",
    "Securing offices, rooms and facilities",
    "Physical security monitoring",
    "Protecting against physical and environmental threats",
    "Working in secure areas",
    "Clear desk and clear screen",
    "Equipment siting and protection",
    "Security of assets off-premises",
    "Storage media",
    "Supporting utilities",
    "Cabling security",
    "Equipment maintenance",
    "Secure disposal or re-use of equipment",
]
_TECH = [
    "User endpoint devices",
    "Privileged access rights",
    "Information access restriction",
    "Access to source code",
    "Secure authentication",
    "Capacity management",
    "Protection against malware",
    "Management of technical vulnerabilities",
    "Configuration management",
    "Information deletion",
    "Data masking",
    "Data leakage prevention",
    "Information backup",
    "Redundancy of information processing facilities",
    "Logging",
    "Monitoring activities",
    "Clock synchronization",
    "Use of privileged utility programs",
    "Installation of software on operational systems",
    "Networks security",
    "Security of network services",
    "Segregation of networks",
    "Web filtering",
    "Use of cryptography",
    "Secure development life cycle",
    "Application security requirements",
    "Secure system architecture and engineering principles",
    "Secure coding",
    "Security testing in development and acceptance",
    "Outsourced development",
    "Separation of development, test and production environments",
    "Change management",
    "Test information",
    "Protection of information systems during audit testing",
]


# Curated map of Annex A control → the platform checks that provide evidence for
# it. The check classes carry CIS/NIST mappings inline; rather than edit ~20 of
# them, this overlay is merged at score/SoA time so the Technological (A.8)
# controls auto-assess. Only controls a CSPM can actually evidence are listed —
# the rest stay Manual, which is honest.
CHECK_MAP: dict[str, list[str]] = {
    "A.5.15": ["iam_aws_007", "storage_aws_001", "network_aws_001", "network_aws_003"],  # Access control
    "A.5.17": ["iam_aws_002", "iam_aws_003"],                                            # Authentication information
    "A.5.18": ["iam_aws_004", "iam_aws_007", "iam_aws_008"],                             # Access rights
    "A.8.2":  ["iam_aws_004", "iam_aws_006", "iam_aws_007"],                             # Privileged access rights
    "A.8.3":  ["storage_aws_001", "storage_aws_003", "network_aws_005",
               "compute_aws_003", "compute_aws_004"],                                    # Information access restriction
    "A.8.5":  ["iam_aws_001", "iam_aws_005", "iam_aws_002"],                             # Secure authentication
    "A.8.8":  ["compute_aws_001", "logging_aws_004", "logging_aws_005"],                 # Technical vulnerabilities
    "A.8.9":  ["logging_aws_006"],                                                       # Configuration management
    "A.8.13": ["storage_aws_004", "storage_aws_006"],                                    # Information backup
    "A.8.15": ["logging_aws_001", "logging_aws_003", "network_aws_002"],                 # Logging
    "A.8.16": ["logging_aws_004", "logging_aws_005", "logging_aws_007", "network_aws_002"],  # Monitoring
    "A.8.20": ["network_aws_001", "network_aws_003", "network_aws_004", "storage_aws_003"],  # Networks security
    "A.8.21": ["storage_aws_003"],                                                       # Security of network services
    "A.8.22": ["network_aws_004"],                                                       # Segregation of networks
    "A.8.24": ["storage_aws_002", "compute_aws_002", "storage_aws_005",
               "encryption_aws_001", "logging_aws_002"],                                 # Use of cryptography
    # --- added: controls a CSPM can defensibly evidence -------------------
    # The bar for adding a row here is that a failing check would be real
    # evidence of the control being unmet. Padding the map would raise the
    # automated-coverage number and lower the value of the SoA, so controls
    # with only a tenuous link (A.8.6 capacity, A.8.11 masking, A.8.17 clock
    # sync, A.8.23 web filtering) are deliberately left Manual.
    "A.5.7":  ["logging_aws_004"],                                                       # Threat intelligence
    # Already reachable through custom_s3_001's own inline mapping. Listed here
    # too so the control carries guidance: the SoA marks a control Automated
    # from either source, and an "Automated" row with no explanation of how is
    # exactly the row an auditor stops on.
    "A.5.9":  ["custom_s3_001"],                                                         # Inventory of assets
    "A.5.16": ["iam_aws_003", "iam_aws_004", "iam_aws_005"],                             # Identity management
    "A.5.23": ["storage_aws_001", "logging_aws_001", "iam_aws_001"],                     # InfoSec for cloud services
    "A.5.28": ["logging_aws_003"],                                                       # Collection of evidence
    "A.5.33": ["logging_aws_002", "logging_aws_003", "storage_aws_004"],                 # Protection of records
    "A.8.7":  ["logging_aws_004"],                                                       # Protection against malware
    "A.8.12": ["storage_aws_001", "compute_aws_003", "compute_aws_004",
               "network_aws_005"],                                                       # Data leakage prevention
    "A.8.32": ["logging_aws_006", "logging_aws_001", "logging_aws_003"],                 # Change management
}


# How each auto-assessed control is evidenced in AWS. Written here rather than
# quoted: ISO/IEC 27002's implementation guidance is copyrighted and is NOT
# reproduced anywhere in this file. This is our own description of what the
# platform actually checks, which is what an auditor asking "how do you know?"
# needs, and what a Statement of Applicability records next to the control.
CLOUD_GUIDANCE: dict[str, str] = {
    "A.5.7":  "GuardDuty consumes AWS and third-party threat intelligence feeds; "
              "the control is evidenced by the detector being enabled in every region.",
    "A.5.9":  "Every scanned resource is recorded as an asset; the tagging check "
              "evidences that the inventory carries the ownership metadata the "
              "control requires, rather than merely existing.",
    "A.5.15": "Evidenced by S3 public access blocks, security groups closed to the "
              "world, and no IAM user holding AdministratorAccess.",
    "A.5.16": "Evidenced by access-key rotation age, absence of root access keys, "
              "and MFA on every console-enabled IAM user.",
    "A.5.17": "Evidenced by the account password policy and access-key rotation age.",
    "A.5.18": "Evidenced by the absence of root access keys, no user-attached "
              "AdministratorAccess, and a support-access role existing.",
    "A.5.23": "The whole posture scan is the evidence; these checks are the "
              "representative sample recorded against the control.",
    "A.5.28": "CloudTrail log file validation produces the digest files that prove "
              "collected evidence was not altered after the fact.",
    "A.5.33": "Evidenced by CloudTrail log encryption, log file validation and S3 "
              "versioning on the buckets holding the records.",
    "A.8.2":  "Evidenced by no root access keys, no inline policies and no IAM user "
              "carrying AdministratorAccess.",
    "A.8.3":  "Evidenced by S3 public access blocks, TLS-enforcing bucket policies, "
              "non-public AMIs and Lambda functions, and private RDS instances.",
    "A.8.5":  "Evidenced by root MFA, per-user console MFA and the password policy.",
    "A.8.7":  "GuardDuty Malware Protection is the detective control; the check "
              "evidences that it is switched on.",
    "A.8.8":  "Evidenced by IMDSv2 enforcement plus GuardDuty and Security Hub, "
              "which surface the vulnerability findings this control manages.",
    "A.8.9":  "AWS Config records the configuration state and its drift over time.",
    "A.8.12": "Evidenced by the egress paths a CSPM can see: public access blocks, "
              "non-public AMIs and Lambda functions, and private RDS endpoints.",
    "A.8.13": "Evidenced by S3 versioning and an RDS backup retention window of at "
              "least seven days.",
    "A.8.15": "Evidenced by multi-region CloudTrail, log file validation and VPC "
              "flow logs.",
    "A.8.16": "Evidenced by GuardDuty, Security Hub, a root-login CloudWatch alarm "
              "and VPC flow logs.",
    "A.8.20": "Evidenced by security groups closed to the world on SSH and RDP, "
              "restricted NACLs and TLS-enforcing bucket policies.",
    "A.8.21": "Evidenced by bucket policies that refuse non-TLS requests.",
    "A.8.22": "Evidenced by network ACLs that do not permit unrestricted inbound.",
    "A.8.24": "Evidenced by encryption at rest on S3, EBS and RDS, CloudTrail log "
              "encryption, and KMS key rotation.",
    "A.8.32": "AWS Config plus CloudTrail with log file validation provide the "
              "tamper-evident record of what changed, when and by whom.",
}


def merge_check_map(ctrl_checks: dict[str, set]) -> None:
    """Merge CHECK_MAP into a {control_id: set(check_ids)} map, in place."""
    for ctrl, cids in CHECK_MAP.items():
        ctrl_checks.setdefault(ctrl, set()).update(cids)


def _build() -> dict[str, Any]:
    catalog: dict[str, Any] = {}
    for prefix, theme, titles in (
        ("A.5", ORGANIZATIONAL, _ORG),
        ("A.6", PEOPLE, _PEOPLE),
        ("A.7", PHYSICAL, _PHYSICAL),
        ("A.8", TECHNOLOGICAL, _TECH),
    ):
        for i, title in enumerate(titles, start=1):
            control_id = f"{prefix}.{i}"
            entry: dict[str, Any] = {"title": title, "section": theme}
            # Carried on the control so the SoA can answer "is this automated,
            # and by what?" without the reader cross-referencing two modules.
            if control_id in CHECK_MAP:
                entry["automated"] = True
                entry["checks"] = list(CHECK_MAP[control_id])
            if control_id in CLOUD_GUIDANCE:
                entry["cloud_guidance"] = CLOUD_GUIDANCE[control_id]
            catalog[control_id] = entry
    return catalog


ANNEX_A_2022: dict[str, Any] = _build()


def _demo() -> None:
    assert len(_ORG) == 37 and len(_PEOPLE) == 8 and len(_PHYSICAL) == 14 and len(_TECH) == 34
    assert len(ANNEX_A_2022) == 93, len(ANNEX_A_2022)
    assert ANNEX_A_2022["A.5.15"]["title"] == "Access control"
    assert ANNEX_A_2022["A.8.24"]["title"] == "Use of cryptography"
    assert ANNEX_A_2022["A.8.24"]["section"] == TECHNOLOGICAL
    # no gaps in numbering per theme
    for prefix, n in (("A.5", 37), ("A.6", 8), ("A.7", 14), ("A.8", 34)):
        for i in range(1, n + 1):
            assert f"{prefix}.{i}" in ANNEX_A_2022

    # Every mapped control must exist, and every guidance note must belong to a
    # control we actually automate — guidance on a Manual control would claim
    # evidence the platform never produces.
    for control_id in CHECK_MAP:
        assert control_id in ANNEX_A_2022, control_id
    for control_id in CLOUD_GUIDANCE:
        assert control_id in ANNEX_A_2022, control_id
        assert control_id in CHECK_MAP, f"guidance without automation: {control_id}"

    automated = [c for c in ANNEX_A_2022.values() if c.get("automated")]
    assert len(automated) == len(CHECK_MAP)
    assert all(c.get("cloud_guidance") for c in automated), "every automated control explains itself"
    # People and Physical controls are inherently manual; claiming otherwise
    # would be the dishonest kind of coverage.
    assert not [
        cid for cid in CHECK_MAP if cid.startswith(("A.6.", "A.7."))
    ], "A.6/A.7 cannot be evidenced by a CSPM"
    print(
        f"iso27001_catalog self-check passed: 93 controls, "
        f"{len(automated)} automated ({len(automated) * 100 // 93}%)"
    )


if __name__ == "__main__":
    _demo()
