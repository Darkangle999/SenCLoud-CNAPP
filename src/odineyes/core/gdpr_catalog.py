"""GDPR — General Data Protection Regulation (EU 2016/679), security-relevant
articles.

Article numbers and short titles are factual identifiers of the published EU
regulation. A CSPM cannot evidence most of the GDPR (lawful basis, data-subject
rights, DPO, transfers) — those are legal/organizational — so this catalog lists
the articles a cloud-posture tool can speak to, with the technical-measures
article (Art.32) and design article (Art.25) mapped to checks via CHECK_MAP. The
rest surface as Manual, which is honest.

Unlike SOC2/HIPAA, the checks do not self-declare GDPR articles, so coverage
comes from the CHECK_MAP overlay (merged at score/SoA time, like ISO/CIS).
"""

from __future__ import annotations

from typing import Any

CH2 = "Chapter II — Principles"
CH3 = "Chapter III — Rights of the data subject"
CH4 = "Chapter IV — Controller and processor"
CH5 = "Chapter V — Transfers to third countries"

# (article_id, title, chapter)
_CONTROLS: list[tuple[str, str, str]] = [
    ("Art.5(1)(f)", "Integrity and confidentiality of personal data", CH2),
    ("Art.5(2)",    "Accountability", CH2),
    ("Art.15",      "Right of access by the data subject", CH3),
    ("Art.17",      "Right to erasure ('right to be forgotten')", CH3),
    ("Art.24",      "Responsibility of the controller", CH4),
    ("Art.25",      "Data protection by design and by default", CH4),
    ("Art.28",      "Processor", CH4),
    ("Art.30",      "Records of processing activities", CH4),
    ("Art.32",      "Security of processing", CH4),
    ("Art.33",      "Notification of a personal data breach to the supervisory authority", CH4),
    ("Art.34",      "Communication of a personal data breach to the data subject", CH4),
    ("Art.35",      "Data protection impact assessment", CH4),
    ("Art.44",      "General principle for transfers", CH5),
    ("Art.46",      "Transfers subject to appropriate safeguards", CH5),
]

# Article → checks that evidence it. Only the technical-measures articles map;
# everything else stays Manual.
CHECK_MAP: dict[str, list[str]] = {
    "Art.5(1)(f)": ["storage_aws_002", "storage_aws_003", "logging_aws_003"],
    "Art.25":      ["storage_aws_001", "network_aws_005", "compute_aws_001"],
    "Art.30":      ["logging_aws_001", "network_aws_002"],
    "Art.32":      ["storage_aws_002", "storage_aws_003", "storage_aws_005",
                    "compute_aws_002", "encryption_aws_001", "storage_aws_001",
                    "network_aws_005", "storage_aws_006"],
    "Art.33":      ["logging_aws_004", "logging_aws_005", "logging_aws_007"],
}


def merge_check_map(ctrl_checks: dict[str, set]) -> None:
    """Merge CHECK_MAP into a {control_id: set(check_ids)} map, in place."""
    for ctrl, cids in CHECK_MAP.items():
        ctrl_checks.setdefault(ctrl, set()).update(cids)


def _build() -> dict[str, Any]:
    return {cid: {"title": title, "section": section} for cid, title, section in _CONTROLS}


GDPR_ARTICLES: dict[str, Any] = _build()


def _demo() -> None:
    cat = GDPR_ARTICLES
    assert len(cat) == len(_CONTROLS) == 14, len(cat)
    assert cat["Art.32"]["title"] == "Security of processing"
    for ctrl in CHECK_MAP:
        assert ctrl in cat, f"CHECK_MAP references unknown article {ctrl}"
    print(f"gdpr_catalog self-check passed: {len(cat)} articles, "
          f"{len(CHECK_MAP)} mapped")


if __name__ == "__main__":
    _demo()
