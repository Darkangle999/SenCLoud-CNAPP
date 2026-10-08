#!/usr/bin/env python3
"""Generate the three service-category CIS AWS catalog modules.

Sources are locally extracted plain-text copies of the published CIS benchmarks
(the PDFs live in the user's Downloads folder; extracted text is kept in
``.cis-extract/``):

* ``compute-v2.txt``  — CIS AWS Compute Services Benchmark v2.0.0 (2026-06-26)
* ``storage-v1.txt``  — CIS AWS Storage Services Benchmark v1.0.0 (2024-07-03)
* ``euc-v1.2.txt``    — CIS AWS End User Compute Services Benchmark v1.2.0 (2025-07-01)

Like ``core/cis_aws_catalog.py`` (Foundations v1.5.0), only the factual control
identifiers, titles, profile levels and section tree are reproduced. The
copyrighted rationale/audit/remediation prose from the CIS PDFs is NOT included.

The generated modules follow the same overlay contract as the Foundations
catalog: ``merge_check_map`` is called at score/SoA time so automatable
controls map onto real ``CheckRegistry`` checks; everything else surfaces as
``not_assessed`` (Manual) — honest automated coverage.

Regenerating the extracts: ``scripts/extract_cis_pdfs.ps1`` pulls the three
PDFs from the user's Downloads folder into ``.cis-extract/`` (needs
``pdftotext``). Running the generator also rewrites
``core/cis_catalog_provenance.json`` (benchmark version + SHA256 of each
extract) — ``test_cis_traceability.py`` uses those hashes to fail loudly when
the catalogs drift from the documents they claim to encode.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
EXTRACT = REPO / ".cis-extract"
OUT = REPO / "src" / "odineyes" / "core"

SOURCES = {
    "compute": ("compute-v2.txt", "2.0.0", "CIS AWS Compute Services Benchmark", "2026-06-26"),
    "storage": ("storage-v1.txt", "1.0.0", "CIS AWS Storage Services Benchmark", "2024-07-03"),
    "euc": ("euc-v1.2.txt", "1.2.0", "CIS AWS End User Compute Services Benchmark", "2025-07-01"),
}

# TOC / section headings that regex can mistake for recommendations.
DROP_IDS = {"storage": {"4.1", "5.1"}, "euc": {"1.2"}}

# control-id prefix → platform section label (matches compliance_mapper labels).
SECTION_RULES: dict[str, list[tuple[str, str]]] = {
    "compute": [
        ("2", "Compute"),          # EC2 / AMI / EBS
        ("3", "Compute"),          # ECS
        ("5.4", "Networking"),     # SG SSH restriction
        ("5.5", "Networking"),     # SG RDP restriction
        ("5", "Compute"),          # Lightsail + instance hygiene
        ("6", "Networking"),       # VPC endpoints for source access
        ("8", "Compute"),          # Batch
        ("10", "Compute"),         # Elastic Beanstalk
        ("11", "Compute"),         # Fargate
        ("12", "Compute"),         # Lambda
        ("16", "Compute"),         # App Runner
        ("17", "Compute"),         # Image Builder
        ("18", "Compute"),         # ECR
    ],
    "storage": [
        ("2.6", "Identity and Access Management"),  # IAM config for EC2/users/groups
        ("2.10", "Identity and Access Management"),
        ("2.11", "Identity and Access Management"),
        ("2.12", "Monitoring"),
        ("2.13", "Monitoring"),
        ("6.12", "Monitoring"),
        ("1", "Storage"),
        ("2", "Storage"),
        ("3", "Storage"),
        ("4", "Storage"),
        ("5", "Storage"),
        ("6", "Storage"),
    ],
    "euc": [
        ("2", "Compute"),          # WorkSpaces
        ("3", "Logging"),          # User Access Logging
        ("4", "Storage"),          # WorkDocs
        ("5", "Compute"),          # AppStream
    ],
}

# Which controls our real checks auto-assess (overlay, same shape as the
# Foundations CHECK_MAP). Only controls whose audit maps 1:1 onto a check.
CHECK_MAPS: dict[str, dict[str, list[str]]] = {
    "compute": {
        "2.1.5": ["compute_aws_003"],   # AMIs not publicly available
        "2.2.1": ["compute_aws_002"],   # EBS volume encryption enabled
        "2.8":   ["compute_aws_001"],   # IMDSv2 enforced on instances
        "5.4":   ["network_aws_001"],   # SG SSH restricted
        "5.5":   ["network_aws_003"],   # SG RDP restricted
        "12.6":  ["compute_aws_004"],   # Lambda not exposed to everyone
        # Dangling refs removed — no such CheckRegistry check exists yet:
        # 2.2.2/2.2.3/2.1.2 (snapshot + AMI encryption), 3.x (ECS task
        # hygiene), 12.16 (Lambda function URLs), 18.x (ECR). Those controls
        # surface as not_assessed until a real check lands; CHECK_MAP must
        # never point at a non-registered id (test_cis_traceability guards).
    },
    "storage": {},   # v1.0.0 is a Manual setup-guidance benchmark; nothing maps 1:1.
    "euc": {},       # 2.3 (WorkSpace volume encryption) has no real check yet — not_assessed.
}

MODULE_NAMES = {
    "compute": "cis_aws_compute_catalog",
    "storage": "cis_aws_storage_catalog",
    "euc": "cis_aws_euc_catalog",
}

CATALOG_VAR = {
    "compute": "CIS_AWS_COMPUTE",
    "storage": "CIS_AWS_STORAGE",
    "euc": "CIS_AWS_EUC",
}

def parse_controls(name: str) -> list[tuple[str, str, str]]:
    """Return [(control_id, title, Automated|Manual)] sorted numerically."""
    text = (EXTRACT / name).read_text(encoding="utf-8", errors="ignore")
    pat = re.compile(r"(\d+(?:\.\d+)+)\s+([A-Z].{5,150}?)\s*\((Automated|Manual)\)(?!\.)")
    seen: dict[str, str] = {}
    for m in pat.finditer(text):
        cid = m.group(1)
        title = re.sub(r"\s+", " ", m.group(2)).strip().rstrip(".")
        if cid in seen:
            continue
        # TOC / section headings carry a nested recommendation reference
        if re.search(r"\d+\.\d+.*\sEnsure\s", title):
            continue
        if title.startswith(("Page", "Table")):
            continue
        seen[cid] = title
    return sorted(seen.items(), key=lambda kv: [int(p) for p in kv[0].split(".")])


def parse_level(text: str, cid: str, title: str) -> int:
    """Profile level from the body copy: first 'Level N' after the last body copy."""
    probe = f"{cid} {title[:30]}"
    idx = text.rfind(probe)
    window = text[idx: idx + 600] if idx != -1 else ""
    m = re.search(r"Level\s*(\d)", window)
    return int(m.group(1)) if m else 1


def section_for(bench: str, cid: str) -> str:
    for prefix, section in SECTION_RULES[bench]:
        if cid == prefix or cid.startswith(prefix + "."):
            return section
    raise KeyError(f"{bench}: no section rule for control {cid}")


def fmt(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def emit(bench: str) -> Path:
    src_name, version, title, date = SOURCES[bench]
    text = (EXTRACT / src_name).read_text(encoding="utf-8", errors="ignore")
    controls = parse_controls(src_name)
    drop = DROP_IDS.get(bench, set())
    controls = [(c, t) for c, t in controls if c not in drop]

    check_map = CHECK_MAPS[bench]
    lines: list[str] = []
    w = lines.append
    w('"""' + f"{title} v{version} — full control catalog ({date})." + "\n")
    w("")
    w("Generated by scripts/generate_cis_catalogs.py from the locally extracted")
    w(f"benchmark text ({src_name}). Reproduce with:")
    w("")
    w("    python scripts/generate_cis_catalogs.py")
    w("")
    w("Only factual control identifiers, titles, profile levels and the section")
    w("tree are reproduced; CIS's copyrighted rationale/audit/remediation prose")
    w("is NOT included. Controls mapped in CHECK_MAP auto-assess from real")
    w("CheckRegistry checks; the rest surface as not_assessed (Manual).")
    w('"""')
    w("")
    w("from __future__ import annotations")
    w("")
    w("from typing import Any")
    w("")
    w("# (control_id, title, profile_level, section). Sections match the")
    w("# platform-wide labels in compliance_mapper so aggregation stays consistent.")
    w("_CONTROLS: list[tuple[str, str, int, str]] = [")
    for cid, t in controls:
        level = parse_level(text, cid, t)
        section = section_for(bench, cid)
        w(f"    ({fmt(cid)}, {fmt(t)}, {level}, {fmt(section)}),")
    w("]")
    w("")
    w("# Control → CheckRegistry check-id overlay, merged at score/SoA time.")
    w("CHECK_MAP: dict[str, list[str]] = {")
    for ctrl in sorted(check_map, key=lambda x: [int(p) for p in x.split(".")]):
        w(f"    {fmt(ctrl)}: {check_map[ctrl]!r},")
    w("}")
    w("")
    w("def merge_check_map(ctrl_checks: dict[str, set]) -> None:")
    w('    """Merge CHECK_MAP into a {control_id: set(check_ids)} map, in place."""')
    w("    for ctrl, cids in CHECK_MAP.items():")
    w("        ctrl_checks.setdefault(ctrl, set()).update(cids)")
    w("")
    w("def _build() -> dict[str, Any]:")
    w('    return {cid: {"title": title, "section": section, "level": level}')
    w("            for cid, title, level, section in _CONTROLS}")
    w("")
    w(f"{CATALOG_VAR[bench]}: dict[str, Any] = _build()")
    w("")
    w("def _demo() -> None:")
    w(f"    cat = {CATALOG_VAR[bench]}")
    w(f"    assert len(cat) == {len(controls)}, len(cat)")
    w("    for ctrl in CHECK_MAP:")
    w("        assert ctrl in cat, ctrl")
    w(f'    print(f"{MODULE_NAMES[bench]} self-check passed: {{len(cat)}} controls, "')
    w('          f"{len(CHECK_MAP)} auto-assessed")')
    w("")
    w('if __name__ == "__main__":')
    w("    _demo()")
    w("")

    out = OUT / f"{MODULE_NAMES[bench]}.py"
    out.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return out


# Foundations catalog provenance: hand-transcribed from the published PDF —
# there is no .cis-extract/ source for it, so it is recorded here so the whole
# CIS surface has one provenance manifest.
FOUNDATIONS_PROVENANCE = {
    "benchmark": "CIS Amazon Web Services Foundations Benchmark",
    "benchmark_version": "1.5.0",
    "source_extract": None,
    "source_sha256": None,
    "generator": None,
    "note": (
        "Hand-transcribed from the published PDF (local only, not in "
        ".cis-extract/). Only factual control identifiers, titles and profile "
        "levels are recorded; CIS's copyrighted prose is not included."
    ),
}


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_provenance() -> Path:
    """Manifest mapping every CIS catalog module to the document it came from."""
    entries: dict[str, dict] = {}
    for bench, (src_name, version, title, date) in SOURCES.items():
        entries[f"cis_aws_{bench}_catalog"] = {
            "benchmark": title,
            "benchmark_version": version,
            "benchmark_date": date,
            "source_extract": f".cis-extract/{src_name}",
            "source_sha256": sha256_of(EXTRACT / src_name),
            "generator": "scripts/generate_cis_catalogs.py",
        }
    entries["cis_aws_catalog"] = dict(FOUNDATIONS_PROVENANCE)
    out = OUT / "cis_catalog_provenance.json"
    out.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8", newline="\n")
    return out


def main() -> int:
    for bench in SOURCES:
        path = emit(bench)
        print(f"wrote {path}")
    print(f"wrote {write_provenance()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

