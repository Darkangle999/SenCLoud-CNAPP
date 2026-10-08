"""Traceability between the checked-in CIS catalogs and the benchmark
documents they were generated from.

``.cis-extract/`` holds the locally extracted text of the CIS benchmark PDFs
(gitignored — copyright). When it is present, these tests pin three
guarantees:

1. every control (id, title, profile level) in a generated catalog is
   reproducible from the benchmark document text;
2. every CHECK_MAP entry targets a control that exists in the catalog and a
   check that exists in the registry (no dangling detection-rule refs);
3. the provenance manifest's SHA256 matches the current extracts — an
   updated document without regenerating the catalogs fails here instead of
   drifting silently.

Without the extracts everything marked ``needs_extract`` skips, so CI on a
fresh clone stays green.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
from pathlib import Path

import pytest

from odineyes.core.check_registry import CheckRegistry

REPO = Path(__file__).resolve().parents[3]
EXTRACT = REPO / ".cis-extract"

SOURCES = {
    "compute": ("cis_aws_compute_catalog", "compute-v2.txt"),
    "storage": ("cis_aws_storage_catalog", "storage-v1.txt"),
    "euc": ("cis_aws_euc_catalog", "euc-v1.2.txt"),
}

needs_extract = pytest.mark.skipif(
    not EXTRACT.exists(), reason=".cis-extract/ benchmark texts not present (local-only)"
)


def _generator():
    spec = importlib.util.spec_from_file_location(
        "generate_cis_catalogs", REPO / "scripts" / "generate_cis_catalogs.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _provenance() -> dict:
    from odineyes.core import cis_aws_catalog

    path = Path(cis_aws_catalog.__file__).parent / "cis_catalog_provenance.json"
    return json.loads(path.read_text(encoding="utf-8"))


@needs_extract
@pytest.mark.parametrize("bench", sorted(SOURCES))
def test_generated_catalog_matches_document(bench):
    module_name, extract_name = SOURCES[bench]
    gen = _generator()
    mod = importlib.import_module(f"odineyes.core.{module_name}")
    text = (EXTRACT / extract_name).read_text(encoding="utf-8", errors="ignore")
    drop = gen.DROP_IDS.get(bench, set())

    doc = {
        cid: (title, gen.parse_level(text, cid, title))
        for cid, title in gen.parse_controls(extract_name)
        if cid not in drop
    }
    checked_in = {cid: (title, level) for cid, title, level, _s in mod._CONTROLS}

    assert set(checked_in) == set(doc), (
        f"{module_name}: catalog/doc control-id drift — "
        f"catalog-only={sorted(set(checked_in) - set(doc))} "
        f"doc-only={sorted(set(doc) - set(checked_in))}"
    )
    for cid, (title, level) in doc.items():
        assert checked_in[cid][0] == title, f"{module_name}:{cid} title drift"
        assert checked_in[cid][1] == level, f"{module_name}:{cid} profile-level drift"


@needs_extract
@pytest.mark.parametrize("bench", sorted(SOURCES))
def test_check_map_targets_document_controls_and_registered_checks(bench):
    module_name, _extract_name = SOURCES[bench]
    gen = _generator()
    mod = importlib.import_module(f"odineyes.core.{module_name}")
    cat = getattr(mod, gen.CATALOG_VAR[bench])
    real_checks = set(CheckRegistry()._checks.keys())
    assert set(mod.CHECK_MAP) == set(gen.CHECK_MAPS[bench])
    for ctrl, cids in mod.CHECK_MAP.items():
        assert ctrl in cat, f"{module_name}: {ctrl} not in document catalog"
        for cid in cids:
            assert cid in real_checks, f"{module_name}: {ctrl} -> missing check {cid}"


@needs_extract
def test_provenance_hashes_match_current_extracts():
    prov = _provenance()
    for bench, (module_name, extract_name) in SOURCES.items():
        entry = prov[module_name]
        assert entry["source_extract"] == f".cis-extract/{extract_name}"
        digest = hashlib.sha256((EXTRACT / extract_name).read_bytes()).hexdigest()
        assert entry["source_sha256"] == digest, (
            f"{module_name}: .cis-extract/{extract_name} changed since the "
            "catalogs were generated — re-run scripts/generate_cis_catalogs.py"
        )


def test_provenance_covers_every_cis_catalog_including_foundations():
    prov = _provenance()
    for module_name, _extract in SOURCES.values():
        assert module_name in prov
    assert "cis_aws_catalog" in prov  # Foundations — hand-transcribed
    assert prov["cis_aws_catalog"]["source_sha256"] is None
    assert prov["cis_aws_catalog"]["benchmark_version"] == "1.5.0"


def test_generated_catalogs_import_and_are_wired_into_frameworks():
    from odineyes.core.compliance_mapper import FRAMEWORKS

    gen = _generator()
    for bench, (module_name, _extract) in SOURCES.items():
        mod = importlib.import_module(f"odineyes.core.{module_name}")  # must import cleanly
        fw_id = "CIS-" + bench.upper()
        assert fw_id in FRAMEWORKS, f"{fw_id} missing from FRAMEWORKS"
        assert FRAMEWORKS[fw_id]["controls"] is getattr(mod, gen.CATALOG_VAR[bench])