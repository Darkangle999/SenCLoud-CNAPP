"""NVD CVE catalog — parsing, ingest, paginated browse, and per-asset enrich.

No network: parse_cve runs on a synthetic NVD-2.0 record; ingest goes through a
temp sqlite DB; the browse query exercises pagination/filter/keyword.
"""
from __future__ import annotations

import gzip
import json

from odineyes.db.base import init_db, session_scope
from odineyes.db.models import CloudAccount, CveCatalog, Vulnerability
from odineyes.inventory import queries
from odineyes.scanner import nvd_catalog

ARN = "arn:aws:ec2:us-east-1:111122223333:instance/i-0abc"


def _nvd_record(cve_id, score=9.8, sev="CRITICAL", desc="Heap overflow in foo", mod="2025-01-02T00:00:00.000"):
    """One NVD-2.0 vulnerabilities[] entry."""
    return {
        "cve": {
            "id": cve_id,
            "published": "2025-01-01T00:00:00.000",
            "lastModified": mod,
            "descriptions": [
                {"lang": "en", "value": desc},
                {"lang": "es", "value": "ignorar"},
            ],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {"baseScore": score, "vectorString": "CVSS:3.1/AV:N/AC:L", "version": "3.1"},
                    "baseSeverity": sev,
                }],
                "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
            },
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-122"}]}],
            "references": [{"url": "https://example.com/advisory"}],
        }
    }


def test_parse_prefers_v31_and_flattens():
    row = nvd_catalog.parse_cve(_nvd_record("CVE-2025-1000")["cve"])
    assert row["cve_id"] == "CVE-2025-1000"
    assert row["cvss_score"] == 9.8 and row["cvss_version"] == "3.1"  # v3.1 wins over v2
    assert row["cvss_severity"] == "critical"                        # lowercased
    assert row["cvss_vector"] == "CVSS:3.1/AV:N/AC:L"
    assert row["cwes"] == ["CWE-122"]
    assert row["refs"] == ["https://example.com/advisory"]
    assert row["description"] == "Heap overflow in foo"               # english only
    assert row["published"] is not None and row["last_modified"] is not None


def test_parse_no_id_returns_none():
    assert nvd_catalog.parse_cve({"descriptions": []}) is None


def _write_feed(path, records, gz=False):
    payload = {"vulnerabilities": records}
    if gz:
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            json.dump(payload, fh)
    else:
        path.write_text(json.dumps(payload), encoding="utf-8")


def test_ingest_dir_and_browse(tmp_path):
    init_db(f"sqlite:///{tmp_path}/cat.db")
    feed = tmp_path / "feeds"
    feed.mkdir()
    _write_feed(feed / "CVE-2025.json", [
        _nvd_record("CVE-2025-0001", 9.8, "CRITICAL", "critical sql injection", "2025-03-01T00:00:00.000"),
        _nvd_record("CVE-2025-0002", 5.4, "MEDIUM", "medium xss bug", "2025-02-01T00:00:00.000"),
    ])
    _write_feed(feed / "CVE-2024.json.gz", [
        _nvd_record("CVE-2024-9999", 7.5, "HIGH", "high path traversal", "2024-12-01T00:00:00.000"),
    ], gz=True)

    with session_scope() as s:
        n = nvd_catalog.ingest_dir(s, str(feed))
    assert n == 3

    with session_scope() as s:
        # newest-modified first
        page1 = queries.list_cve_catalog(s, page=1, page_size=2)
        assert page1["total"] == 3 and page1["pages"] == 2
        assert [i["cve_id"] for i in page1["items"]] == ["CVE-2025-0001", "CVE-2025-0002"]
        # severity filter
        crit = queries.list_cve_catalog(s, severity="critical")
        assert crit["total"] == 1 and crit["items"][0]["cve_id"] == "CVE-2025-0001"
        # keyword (matches description)
        kw = queries.list_cve_catalog(s, keyword="traversal")
        assert kw["total"] == 1 and kw["items"][0]["cve_id"] == "CVE-2024-9999"
        # detail
        detail = queries.get_cve(s, "cve-2025-0001")  # case-insensitive
        assert detail["cwes"] == ["CWE-122"] and detail["refs"]
        # summary
        summary = queries.cve_catalog_summary(s)
        assert summary["total"] == 3 and summary["by_severity"]["critical"] == 1


def test_ingest_is_idempotent_upsert(tmp_path):
    init_db(f"sqlite:///{tmp_path}/cat2.db")
    feed = tmp_path / "f"
    feed.mkdir()
    _write_feed(feed / "a.json", [_nvd_record("CVE-2025-0001", 5.0, "MEDIUM", "v1")])
    with session_scope() as s:
        nvd_catalog.ingest_dir(s, str(feed))
    # re-ingest same id with updated data -> update, not duplicate
    _write_feed(feed / "a.json", [_nvd_record("CVE-2025-0001", 9.0, "CRITICAL", "v2 updated")])
    with session_scope() as s:
        nvd_catalog.ingest_dir(s, str(feed))
        assert s.query(CveCatalog).count() == 1
        d = queries.get_cve(s, "CVE-2025-0001")
        assert d["severity"] == "critical" and d["description"] == "v2 updated"


def test_list_vulnerabilities_enriched_from_catalog(tmp_path):
    init_db(f"sqlite:///{tmp_path}/cat3.db")
    with session_scope() as s:
        acct = CloudAccount(provider="aws", account_identifier="111122223333")
        s.add(acct)
        s.flush()
        s.add(Vulnerability(account_id=acct.id, resource_id=ARN, cve_id="CVE-2025-0001",
                            package="openssl", severity="critical", cvss=None, summary=None))
        s.add(CveCatalog(cve_id="CVE-2025-0001", cvss_severity="critical", cvss_score=9.8,
                         cvss_vector="CVSS:3.1/AV:N", cwes=["CWE-122"], refs=["https://x"],
                         description="from nvd catalog"))
        s.commit()
    with session_scope() as s:
        item = queries.list_vulnerabilities(s)["items"][0]
    assert item["cvss_vector"] == "CVSS:3.1/AV:N"
    assert item["cwes"] == ["CWE-122"]
    assert item["nvd_url"].endswith("CVE-2025-0001")
    assert item["summary"] == "from nvd catalog"  # description fallback
    assert item["cvss"] == 9.8                     # cvss fallback from catalog
