"""Bulk NVD CVE catalog ingest.

Populates the ``cve_catalog`` table with the full NVD CVE dictionary so the UI
can browse/search every CVE — not just the ones found on our assets. Two
sources, same NVD 2.0 JSON shape:

* ``ingest_dir``  — a directory of NVD-2.0 feed files (``*.json`` / ``*.json.gz``).
  NIST retired the legacy 1.1 feeds in Dec 2023; community mirrors (e.g.
  fkie-cad/nvd-json-data-feeds) republish 2.0-shaped yearly files. Drop them in
  a dir and point this at it — no per-CVE rate limit, fastest initial load.
* ``ingest_api``  — the NVD 2.0 REST API, paginated (2000/page), optionally a
  ``last_modified_since`` delta for incremental refresh. Rate-limited; needs
  $NVD_API_KEY for usable speed.

Single-CVE realtime lookups still go through :mod:`odineyes.scanner.nvd_client`;
this module is the bulk path and shares its NVD-2.0 record parsing convention.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from sqlalchemy.orm import Session

from odineyes.db.models import CveCatalog

logger = logging.getLogger(__name__)

_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE = 2000  # NVD 2.0 max resultsPerPage


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_cve(cve: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Flatten one NVD 2.0 ``cve`` object into a ``cve_catalog`` row dict.
    Returns None if it has no usable id. Mirrors nvd_client's metric precedence
    (v3.1 > v3.0 > v2)."""
    cve_id = cve.get("id")
    if not cve_id:
        return None

    metrics = cve.get("metrics", {})
    score = severity = vector = version = None
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        arr = metrics.get(key)
        if arr:
            cdata = arr[0].get("cvssData", {})
            score = cdata.get("baseScore")
            severity = arr[0].get("baseSeverity") or cdata.get("baseSeverity")
            vector = cdata.get("vectorString")
            version = ver
            break

    description = next(
        (d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), None
    )
    cwes = sorted({
        d.get("value")
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if (d.get("value") or "").startswith("CWE-")
    })
    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]

    sev = (severity or "").lower() or None  # NVD: CRITICAL/HIGH/MEDIUM/LOW/NONE
    return {
        "cve_id": cve_id,
        "source": "nvd",
        "description": description,
        "cvss_score": score,
        "cvss_severity": sev,
        "cvss_vector": vector,
        "cvss_version": version,
        "cwes": cwes,
        "refs": refs,
        "raw": {},  # flattened columns cover list+detail; skip storing 2GB of blobs
        "published": _parse_dt(cve.get("published")),
        "last_modified": _parse_dt(cve.get("lastModified")),
    }


def upsert_rows(session: Session, rows: Iterable[dict[str, Any]], *, batch: int = 1000) -> int:
    """Insert-or-update catalog rows keyed by cve_id. Commits every ``batch``
    so a huge bulk load streams instead of buffering 300k objects in memory."""
    n = 0
    pending = 0
    for row in rows:
        existing = session.get(CveCatalog, row["cve_id"])
        if existing is None:
            session.add(CveCatalog(**row))
        else:
            for k, v in row.items():
                if k != "cve_id":
                    setattr(existing, k, v)
        n += 1
        pending += 1
        if pending >= batch:
            session.commit()
            pending = 0
    if pending:
        session.commit()
    return n


# ── source: directory of NVD-2.0 feed files ────────────────────

def _iter_feed_file(path: Path) -> Iterator[dict[str, Any]]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as fh:
        data = json.load(fh)
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cve")
        if cve:
            yield cve


def ingest_dir(session: Session, directory: str) -> int:
    """Ingest every ``*.json`` / ``*.json.gz`` feed file in ``directory``."""
    d = Path(directory)
    files = sorted([*d.glob("*.json"), *d.glob("*.json.gz")])
    if not files:
        raise FileNotFoundError(f"no NVD feed files (*.json/*.json.gz) in {directory}")

    def rows() -> Iterator[dict[str, Any]]:
        for f in files:
            logger.info("ingesting NVD feed %s", f.name)
            for cve in _iter_feed_file(f):
                parsed = parse_cve(cve)
                if parsed:
                    yield parsed

    return upsert_rows(session, rows())


# ── source: NVD 2.0 REST API (paginated + delta) ───────────────

def ingest_api(session: Session, *, last_modified_since: Optional[datetime] = None,
               max_records: Optional[int] = None) -> int:
    """Page through the NVD 2.0 API. With ``last_modified_since`` it pulls only
    the delta (incremental refresh); without it, the whole catalog (slow — prefer
    ingest_dir for the initial load)."""
    api_key = os.environ.get("NVD_API_KEY")
    interval = 0.7 if api_key else 6.5  # respect 50/30s keyed, 5/30s anonymous
    headers = {"apiKey": api_key} if api_key else {}

    def rows() -> Iterator[dict[str, Any]]:
        start = 0
        total = None
        last = 0.0
        while True:
            params: dict[str, Any] = {"resultsPerPage": _PAGE, "startIndex": start}
            if last_modified_since:
                params["lastModStartDate"] = last_modified_since.isoformat()
                params["lastModEndDate"] = datetime.now(last_modified_since.tzinfo).isoformat()
            wait = interval - (time.time() - last)
            if wait > 0:
                time.sleep(wait)
            last = time.time()
            req = urllib.request.Request(f"{_API}?{urllib.parse.urlencode(params)}", headers=headers)
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read())
            total = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            for entry in vulns:
                cve = entry.get("cve")
                parsed = parse_cve(cve) if cve else None
                if parsed:
                    yield parsed
            start += _PAGE
            logger.info("NVD API %d/%s", min(start, total or start), total)
            if not vulns or start >= (total or 0) or (max_records and start >= max_records):
                break

    return upsert_rows(session, rows())
