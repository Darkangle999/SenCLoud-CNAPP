"""CISA KEV (Known Exploited Vulnerabilities) catalog.

KEV is the ground truth that a CVE is being exploited in the wild — binary, and
the strongest exploit_maturity signal there is. The whole catalog is one JSON
fetch; cached on disk with a TTL (it changes ~daily). Best-effort: if the fetch
fails, is_kev() returns False and the caller falls back to EPSS.
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CACHE_PATH = Path(os.environ.get("ODINEYES_KEV_CACHE", "/tmp/odineyes_kev_cache.json"))
_TTL_SEC = 24 * 3600


class KevClient:
    def __init__(self) -> None:
        self._catalog: set[str] | None = None

    def catalog(self) -> set[str]:
        """Set of KEV CVE ids (cached on disk for a day)."""
        if self._catalog is not None:
            return self._catalog
        cached = self._load_disk()
        if cached is not None:
            self._catalog = cached
            return cached
        self._catalog = self._fetch()
        return self._catalog

    def is_kev(self, cve_id: str) -> bool:
        return cve_id in self.catalog()

    def _load_disk(self) -> set[str] | None:
        try:
            d = json.loads(_CACHE_PATH.read_text())
            if time.time() - d.get("fetched_at", 0) < _TTL_SEC:
                return set(d.get("cves", []))
        except Exception:
            pass
        return None

    def _fetch(self) -> set[str]:
        try:
            with urllib.request.urlopen(_URL, timeout=30) as r:
                data = json.loads(r.read())
        except Exception as e:  # noqa: BLE001 — best-effort enrichment
            logger.warning("KEV catalog fetch failed: %s", e)
            return set()
        cves = {v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")}
        try:
            _CACHE_PATH.write_text(json.dumps({"fetched_at": time.time(), "cves": sorted(cves)}))
        except Exception:
            pass
        return cves
