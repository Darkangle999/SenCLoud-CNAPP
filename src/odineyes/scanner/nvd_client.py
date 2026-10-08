"""Realtime NVD (National Vulnerability Database) CVE lookup.

Authoritative CVSS base score, severity and description per CVE, straight from
services.nvd.nist.gov. NVD rate-limits hard (5 req / 30s anonymous, 50 with an
API key in $NVD_API_KEY), so this throttles, dedup-caches in-process, and
persists a small on-disk cache between runs. Best-effort: a miss/timeout
returns None and the caller falls back to the OSV-derived CVSS.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE_PATH = Path(os.environ.get("ODINEYES_NVD_CACHE", "/tmp/odineyes_nvd_cache.json"))


@dataclass
class NvdRecord:
    cve_id: str
    cvss: Optional[float]
    severity: str          # critical|high|medium|low|info|unknown
    description: Optional[str]


class NvdClient:
    def __init__(self) -> None:
        self.api_key = os.environ.get("NVD_API_KEY")
        # Stay under the published limits: ~50/30s keyed, ~5/30s anonymous.
        self._min_interval = 0.7 if self.api_key else 6.5
        self._last = 0.0
        self._mem: dict[str, Optional[NvdRecord]] = {}
        self._disk = self._load_disk()

    def _load_disk(self) -> dict:
        try:
            return json.loads(_CACHE_PATH.read_text())
        except Exception:
            return {}

    def _save_disk(self) -> None:
        try:
            _CACHE_PATH.write_text(json.dumps(self._disk))
        except Exception:
            pass

    def _throttle(self) -> None:
        wait = self._min_interval - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

    def lookup(self, cve_id: str) -> Optional[NvdRecord]:
        if not cve_id.startswith("CVE-"):
            return None
        if cve_id in self._mem:
            return self._mem[cve_id]
        if cve_id in self._disk:
            d = self._disk[cve_id]
            rec = NvdRecord(**d) if d else None
            self._mem[cve_id] = rec
            return rec

        rec = self._fetch(cve_id)
        self._mem[cve_id] = rec
        self._disk[cve_id] = rec.__dict__ if rec else None
        self._save_disk()
        return rec

    def _fetch(self, cve_id: str) -> Optional[NvdRecord]:
        self._throttle()
        url = f"{_API}?{urllib.parse.urlencode({'cveId': cve_id})}"
        req = urllib.request.Request(url, headers={"apiKey": self.api_key} if self.api_key else {})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read())
        except Exception as e:  # noqa: BLE001 — best-effort enrichment
            logger.warning("NVD lookup failed for %s: %s", cve_id, e)
            return None

        vulns = data.get("vulnerabilities") or []
        if not vulns:
            return None
        cve = vulns[0].get("cve", {})
        metrics = cve.get("metrics", {})
        score = severity = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key)
            if arr:
                cdata = arr[0].get("cvssData", {})
                score = cdata.get("baseScore")
                severity = (arr[0].get("baseSeverity") or cdata.get("baseSeverity"))
                break
        desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
        sev = (severity or "unknown").lower()
        if sev == "none":
            sev = "info"
        return NvdRecord(cve_id=cve_id, cvss=score, severity=sev, description=desc)
