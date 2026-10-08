"""EPSS (Exploit Prediction Scoring System) lookup — FIRST.org.

EPSS gives the probability (0–1) a CVE will be exploited in the wild in the next
30 days. It is the 'exploit_maturity' signal that separates a CVSS 9.8 nobody
weaponizes from a CVSS 7.5 under active mass-exploitation. Batched (the API
takes many CVEs per call), in-process + on-disk cached. Best-effort: a miss
returns no score and the caller treats maturity as 0.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_API = "https://api.first.org/data/v1/epss"
_CACHE_PATH = Path(os.environ.get("ODINEYES_EPSS_CACHE", "/tmp/odineyes_epss_cache.json"))
_BATCH = 100


@dataclass
class EpssScore:
    cve_id: str
    epss: float        # probability 0–1
    percentile: float  # 0–1 rank vs all CVEs


class EpssClient:
    def __init__(self) -> None:
        self._mem: dict[str, Optional[EpssScore]] = {}
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

    def scores(self, cve_ids: list[str]) -> dict[str, EpssScore]:
        """Return EPSS for the given CVEs (cached + batched fetch for misses)."""
        cves = sorted({c for c in cve_ids if c.startswith("CVE-")})
        out: dict[str, EpssScore] = {}
        missing: list[str] = []
        for c in cves:
            if c in self._mem:
                rec = self._mem[c]
            elif c in self._disk:
                d = self._disk[c]
                rec = EpssScore(**d) if d else None
                self._mem[c] = rec
            else:
                missing.append(c)
                continue
            if rec:
                out[c] = rec

        for i in range(0, len(missing), _BATCH):
            batch = missing[i:i + _BATCH]
            fetched = self._fetch(batch)
            for c in batch:
                rec = fetched.get(c)
                self._mem[c] = rec
                self._disk[c] = rec.__dict__ if rec else None
                if rec:
                    out[c] = rec
        if missing:
            self._save_disk()
        return out

    def _fetch(self, cves: list[str]) -> dict[str, EpssScore]:
        url = f"{_API}?{urllib.parse.urlencode({'cve': ','.join(cves)})}"
        try:
            with urllib.request.urlopen(url, timeout=20) as r:
                data = json.loads(r.read())
        except Exception as e:  # noqa: BLE001 — best-effort enrichment
            logger.warning("EPSS fetch failed (%d cves): %s", len(cves), e)
            return {}
        out: dict[str, EpssScore] = {}
        for row in data.get("data", []):
            cid = row.get("cve")
            try:
                out[cid] = EpssScore(
                    cve_id=cid,
                    epss=float(row.get("epss", 0.0)),
                    percentile=float(row.get("percentile", 0.0)),
                )
            except (TypeError, ValueError):
                continue
        return out
