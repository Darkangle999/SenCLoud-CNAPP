import json
import re
import requests
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class OsvClient:
    """
    Client for querying the OSV.dev Threat Intelligence API.
    Used to fetch real-time vulnerability data for software packages.
    """

    BASE_URL = "https://api.osv.dev/v1/query"
    BATCH_URL = "https://api.osv.dev/v1/querybatch"
    VULN_URL = "https://api.osv.dev/v1/vulns"

    def __init__(self) -> None:
        self._detail_cache: Dict[str, Dict[str, Any]] = {}

    def query_batch(self, packages: List[Dict[str, str]]) -> List[List[Dict[str, Any]]]:
        """Query OSV for many packages at once.

        Args:
            packages: list of {"name", "version", "ecosystem"} dicts.

        Returns:
            Parallel list; element i is the list of vuln stubs ({"id", ...}) for
            packages[i]. OSV's batch endpoint returns ids only — callers that need
            full records can follow up with query_package, but id+aliases is enough
            for graph nodes.
        """
        if not packages:
            return []
        queries = [
            {"version": p["version"],
             "package": {"name": p["name"], "ecosystem": p.get("ecosystem", "PyPI")}}
            for p in packages
        ]
        try:
            resp = requests.post(self.BATCH_URL, json={"queries": queries}, timeout=20)
            resp.raise_for_status()
            results = resp.json().get("results", [])
            return [r.get("vulns", []) or [] for r in results]
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying OSV batch API: {e}")
            return [[] for _ in packages]

    def query_package(self, name: str, version: str, ecosystem: str = "PyPI") -> List[Dict[str, Any]]:
        """
        Queries the OSV API for vulnerabilities affecting a specific package version.
        
        Args:
            name: The package name (e.g., 'requests', 'log4j-core')
            version: The installed version (e.g., '2.25.1')
            ecosystem: The package ecosystem (e.g., 'PyPI', 'Maven')
            
        Returns:
            A list of OSV vulnerability dictionary objects.
        """
        payload = {
            "version": version,
            "package": {
                "name": name,
                "ecosystem": ecosystem
            }
        }
        
        try:
            response = requests.post(self.BASE_URL, json=payload, timeout=5)
            response.raise_for_status()
            
            data = response.json()
            # The API returns {"vulns": [...]} if vulnerabilities are found, otherwise {}
            return data.get("vulns", [])
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout querying OSV API for {name}@{version}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying OSV API: {e}")
            
        return []

    def hydrate(self, vuln_id: str) -> Dict[str, Any]:
        """Fetch the full OSV record for an id (batch returns only stubs).
        In-process cached — many packages share the same advisory."""
        if vuln_id in self._detail_cache:
            return self._detail_cache[vuln_id]
        rec: Dict[str, Any] = {}
        try:
            resp = requests.get(f"{self.VULN_URL}/{vuln_id}", timeout=15)
            resp.raise_for_status()
            rec = resp.json()
        except requests.exceptions.RequestException as e:
            logger.warning("OSV hydrate failed for %s: %s", vuln_id, e)
        self._detail_cache[vuln_id] = rec
        return rec

    @staticmethod
    def cves_of(record: Dict[str, Any]) -> List[str]:
        """Real CVE ids for an advisory: aliases + upstream (RLSA stores CVEs in
        upstream) + related, de-duped; regex fallback over the raw record."""
        out = set()
        for field in ("aliases", "upstream", "related"):
            for x in record.get(field, []) or []:
                if str(x).startswith("CVE-"):
                    out.add(str(x))
        if not out:
            out |= set(re.findall(r"CVE-\d{4}-\d+", json.dumps(record)))
        return sorted(out)

    @staticmethod
    def cvss_vector(record: Dict[str, Any]) -> Optional[str]:
        for s in record.get("severity", []) or []:
            if str(s.get("type", "")).startswith("CVSS") and s.get("score"):
                return s["score"]
        return None

    @staticmethod
    def fixed_version(record: Dict[str, Any]) -> Optional[str]:
        for aff in record.get("affected", []) or []:
            for rng in aff.get("ranges", []) or []:
                for ev in rng.get("events", []) or []:
                    if ev.get("fixed"):
                        return ev["fixed"]
        return None

    def extract_cve_id(self, osv_vuln: Dict[str, Any]) -> str:
        """
        Helper method to extract the CVE ID from an OSV vulnerability record.
        OSV records often use their own IDs (e.g., GHSA) and store CVEs in 'aliases'.
        """
        # First check aliases for CVE IDs
        aliases = osv_vuln.get("aliases", [])
        for alias in aliases:
            if str(alias).startswith("CVE-"):
                return alias
                
        # Fallback to the primary OSV ID if no CVE is found
        return osv_vuln.get("id", "UNKNOWN-ID")
