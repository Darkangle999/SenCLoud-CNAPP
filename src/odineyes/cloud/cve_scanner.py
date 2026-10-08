"""
Odineyes — Agentless-ish CVE Scanner (AWS SSM + OSV)

Real package inventory for EC2 instances that are SSM-managed, matched against
the OSV.dev vulnerability database. No agent install required: it uses the SSM
RunShellScript document to read the package DB read-only, then closes.

If an instance is NOT SSM-managed, it is skipped — nothing is fabricated. This
is the honest replacement for the old `time.sleep(2)` mock.

All AWS calls are read-only except `ssm:SendCommand`, which only *runs read-only
shell commands* (dpkg-query / rpm -qa / pip freeze) and creates no resources.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from odineyes.scanner.cvss import band as cvss_band
from odineyes.scanner.cvss import base_score as cvss_base
from odineyes.scanner.osv_client import OsvClient

logger = logging.getLogger(__name__)

# Read-only inventory command. Emits lines: "ECO\tname\tversion"
_INVENTORY_SCRIPT = r"""
set -e
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='Debian\t${Package}\t${Version}\n' 2>/dev/null | sed 's/[-+~:].*$//' 2>/dev/null || \
  dpkg-query -W -f='Debian\t${Package}\t${Version}\n' 2>/dev/null
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf 'Rocky Linux\t%{NAME}\t%{VERSION}\n' 2>/dev/null
elif command -v apk >/dev/null 2>&1; then
  apk info -v 2>/dev/null | sed 's/\(.*\)-\([0-9].*\)/Alpine\t\1\t\2/'
fi
if command -v pip3 >/dev/null 2>&1; then
  pip3 freeze 2>/dev/null | sed 's/==/\t/' | sed 's/^/PyPI\t/'
fi
"""


@dataclass
class Vulnerability:
    cve_id: str            # real CVE when resolvable, else the source advisory id
    package: str
    version: str
    ecosystem: str
    severity: str = "unknown"
    cvss: Optional[float] = None
    summary: Optional[str] = None
    fixed_version: Optional[str] = None
    advisory: Optional[str] = None   # source advisory (e.g. RLSA-…) the CVE came from
    epss: Optional[float] = None     # exploit probability 0–1 (FIRST.org EPSS)
    epss_percentile: Optional[float] = None
    kev: bool = False                # in CISA Known Exploited Vulnerabilities
    scanner_source: str = "ssm-osv"
    target: Optional[str] = None
    package_path: Optional[str] = None


@dataclass
class InstanceCveResult:
    instance_id: str
    ssm_managed: bool
    package_count: int = 0
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    skipped_reason: str = ""


class CveScanner:
    """SSM-driven package inventory + OSV CVE matching."""

    def __init__(self, region: str = "us-east-1", profile: Optional[str] = None,
                 max_packages: int = 400, enrich_nvd: bool = True, nvd_cap: int = 400):
        self.region = region
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.ssm = self.session.client("ssm", region_name=region)
        self.osv = OsvClient()
        self.max_packages = max_packages
        self.enrich_nvd = enrich_nvd
        self.nvd_cap = nvd_cap            # max unique CVEs to enrich live from NVD per scan
        self._nvd = None                  # lazily created
        self._nvd_calls = 0

    def _ssm_managed_ids(self) -> set[str]:
        managed: set[str] = set()
        try:
            paginator = self.ssm.get_paginator("describe_instance_information")
            for page in paginator.paginate():
                for info in page.get("InstanceInformationList", []):
                    if info.get("PingStatus") == "Online":
                        managed.add(info.get("InstanceId", ""))
        except ClientError as e:
            logger.error("describe_instance_information failed: %s", e)
        return managed

    def scan_instances(self, instance_ids: list[str]) -> list[InstanceCveResult]:
        results: list[InstanceCveResult] = []
        managed = self._ssm_managed_ids()
        for iid in instance_ids:
            if iid not in managed:
                results.append(InstanceCveResult(
                    instance_id=iid, ssm_managed=False,
                    skipped_reason="not SSM-managed (no agent / not Online)"))
                continue
            results.append(self._scan_one(iid))
        return results

    def _scan_one(self, instance_id: str) -> InstanceCveResult:
        packages = self._inventory_via_ssm(instance_id)
        if not packages:
            return InstanceCveResult(instance_id=instance_id, ssm_managed=True,
                                     skipped_reason="no packages returned")
        packages = packages[: self.max_packages]

        # 1. OSV batch → which advisories hit which package (stubs: id only).
        pkg_adv: list[tuple[dict, list[str]]] = []
        for i in range(0, len(packages), 100):
            chunk = packages[i: i + 100]
            batch = self.osv.query_batch(chunk)
            for pkg, vlist in zip(chunk, batch):
                ids = [v.get("id") for v in vlist if v.get("id")]
                if ids:
                    pkg_adv.append((pkg, ids))

        # 2. Hydrate each unique advisory once → CVEs, CVSS vector, fix, summary.
        adv_detail: dict[str, dict] = {}
        for _, ids in pkg_adv:
            for aid in ids:
                if aid not in adv_detail:
                    rec = self.osv.hydrate(aid)
                    adv_detail[aid] = {
                        "cves": self.osv.cves_of(rec),
                        "vector": self.osv.cvss_vector(rec),
                        "fixed": self.osv.fixed_version(rec),
                        "summary": rec.get("summary") or rec.get("details"),
                    }

        # 3. Emit one row per (package, CVE); severity from OSV CVSS vector now,
        #    upgraded to authoritative NVD score/description below. Advisories
        #    with no CVE keep one row under the advisory id (nothing dropped).
        vulns: list[Vulnerability] = []
        seen: set[tuple[str, str]] = set()
        for pkg, ids in pkg_adv:
            for aid in ids:
                d = adv_detail.get(aid, {})
                vector, fixed = d.get("vector"), d.get("fixed")
                summary = d.get("summary")
                osv_score = cvss_base(vector) if vector else None
                osv_sev = cvss_band(osv_score)
                targets = d.get("cves") or [aid]
                for ident in targets:
                    key = (pkg["name"], ident)
                    if key in seen:
                        continue
                    seen.add(key)
                    vulns.append(Vulnerability(
                        cve_id=ident, package=pkg["name"], version=pkg["version"],
                        ecosystem=pkg["ecosystem"], severity=osv_sev, cvss=osv_score,
                        summary=(summary or "")[:500] or None, fixed_version=fixed,
                        advisory=aid if ident.startswith("CVE-") else None,
                    ))

        # 4. Authoritative enrichment from NVD (best-effort, capped, cached).
        if self.enrich_nvd:
            self._enrich_from_nvd(vulns)

        # 5. Exploit maturity — EPSS probability + CISA KEV (best-effort).
        self._enrich_exploit_maturity(vulns)

        return InstanceCveResult(instance_id=instance_id, ssm_managed=True,
                                 package_count=len(packages), vulnerabilities=vulns)

    def _enrich_exploit_maturity(self, vulns: list[Vulnerability]) -> None:
        """Attach EPSS score + KEV flag to each real CVE (the exploit_maturity
        signal). Best-effort: network misses leave the fields unset (maturity 0)."""
        from odineyes.scanner.epss_client import EpssClient
        from odineyes.scanner.kev_client import KevClient
        cves = sorted({v.cve_id for v in vulns if v.cve_id.startswith("CVE-")})
        if not cves:
            return
        try:
            epss = EpssClient().scores(cves)
        except Exception:  # noqa: BLE001
            epss = {}
        try:
            kev = KevClient().catalog()
        except Exception:  # noqa: BLE001
            kev = set()
        for v in vulns:
            sc = epss.get(v.cve_id)
            if sc:
                v.epss = round(sc.epss, 5)
                v.epss_percentile = round(sc.percentile, 5)
            v.kev = v.cve_id in kev

    def _enrich_from_nvd(self, vulns: list[Vulnerability]) -> None:
        from odineyes.scanner.nvd_client import NvdClient
        if self._nvd is None:
            self._nvd = NvdClient()
        # unique CVEs, worst-OSV-severity first so the cap spends budget well
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        uniq = sorted({v.cve_id for v in vulns if v.cve_id.startswith("CVE-")},
                      key=lambda c: min((rank.get(v.severity, 9) for v in vulns if v.cve_id == c), default=9))
        # Anonymous NVD is ~5 req/30s — keep a keyless scan snappy by enriching
        # only the worst CVEs; the rest already carry OSV-derived CVSS severity.
        cap = self.nvd_cap if self._nvd.api_key else min(self.nvd_cap, 25)
        records = {}
        for cve in uniq[:cap]:
            rec = self._nvd.lookup(cve)
            self._nvd_calls += 1
            if rec:
                records[cve] = rec
        for v in vulns:
            rec = records.get(v.cve_id)
            if rec:
                if rec.cvss is not None:
                    v.cvss = rec.cvss
                if rec.severity and rec.severity != "unknown":
                    v.severity = rec.severity
                if rec.description:
                    v.summary = rec.description[:500]

    def _inventory_via_ssm(self, instance_id: str) -> list[dict]:
        try:
            cmd = self.ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [_INVENTORY_SCRIPT]},
                Comment="Odineyes read-only package inventory",
            )
            cmd_id = cmd["Command"]["CommandId"]
        except ClientError as e:
            logger.error("send_command(%s) failed: %s", instance_id, e)
            return []

        # poll for completion
        output = ""
        for _ in range(30):
            time.sleep(2)
            try:
                inv = self.ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
            except ClientError:
                continue
            status = inv.get("Status")
            if status in ("Success", "Failed", "Cancelled", "TimedOut"):
                output = inv.get("StandardOutputContent", "")
                break
        return self._parse_inventory(output)

    @staticmethod
    def _parse_inventory(output: str) -> list[dict]:
        pkgs: list[dict] = []
        seen: set[tuple] = set()
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            eco, name, version = (p.strip() for p in parts)
            if not name or not version:
                continue
            key = (eco, name, version)
            if key in seen:
                continue
            seen.add(key)
            pkgs.append({"ecosystem": eco, "name": name, "version": version})
        return pkgs
