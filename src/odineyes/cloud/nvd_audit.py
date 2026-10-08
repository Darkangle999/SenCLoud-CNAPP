"""Independent NVD cross-check of Trivy findings (CWPP audit layer).

We trust Trivy's *speed* but not Trivy's *word*. After Trivy reports a CVE on a
package, this re-derives the verdict straight from NVD's own CPE applicability
data (the ``configurations`` block ``nvd_client``/``nvd_catalog`` deliberately
drop). Two jobs:

* **Auditability** — for each finding we can say *why* it matches: which CPE
  range NVD says is affected, and where the installed version falls in it.
* **Supply-chain tripwire** — a tampered Trivy (the binary ships from a single
  upstream; a compromised release could inject or mute CVEs) can lie in its
  JSON. NVD is a second, independent source: if Trivy flags a version that NVD's
  own data says is *not* affected, we surface it as ``refuted`` instead of
  trusting it blindly.

Verdicts are deliberately asymmetric. The only verdict that accuses Trivy —
``refuted`` — requires a high bar: the CVE exists in NVD, carries CPE ranges,
the CPE product strictly matches the package, the version is cleanly comparable,
and it falls outside *every* affected range. Anything short of that is
``unverifiable`` (NVD lags, distro package names rarely equal CPE products, many
CVEs lack CPE data). So an alarm is rare but trustworthy: we never cry wolf on
uncertainty, we only flag a concrete contradiction.

Source of truth, in order: a local NVD-2.0 feed mirror (``ODINEYES_NVD_FEED_DIR``,
e.g. the fkie-cad/nvd-json-data-feeds layout — offline, deterministic, the
supply-chain-safe choice) then the live NVD API as a best-effort fallback. Pure
matching logic; fixture-tested without network.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

logger = logging.getLogger(__name__)

CONFIRMED = "confirmed"        # NVD agrees this version is affected
REFUTED = "refuted"            # NVD says this version is NOT affected — Trivy disagrees
UNVERIFIABLE = "unverifiable"  # not enough comparable NVD data to rule either way

_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# packaging gives PEP440-correct ordering (epochs, pre-releases). Optional: if it
# isn't importable we fall back to a pure-numeric compare and otherwise abstain.
try:
    from packaging.version import InvalidVersion as _IV
    from packaging.version import Version as _V
    _HAVE_PACKAGING = True
except Exception:  # noqa: BLE001
    _HAVE_PACKAGING = False

_NUMERIC = re.compile(r"^\d+(\.\d+)*$")


def audit_enabled() -> bool:
    """Opt-in. Off unless a feed mirror is configured or it's explicitly enabled,
    so the default fast Trivy path takes zero extra latency."""
    return bool(os.environ.get("ODINEYES_NVD_AUDIT")
                or os.environ.get("ODINEYES_NVD_FEED_DIR"))


def _cmp(a: str, b: str) -> Optional[int]:
    """-1/0/1 for a<=>b, or None when we can't compare confidently. None is the
    safe answer: it bubbles up to UNVERIFIABLE, never a false refute."""
    a, b = (a or "").strip(), (b or "").strip()
    if not a or not b:
        return None
    if _HAVE_PACKAGING:
        try:
            va, vb = _V(a), _V(b)
            return (va > vb) - (va < vb)
        except _IV:
            pass
    # ponytail: pure dotted-numeric fallback only; distro epochs/suffixes (1:2.3,
    # 3.0.1-deb11u1) return None → UNVERIFIABLE. Upgrade to per-ecosystem
    # comparators (apt/rpm/apk) only if audit *coverage* (not safety) matters.
    if _NUMERIC.match(a) and _NUMERIC.match(b):
        ta = [int(x) for x in a.split(".")]
        tb = [int(x) for x in b.split(".")]
        n = max(len(ta), len(tb))
        ta += [0] * (n - len(ta))
        tb += [0] * (n - len(tb))
        return (ta > tb) - (ta < tb)
    return None


def _norm(s: str) -> str:
    """Collapse a name to lowercase alphanumerics so 'OpenSSL' == 'openssl' and
    'python-requests' compares cleanly. Used for *strict* product==package gating."""
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


@dataclass
class CpeRange:
    """One ``vulnerable: true`` cpeMatch entry, reduced to product + bounds."""
    product: str
    exact: Optional[str] = None          # version pinned in the CPE string (not * / -)
    start_incl: Optional[str] = None
    start_excl: Optional[str] = None
    end_incl: Optional[str] = None
    end_excl: Optional[str] = None

    def covers(self, version: str) -> Optional[bool]:
        """True/False if ``version`` is in/out of this affected range, or None if
        any needed comparison is inconclusive."""
        if self.exact and self.exact not in ("*", "-"):
            c = _cmp(version, self.exact)
            return None if c is None else (c == 0)
        checks = [
            (self.start_incl, lambda c: c >= 0),
            (self.start_excl, lambda c: c > 0),
            (self.end_incl, lambda c: c <= 0),
            (self.end_excl, lambda c: c < 0),
        ]
        active = [(b, test) for b, test in checks if b]
        if not active:
            return True  # product:* with no bounds == every version is vulnerable
        for bound, test in active:
            c = _cmp(version, bound)
            if c is None:
                return None
            if not test(c):
                return False
        return True


def _parse_cpe_ranges(cve_obj: dict[str, Any]) -> list[CpeRange]:
    """Pull every ``vulnerable: true`` cpeMatch out of an NVD 2.0 cve object."""
    out: list[CpeRange] = []
    for cfg in cve_obj.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                criteria = m.get("criteria", "") or ""
                parts = criteria.split(":")
                if len(parts) < 6:
                    continue
                product, ver = parts[4], parts[5]
                out.append(CpeRange(
                    product=product,
                    exact=ver if ver not in ("*", "-") else None,
                    start_incl=m.get("versionStartIncluding"),
                    start_excl=m.get("versionStartExcluding"),
                    end_incl=m.get("versionEndIncluding"),
                    end_excl=m.get("versionEndExcluding"),
                ))
    return out


@dataclass
class AuditResult:
    cve_id: str
    package: str
    version: str
    verdict: str
    reason: str


def _as_triple(item: Any) -> tuple[str, str, str]:
    """Accept a (cve_id, package, version) tuple or any object exposing those
    (Trivy Vulnerability with .version, or the persist SimpleNamespace with
    .installed_version)."""
    if isinstance(item, (tuple, list)):
        return str(item[0]), str(item[1]), str(item[2])
    ver = getattr(item, "version", None) or getattr(item, "installed_version", "")
    return getattr(item, "cve_id", ""), getattr(item, "package", ""), str(ver or "")


class NvdAuditor:
    """Re-derive Trivy's CVE verdicts from NVD's own CPE data.

    ``loader`` is an injection seam (cve_id -> raw NVD cve object or None); the
    default chains a local feed mirror then the live API. Tests pass a dict-backed
    loader so the matching logic runs without network.
    """

    def __init__(self, feed_dir: Optional[str] = None,
                 loader: Optional[Callable[[str], Optional[dict]]] = None) -> None:
        self.feed_dir = feed_dir or os.environ.get("ODINEYES_NVD_FEED_DIR")
        self._loader = loader or self._default_loader
        self._mem: dict[str, Optional[dict]] = {}

    # -- CVE object sourcing --------------------------------------
    def _default_loader(self, cve_id: str) -> Optional[dict]:
        if self.feed_dir:
            obj = self._from_feed_dir(cve_id)
            if obj is not None:
                return obj
        return self._from_api(cve_id)

    def _from_feed_dir(self, cve_id: str) -> Optional[dict]:
        """fkie-cad layout: <dir>/CVE-YYYY/CVE-YYYY-NNxx/CVE-YYYY-NNNN.json.
        Falls back to a flat <dir>/CVE-YYYY-NNNN.json if that's how it's mirrored."""
        m = re.match(r"CVE-(\d{4})-(\d+)$", cve_id)
        if not m:
            return None
        year, num = m.group(1), m.group(2)
        bucket = (num[:-2] or "0") + "xx"
        base = Path(self.feed_dir)
        for cand in (base / f"CVE-{year}" / f"CVE-{year}-{bucket}" / f"{cve_id}.json",
                     base / f"{cve_id}.json"):
            if cand.is_file():
                try:
                    return _unwrap(json.loads(cand.read_text(encoding="utf-8")))
                except Exception as e:  # noqa: BLE001
                    logger.warning("NVD audit: bad feed file %s: %s", cand, e)
                    return None
        return None

    def _from_api(self, cve_id: str) -> Optional[dict]:
        url = f"{_API}?{urllib.parse.urlencode({'cveId': cve_id})}"
        headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as r:
                data = json.loads(r.read())
        except Exception as e:  # noqa: BLE001 — best-effort; a miss => UNVERIFIABLE
            logger.warning("NVD audit: API lookup failed for %s: %s", cve_id, e)
            return None
        return _unwrap(data)

    def _load(self, cve_id: str) -> Optional[dict]:
        if cve_id not in self._mem:
            self._mem[cve_id] = self._loader(cve_id)
        return self._mem[cve_id]

    # -- verdict ---------------------------------------------------
    def audit_one(self, cve_id: str, package: str, version: str) -> AuditResult:
        if not cve_id.startswith("CVE-"):
            return AuditResult(cve_id, package, version, UNVERIFIABLE,
                               "not a CVE id (distro/GHSA advisory) — outside NVD")
        cve = self._load(cve_id)
        if not cve:
            return AuditResult(cve_id, package, version, UNVERIFIABLE,
                               "CVE absent from NVD source (lag, rejected, or fabricated)")
        ranges = _parse_cpe_ranges(cve)
        if not ranges:
            return AuditResult(cve_id, package, version, UNVERIFIABLE,
                               "NVD record carries no CPE applicability data")
        pkg = _norm(package)
        matched = [r for r in ranges if _norm(r.product) == pkg]
        if not matched:
            return AuditResult(cve_id, package, version, UNVERIFIABLE,
                               f"no NVD CPE product strictly matches package '{package}'")
        verdicts = [r.covers(version) for r in matched]
        if any(v is True for v in verdicts):
            return AuditResult(cve_id, package, version, CONFIRMED,
                               "installed version falls in an NVD-affected range")
        if any(v is None for v in verdicts):
            return AuditResult(cve_id, package, version, UNVERIFIABLE,
                               f"version '{version}' not cleanly comparable to NVD range bounds")
        return AuditResult(cve_id, package, version, REFUTED,
                           f"version '{version}' is outside every NVD-affected range for this CVE")

    def audit(self, items: Iterable[Any]) -> list[AuditResult]:
        results: list[AuditResult] = []
        for item in items:
            cve_id, package, version = _as_triple(item)
            if cve_id and package:
                results.append(self.audit_one(cve_id, package, version))
        return results

    @staticmethod
    def summarize(results: list[AuditResult]) -> dict[str, Any]:
        counts = {CONFIRMED: 0, REFUTED: 0, UNVERIFIABLE: 0}
        refuted: list[dict[str, str]] = []
        for r in results:
            counts[r.verdict] = counts.get(r.verdict, 0) + 1
            if r.verdict == REFUTED:
                refuted.append({"cve": r.cve_id, "package": r.package,
                                "version": r.version, "reason": r.reason})
        return {"counts": counts, "refuted": refuted}


def _unwrap(data: Any) -> Optional[dict]:
    """Normalize the three shapes we might load into a single cve object:
    the API list (``{vulnerabilities:[{cve:{…}}]}``), a single ``{cve:{…}}``
    wrapper, or the bare cve object (``{id:…, configurations:…}``)."""
    if not isinstance(data, dict):
        return None
    if "vulnerabilities" in data:
        vulns = data.get("vulnerabilities") or []
        return vulns[0].get("cve") if vulns else None
    if "cve" in data and isinstance(data["cve"], dict):
        return data["cve"]
    if "id" in data:
        return data
    return None


if __name__ == "__main__":
    # Offline self-check — the matching logic is the only non-trivial part. No
    # network: a dict-backed loader stands in for NVD.
    _openssl = {
        "id": "CVE-2023-1111",
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
             "versionStartIncluding": "3.0.0", "versionEndExcluding": "3.0.2"},
        ]}]}],
    }
    _nocpe = {"id": "CVE-2023-2222", "configurations": []}
    _fixtures = {"CVE-2023-1111": _openssl, "CVE-2023-2222": _nocpe}
    aud = NvdAuditor(loader=lambda c: _fixtures.get(c))

    # in-range -> confirmed
    assert aud.audit_one("CVE-2023-1111", "openssl", "3.0.1").verdict == CONFIRMED
    # out-of-range -> refuted (the supply-chain tripwire)
    assert aud.audit_one("CVE-2023-1111", "openssl", "3.0.5").verdict == REFUTED
    # boundary: end is *excluding* 3.0.2 -> refuted
    assert aud.audit_one("CVE-2023-1111", "openssl", "3.0.2").verdict == REFUTED
    # uncomparable distro version -> unverifiable, never a false refute
    assert aud.audit_one("CVE-2023-1111", "openssl", "3.0.1-deb11u2").verdict == UNVERIFIABLE
    # product != package -> unverifiable (CPE naming differs from distro pkg)
    assert aud.audit_one("CVE-2023-1111", "libssl1.1", "3.0.5").verdict == UNVERIFIABLE
    # CVE missing from NVD -> unverifiable (could be fabricated; flagged, not trusted)
    assert aud.audit_one("CVE-2099-0000", "openssl", "3.0.1").verdict == UNVERIFIABLE
    # CVE present but no CPE data -> unverifiable
    assert aud.audit_one("CVE-2023-2222", "anything", "1.0").verdict == UNVERIFIABLE
    # non-CVE advisory id -> unverifiable
    assert aud.audit_one("RLSA-2023:1234", "openssl", "3.0.1").verdict == UNVERIFIABLE

    summary = NvdAuditor(loader=lambda c: _fixtures.get(c)).summarize([
        aud.audit_one("CVE-2023-1111", "openssl", "3.0.1"),
        aud.audit_one("CVE-2023-1111", "openssl", "3.0.5"),
    ])
    assert summary["counts"][CONFIRMED] == 1 and summary["counts"][REFUTED] == 1
    assert summary["refuted"][0]["cve"] == "CVE-2023-1111"
    print(f"nvd_audit self-check OK (packaging={'yes' if _HAVE_PACKAGING else 'fallback'})")
