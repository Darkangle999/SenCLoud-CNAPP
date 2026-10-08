"""Container-image CVE scanning via Trivy (CWPP).

Mirrors ``cloud.cve_scanner`` but for container images instead of EC2 hosts:
discover images in ECR, run ``trivy image --format json`` against each, and map
the results into the same ``Vulnerability`` shape the inventory spine persists.

Read-only. If the ``trivy`` binary is not installed the scan is **skipped, never
faked** (same contract as a non-SSM-managed instance). The JSON parser is pure
and fixture-tested — it needs neither the binary nor AWS.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError

from odineyes.cloud.cve_scanner import Vulnerability

logger = logging.getLogger(__name__)

# Per-image trivy timeout. A cold run pulls the image + vuln DB; keep generous
# but bounded so one slow image can't hang the whole scan.
_TRIVY_TIMEOUT = 300
_TRIVY_VM_TIMEOUT = 1800
_SNAPSHOT_ID_RE = re.compile(r"^snap-[0-9a-fA-F]{8,32}$")

# Supply-chain pins are read live from the env (in verify_binary) so they're
# testable and so a value set after import still applies. The trivy binary ships
# from a single upstream; a poisoned release could exfiltrate or silently alter
# findings. Operators pin the known-good binary's SHA256 — directly via
# ODINEYES_TRIVY_SHA256, or via ODINEYES_TRIVY_SHA256_FILE (a file
# holding the hash; the Docker image self-pins this way at build time) — plus an
# optional ODINEYES_TRIVY_VERSION string. A mismatch => we refuse to run the
# binary. Unset => we run but warn integrity is unverified. Pairs with the NVD
# audit layer (nvd_audit), which independently re-checks what a *running* binary
# actually reports.


@dataclass
class ImageScanResult:
    image_ref: str
    scanned: bool
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    component_count: int = 0
    targets: list[str] = field(default_factory=list)
    skipped_reason: str = ""


@dataclass
class ImageSbomResult:
    image_ref: str
    generated: bool
    sbom: dict = field(default_factory=dict)   # raw CycloneDX document
    component_count: int = 0
    skipped_reason: str = ""


@dataclass
class EbsSnapshotScanResult:
    """Result of a read-only Trivy VM scan against one EBS snapshot.

    The VM target uses the EBS Direct APIs. It does not attach or mount a
    volume, and the direct path intentionally requests only vulnerability
    results. Secret scanning is deliberately excluded here so raw secret
    material never crosses the scanner process boundary into Odineyes.
    """

    snapshot_id: str
    scanned: bool
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    component_count: int = 0
    targets: list[str] = field(default_factory=list)
    skipped_reason: str = ""


class TrivyScanner:
    """Discover ECR images and scan them with Trivy."""

    def __init__(self, region: str = "us-east-1", profile: Optional[str] = None,
                 session: Optional[boto3.Session] = None, max_images: int = 50):
        self.region = region
        self.session = session or boto3.Session(profile_name=profile, region_name=region)
        self.max_images = max_images

    # -- availability ---------------------------------------------
    @staticmethod
    def available() -> bool:
        """True iff the trivy binary is on PATH."""
        return shutil.which("trivy") is not None

    @staticmethod
    def _sha256(path: str) -> str:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    @staticmethod
    def _expected_sha() -> Optional[str]:
        """The pinned binary hash, from ODINEYES_TRIVY_SHA256 or, failing
        that, the first token of the file named by ODINEYES_TRIVY_SHA256_FILE
        (how the Docker image self-pins at build time). Read live so it's testable.
        None => no pin configured."""
        val = os.environ.get("ODINEYES_TRIVY_SHA256")
        if val:
            return val.strip().lower()
        f = os.environ.get("ODINEYES_TRIVY_SHA256_FILE")
        if f:
            return Path(f).read_text(encoding="utf-8").strip().split()[0].lower()
        return None

    @staticmethod
    def verify_binary() -> tuple[bool, str]:
        """Supply-chain gate: confirm the trivy on PATH is the one we trust before
        we execute it. Optional version-string pin (ODINEYES_TRIVY_VERSION)
        then SHA256 pin (ODINEYES_TRIVY_SHA256[_FILE]). No pin => (True,
        'unverified …') and the caller logs a hardening warning. A mismatch =>
        (False, reason) and the binary is never run (fail closed)."""
        path = shutil.which("trivy")
        if not path:
            return False, "trivy not on PATH"
        pin_ver = os.environ.get("ODINEYES_TRIVY_VERSION")
        if pin_ver:
            try:
                out = subprocess.run(["trivy", "--version"], capture_output=True,
                                     text=True, timeout=30)
            except Exception as e:  # noqa: BLE001
                return False, f"version check failed: {e}"
            if pin_ver not in (out.stdout or ""):
                return False, f"version mismatch: expected pin '{pin_ver}'"
        try:
            expected = TrivyScanner._expected_sha()
        except Exception as e:  # noqa: BLE001 — unreadable pin file => fail closed
            return False, f"could not read trivy SHA256 pin: {e}"
        if expected:
            try:
                digest = TrivyScanner._sha256(path)
            except Exception as e:  # noqa: BLE001
                return False, f"hash read failed: {e}"
            if digest != expected:
                return False, f"SHA256 mismatch: got {digest[:16]}… (binary may be tampered)"
            return True, "sha256-pinned"
        return True, "unverified (set ODINEYES_TRIVY_SHA256[_FILE] to pin the binary)"

    @staticmethod
    def assume_role_session(
        *, role_arn: str, external_id: Optional[str], region: str,
        session_name: str = "odineyes-ebs-vm-scan",
    ) -> boto3.Session:
        """Assume the separately scoped disk-scan role.

        This is intentionally not the general read-only inventory role. The
        caller receives temporary credentials only, and their values are passed
        to Trivy through its child-process environment without being logged.
        """
        kwargs: dict[str, str] = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
        }
        if external_id:
            kwargs["ExternalId"] = external_id
        creds = boto3.client("sts", region_name=region).assume_role(**kwargs)["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )

    def _aws_child_env(self) -> tuple[Optional[dict[str, str]], str]:
        """Build an isolated AWS environment for the Trivy child process.

        Removing profile selectors prevents a local developer profile from
        overriding the temporary role credentials selected by the backend.
        """
        try:
            credentials = self.session.get_credentials()
            frozen = credentials.get_frozen_credentials() if credentials else None
        except Exception as exc:  # noqa: BLE001 - a skipped scan is safer than ambient fallback
            return None, f"could not load disk-scan credentials: {exc}"
        if not frozen or not frozen.access_key or not frozen.secret_key:
            return None, "disk-scan session has no usable AWS credentials"
        env = os.environ.copy()
        env.pop("AWS_PROFILE", None)
        env.pop("AWS_DEFAULT_PROFILE", None)
        env["AWS_ACCESS_KEY_ID"] = frozen.access_key
        env["AWS_SECRET_ACCESS_KEY"] = frozen.secret_key
        if frozen.token:
            env["AWS_SESSION_TOKEN"] = frozen.token
        env["AWS_REGION"] = self.region
        env["AWS_DEFAULT_REGION"] = self.region
        env["AWS_EC2_METADATA_DISABLED"] = "true"
        return env, ""

    @staticmethod
    def _vm_timeout() -> int:
        """Read a bounded VM timeout without allowing an endless worker."""
        raw = os.environ.get("ODINEYES_TRIVY_VM_TIMEOUT_SECONDS", str(_TRIVY_VM_TIMEOUT))
        try:
            return min(7200, max(60, int(raw)))
        except ValueError:
            return _TRIVY_VM_TIMEOUT

    # -- ECR discovery --------------------------------------------
    def discover_ecr_images(self) -> list[str]:
        """Latest-tagged image ref per ECR repository, newest-push first.

        Read-only (describe_* only). Untagged repos are skipped — trivy needs a
        pullable ref. Caps at ``max_images`` so a large registry can't blow up
        the scan."""
        ecr = self.session.client("ecr", region_name=self.region)
        refs: list[str] = []
        try:
            repos = ecr.get_paginator("describe_repositories")
            for page in repos.paginate():
                for repo in page.get("repositories", []):
                    uri = repo.get("repositoryUri")
                    name = repo.get("repositoryName")
                    if not uri or not name:
                        continue
                    tag = self._latest_tag(ecr, name)
                    if tag:
                        refs.append(f"{uri}:{tag}")
                    if len(refs) >= self.max_images:
                        return refs
        except ClientError as e:
            logger.error("ECR describe_repositories failed: %s", e)
        return refs

    def _latest_tag(self, ecr: Any, repo_name: str) -> Optional[str]:
        """Newest-pushed tagged image's first tag, or None if the repo is empty
        / has only untagged images."""
        try:
            imgs = ecr.describe_images(repositoryName=repo_name).get("imageDetails", [])
        except ClientError as e:
            logger.debug("describe_images %s failed: %s", repo_name, e)
            return None
        tagged = [i for i in imgs if i.get("imageTags")]
        if not tagged:
            return None
        tagged.sort(key=lambda i: i.get("imagePushedAt", 0), reverse=True)
        return tagged[0]["imageTags"][0]

    # -- scan -----------------------------------------------------
    def scan_images(self, image_refs: list[str]) -> list[ImageScanResult]:
        if not self.available():
            return [ImageScanResult(image_ref=r, scanned=False,
                                    skipped_reason="trivy binary not installed")
                    for r in image_refs]
        ok, detail = self.verify_binary()
        if not ok:
            logger.error("trivy integrity check failed (%s) — refusing to run", detail)
            return [ImageScanResult(image_ref=r, scanned=False,
                                    skipped_reason=f"trivy integrity check failed: {detail}")
                    for r in image_refs]
        if detail.startswith("unverified"):
            logger.warning("trivy binary integrity is unverified: %s", detail)
        return [self.scan_image(r) for r in image_refs]

    def scan_image(self, image_ref: str) -> ImageScanResult:
        if not self.available():
            return ImageScanResult(image_ref=image_ref, scanned=False,
                                   skipped_reason="trivy binary not installed")
        # Reject refs that look like flags — argv flag-smuggling guard.
        # Even without shell=True, trivy parses its own argv; a ref like
        # "--output=/tmp/x" would be treated as a flag, not an image name.
        # The "--" end-of-options marker is the canonical fix; rejecting
        # leading "-" is defense-in-depth (no valid image ref starts with "-").
        if image_ref.startswith("-"):
            return ImageScanResult(image_ref=image_ref, scanned=False,
                                   skipped_reason="invalid image ref (starts with '-')")
        try:
            proc = subprocess.run(
                ["trivy", "image", "--quiet", "--format", "json",
                 "--scanners", "vuln", "--", image_ref],
                capture_output=True, text=True, timeout=_TRIVY_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return ImageScanResult(image_ref=image_ref, scanned=False,
                                   skipped_reason=f"trivy timed out after {_TRIVY_TIMEOUT}s")
        except Exception as e:  # noqa: BLE001 — binary vanished, OOM, etc.
            return ImageScanResult(image_ref=image_ref, scanned=False,
                                   skipped_reason=f"trivy failed to launch: {e}")
        if proc.returncode != 0:
            return ImageScanResult(image_ref=image_ref, scanned=False,
                                   skipped_reason=f"trivy exit {proc.returncode}: {proc.stderr.strip()[:200]}")
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as e:
            return ImageScanResult(image_ref=image_ref, scanned=False,
                                   skipped_reason=f"trivy JSON parse failed: {e}")
        vulnerabilities = self._parse(data)
        targets = [
            str(result.get("Target"))
            for result in data.get("Results") or []
            if result.get("Target")
        ]
        components = {
            (
                str(v.get("PkgName") or ""),
                str(v.get("InstalledVersion") or ""),
                str(result.get("Type") or ""),
            )
            for result in data.get("Results") or []
            for v in result.get("Vulnerabilities") or []
            if v.get("PkgName")
        }
        return ImageScanResult(
            image_ref=image_ref,
            scanned=True,
            vulnerabilities=vulnerabilities,
            component_count=len(components),
            targets=targets,
        )

    def scan_ebs_snapshot(self, snapshot_id: str) -> EbsSnapshotScanResult:
        """Scan one private EBS snapshot with Trivy's EBS Direct VM target.

        The operation is read-only from Odineyes' perspective. It requires
        ``ebs:ListSnapshotBlocks`` and ``ebs:GetSnapshotBlock`` in the assumed
        disk role. Snapshot creation, sharing, volume attachment and mounting
        are not performed by this method.
        """
        snapshot_id = (snapshot_id or "").strip()
        if not _SNAPSHOT_ID_RE.fullmatch(snapshot_id):
            return EbsSnapshotScanResult(
                snapshot_id=snapshot_id, scanned=False,
                skipped_reason="invalid EBS snapshot id",
            )
        if not self.available():
            return EbsSnapshotScanResult(
                snapshot_id=snapshot_id, scanned=False,
                skipped_reason="trivy binary not installed",
            )
        ok, detail = self.verify_binary()
        if not ok:
            return EbsSnapshotScanResult(
                snapshot_id=snapshot_id, scanned=False,
                skipped_reason=f"trivy integrity check failed: {detail}",
            )
        env, env_error = self._aws_child_env()
        if env is None:
            return EbsSnapshotScanResult(snapshot_id=snapshot_id, scanned=False, skipped_reason=env_error)
        try:
            proc = subprocess.run(
                [
                    "trivy", "vm", "--quiet", "--format", "json", "--scanners", "vuln",
                    "--aws-region", self.region, "--timeout", f"{self._vm_timeout()}s",
                    f"ebs:{snapshot_id}",
                ],
                capture_output=True,
                text=True,
                timeout=self._vm_timeout() + 30,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return EbsSnapshotScanResult(
                snapshot_id=snapshot_id, scanned=False,
                skipped_reason=f"trivy VM scan timed out after {self._vm_timeout()}s",
            )
        except Exception as exc:  # noqa: BLE001
            return EbsSnapshotScanResult(
                snapshot_id=snapshot_id, scanned=False,
                skipped_reason=f"trivy VM scan failed to launch: {exc}",
            )
        if proc.returncode != 0:
            return EbsSnapshotScanResult(
                snapshot_id=snapshot_id, scanned=False,
                skipped_reason=f"trivy VM exit {proc.returncode}: {proc.stderr.strip()[:200]}",
            )
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            return EbsSnapshotScanResult(
                snapshot_id=snapshot_id, scanned=False,
                skipped_reason=f"trivy VM JSON parse failed: {exc}",
            )
        vulnerabilities = self._parse(data)
        for vuln in vulnerabilities:
            vuln.scanner_source = "trivy-ebs"
        targets = [
            str(result.get("Target"))
            for result in data.get("Results") or []
            if result.get("Target")
        ]
        components = {
            (str(v.get("PkgName") or ""), str(v.get("InstalledVersion") or ""), str(result.get("Type") or ""))
            for result in data.get("Results") or []
            for v in result.get("Vulnerabilities") or []
            if v.get("PkgName")
        }
        return EbsSnapshotScanResult(
            snapshot_id=snapshot_id,
            scanned=True,
            vulnerabilities=vulnerabilities,
            component_count=len(components),
            targets=targets,
        )

    # -- SBOM (CycloneDX) -----------------------------------------
    def sbom_image(self, image_ref: str) -> ImageSbomResult:
        """CycloneDX SBOM for one image. Same guards as scan_image (binary
        present + integrity-verified + argv flag-smuggling guard). If trivy is
        absent the SBOM is skipped, never faked."""
        if not self.available():
            return ImageSbomResult(image_ref, False, skipped_reason="trivy binary not installed")
        ok, detail = self.verify_binary()
        if not ok:
            return ImageSbomResult(image_ref, False,
                                   skipped_reason=f"trivy integrity check failed: {detail}")
        if image_ref.startswith("-"):
            return ImageSbomResult(image_ref, False,
                                   skipped_reason="invalid image ref (starts with '-')")
        try:
            proc = subprocess.run(
                ["trivy", "image", "--quiet", "--format", "cyclonedx", "--", image_ref],
                capture_output=True, text=True, timeout=_TRIVY_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return ImageSbomResult(image_ref, False,
                                   skipped_reason=f"trivy timed out after {_TRIVY_TIMEOUT}s")
        except Exception as e:  # noqa: BLE001
            return ImageSbomResult(image_ref, False, skipped_reason=f"trivy failed to launch: {e}")
        if proc.returncode != 0:
            return ImageSbomResult(image_ref, False,
                                   skipped_reason=f"trivy exit {proc.returncode}: {proc.stderr.strip()[:200]}")
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as e:
            return ImageSbomResult(image_ref, False, skipped_reason=f"trivy JSON parse failed: {e}")
        return ImageSbomResult(image_ref, True, sbom=data,
                               component_count=len(data.get("components") or []))

    # -- parsing (pure, fixture-tested) ---------------------------
    @staticmethod
    def _parse(data: dict[str, Any]) -> list[Vulnerability]:
        """Map a trivy ``image --format json`` document into Vulnerability rows.
        Dedups on (cve_id, package, version) — the same CVE can appear under
        multiple Results targets."""
        out: list[Vulnerability] = []
        seen: set[tuple[str, str, str]] = set()
        for result in data.get("Results") or []:
            ecosystem = result.get("Type", "") or ""
            target = result.get("Target") or None
            for v in result.get("Vulnerabilities") or []:
                cve = v.get("VulnerabilityID", "")
                pkg = v.get("PkgName", "")
                ver = v.get("InstalledVersion", "") or ""
                if not cve or not pkg:
                    continue
                key = (cve, pkg, ver)
                if key in seen:
                    continue
                seen.add(key)
                out.append(Vulnerability(
                    cve_id=cve, package=pkg, version=ver, ecosystem=ecosystem,
                    severity=(v.get("Severity", "unknown") or "unknown").lower(),
                    cvss=TrivyScanner._best_cvss(v.get("CVSS") or {}),
                    summary=v.get("Title") or (v.get("Description") or "")[:300] or None,
                    fixed_version=v.get("FixedVersion") or None,
                    scanner_source="trivy",
                    target=target,
                    package_path=v.get("PkgPath") or None,
                ))
        return out

    @staticmethod
    def _best_cvss(cvss: dict[str, Any]) -> Optional[float]:
        """Highest V3 (fallback V2) base score across reporting vendors."""
        scores: list[float] = []
        for vendor in cvss.values():
            if not isinstance(vendor, dict):
                continue
            for k in ("V3Score", "V2Score"):
                s = vendor.get(k)
                if isinstance(s, (int, float)):
                    scores.append(float(s))
                    break
        return max(scores) if scores else None


if __name__ == "__main__":
    # Offline self-check for the parser — the only non-trivial pure logic. Uses a
    # trimmed real ``trivy image --format json`` document; no binary, no AWS.
    _doc = {
        "Results": [
            {"Target": "app:latest (debian 12)", "Type": "debian", "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2023-1111", "PkgName": "openssl",
                 "InstalledVersion": "3.0.1", "FixedVersion": "3.0.2",
                 "Severity": "HIGH", "Title": "openssl flaw",
                 "CVSS": {"nvd": {"V3Score": 7.5}, "redhat": {"V3Score": 6.5}}},
                # duplicate of the above across a second target — must dedup
                {"VulnerabilityID": "CVE-2023-1111", "PkgName": "openssl",
                 "InstalledVersion": "3.0.1", "Severity": "HIGH", "CVSS": {}},
            ]},
            {"Target": "Python", "Type": "python-pkg", "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2024-2222", "PkgName": "requests",
                 "InstalledVersion": "2.0.0", "Severity": "critical",
                 "CVSS": {"nvd": {"V2Score": 9.0}}},
                {"PkgName": "nocve"},  # missing VulnerabilityID — skipped
            ]},
        ]
    }
    vulns = TrivyScanner._parse(_doc)
    assert len(vulns) == 2, f"expected 2 deduped vulns, got {len(vulns)}"
    by_cve = {v.cve_id: v for v in vulns}
    assert by_cve["CVE-2023-1111"].cvss == 7.5, "best V3 across vendors"
    assert by_cve["CVE-2023-1111"].fixed_version == "3.0.2"
    assert by_cve["CVE-2024-2222"].cvss == 9.0 and by_cve["CVE-2024-2222"].severity == "critical"
    assert by_cve["CVE-2024-2222"].ecosystem == "python-pkg"
    print(f"trivy parser self-check OK: {len(vulns)} vulns, dedup + CVSS + skip-missing work")

    # verify_binary pin-resolution — the security-relevant logic — exercised
    # without trivy/network via a temp file standing in for the binary.
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as _f:
        _f.write(b"pretend-trivy-binary")
        _bin = _f.name
    _digest = TrivyScanner._sha256(_bin)
    assert _digest == hashlib.sha256(b"pretend-trivy-binary").hexdigest()
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".sha256") as _f:
        _f.write(_digest + "  trivy\n")  # checksum-file format: "<hash>  <name>"
        _pin = _f.name
    os.environ.pop("ODINEYES_TRIVY_SHA256", None)
    os.environ["ODINEYES_TRIVY_SHA256_FILE"] = _pin
    assert TrivyScanner._expected_sha() == _digest, "file pin must resolve to the hash"
    os.environ["ODINEYES_TRIVY_SHA256"] = "DEADBEEF"
    assert TrivyScanner._expected_sha() == "deadbeef", "explicit pin overrides file, lowercased"
    os.environ.pop("ODINEYES_TRIVY_SHA256", None)
    os.environ.pop("ODINEYES_TRIVY_SHA256_FILE", None)
    os.unlink(_bin)
    os.unlink(_pin)
    print("trivy verify_binary self-check OK: sha256 + file/env pin resolution work")
