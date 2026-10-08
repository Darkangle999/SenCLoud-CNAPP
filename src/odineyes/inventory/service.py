"""Scan-job orchestration.

``persist_scan`` runs one tracked job end to end: register the account, open a
scan_job, normalize each raw resource (a bad resource logs to scan_errors and is
skipped — it never aborts the job), upsert with delta + soft-delete, then close
the job with summary stats. Idempotent: re-running over identical input changes
nothing.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional, Sequence

if TYPE_CHECKING:
    from odineyes.inventory.repository import VulnSyncStats

from odineyes.db.base import init_db, session_scope
from odineyes.db.models import CloudAccount, ScanJob, SecurityScanRun
from odineyes.inventory.collection import CollectionError, CollectionScope
from odineyes.inventory.normalizers import get_normalizer
from odineyes.inventory.repository import (
    AccountRepository,
    AssetRepository,
    DspmRepository,
    DspmSyncStats,
    FindingRepository,
    FindingSyncStats,
    GraphEdgeRepository,
    IssueRepository,
    IssueSyncStats,
    ScanJobRepository,
    ScanScopeRepository,
    SecurityScanRepository,
    VulnerabilityRepository,
)
from odineyes.inventory.schema import NormalizedAsset

# A collected resource: (source_type, raw_api_dict).
RawResource = tuple[str, dict[str, Any]]
logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    scan_job_id: int
    status: str
    found: int
    new: int
    changed: int
    deleted: int
    reactivated: int
    errors: int
    partial: bool = False


@dataclass
class EbsSnapshotScanStats:
    """Persistence outcome for one Trivy EBS Direct scan lifecycle."""

    snapshot_id: str
    scanned: bool
    component_count: int = 0
    findings_count: int = 0
    skipped_reason: str = ""
    sync: Optional["VulnSyncStats"] = None
    instance_id: str = ""
    volume_id: str = ""
    snapshot_deleted: Optional[bool] = None
    cleanup_error: str = ""


_EC2_INSTANCE_ID_RE = re.compile(r"^i-[0-9a-fA-F]{8,32}$")


class InventoryService:
    def __init__(self, database_url: Optional[str] = None, auto_init: bool = True):
        self._url = database_url
        if auto_init:
            init_db(database_url)

    @property
    def database_url(self) -> Optional[str]:
        return self._url

    def begin_scan(
        self,
        provider: str,
        account_identifier: str,
        *,
        account_name: Optional[str] = None,
        role_arn: Optional[str] = None,
        scan_type: str = "config",
    ) -> int:
        """Create a durable running job *before* contacting a cloud provider.

        Collection can fail during AssumeRole, region discovery, or a first API
        call. Creating this record first makes those failures observable to the
        UI instead of leaving a newly connected account looking permanently
        empty.
        """
        with session_scope(self._url) as session:
            account = AccountRepository.get_or_create(
                session, provider, account_identifier, account_name, role_arn,
            )
            job = ScanJobRepository.create(session, account, scan_type)
            ScanJobRepository.start(job)
            return job.id

    def fail_scan(self, scan_job_id: int, message: str) -> None:
        """Best-effort terminal failure for collection/preflight errors."""
        with session_scope(self._url) as session:
            job = session.get(ScanJob, scan_job_id)
            if job is None or job.status in {"completed", "failed"}:
                return
            ScanJobRepository.fail(session, job, message)

    def persist_scan(
        self,
        provider: str,
        account_identifier: str,
        resources: Sequence[RawResource],
        *,
        account_name: Optional[str] = None,
        role_arn: Optional[str] = None,
        scan_type: str = "config",
        authoritative_scopes: Optional[set[CollectionScope]] = None,
        collection_errors: Sequence[CollectionError] = (),
        scan_job_id: Optional[int] = None,
    ) -> ScanResult:
        # Commit the lifecycle row before the work transaction. If persistence
        # fails (constraint, disk, serialization, etc.), the job can still be
        # marked failed instead of vanishing in the rollback.
        with session_scope(self._url) as session:
            if scan_job_id is None:
                account = AccountRepository.get_or_create(
                    session, provider, account_identifier, account_name, role_arn,
                )
                job = ScanJobRepository.create(session, account, scan_type)
                ScanJobRepository.start(job)
            else:
                job = session.get(ScanJob, scan_job_id)
                if job is None:
                    raise RuntimeError(f"scan job {scan_job_id} not found")
                account = session.get(CloudAccount, job.account_id)
                if account is None:
                    raise RuntimeError("scan account disappeared before persistence")
                if (account.provider, account.account_identifier) != (provider, account_identifier):
                    raise RuntimeError("scan job does not belong to the requested cloud account")
                if job.status != "running":
                    raise RuntimeError(f"scan job {scan_job_id} is not running")
            account_id = account.id
            job_id = job.id

        try:
            with session_scope(self._url) as session:
                account = session.get(CloudAccount, account_id)
                job = session.get(ScanJob, job_id)
                if account is None or job is None:
                    raise RuntimeError("scan account/job disappeared before persistence")

                effective_scopes = None if authoritative_scopes is None else set(authoritative_scopes)
                scope_errors = list(collection_errors)
                for error in collection_errors:
                    ScanJobRepository.add_error(
                        session,
                        job,
                        error.scan_message(),
                        resource_type=error.source_type,
                    )

                normalized: list[NormalizedAsset] = []
                observed_counts: dict[tuple[str, str], int] = {}
                normalization_failed = False
                for source_type, raw in resources:
                    raw_region = str(raw.get("Region") or raw.get("region") or "*")
                    fn = get_normalizer(source_type)
                    if fn is None:
                        normalization_failed = True
                        effective_scopes = self._protect_failed_scope(effective_scopes, source_type, raw)
                        scope_errors.append(CollectionError(
                            source_type=source_type, operation="normalize",
                            message=f"no normalizer registered for '{source_type}'", region=raw_region,
                        ))
                        ScanJobRepository.add_error(
                            session, job, f"no normalizer registered for '{source_type}'",
                            resource_type=source_type,
                        )
                        continue
                    try:
                        res = fn(raw, account_identifier)
                        if res is not None:
                            normalized.append(res)
                            observed_counts[(source_type, raw_region)] = (
                                observed_counts.get((source_type, raw_region), 0) + 1
                            )
                    except Exception as exc:  # one bad resource must not fail the job
                        normalization_failed = True
                        effective_scopes = self._protect_failed_scope(effective_scopes, source_type, raw)
                        scope_errors.append(CollectionError(
                            source_type=source_type, operation="normalize",
                            message=str(exc), region=raw_region,
                        ))
                        ScanJobRepository.add_error(
                            session, job, str(exc),
                            resource_id=raw.get("Name") or raw.get("name") or raw.get("id"),
                            resource_type=source_type,
                        )

                stats = AssetRepository.upsert_assets(
                    session,
                    account,
                    job,
                    normalized,
                    authoritative_scopes=effective_scopes,
                )
                ScanScopeRepository.sync(
                    session, job, effective_scopes, scope_errors, observed_counts,
                )
                ScanJobRepository.complete(job, stats)

                return ScanResult(
                    scan_job_id=job.id,
                    status=job.status,
                    found=stats.found,
                    new=stats.new,
                    changed=stats.changed,
                    deleted=stats.deleted,
                    reactivated=stats.reactivated,
                    errors=job.error_count,
                    partial=bool(collection_errors) or normalization_failed,
                )
        except Exception as exc:
            # Best-effort failure recording must never mask the original error.
            try:
                with session_scope(self._url) as session:
                    failed_job = session.get(ScanJob, job_id)
                    if failed_job is not None:
                        ScanJobRepository.fail(session, failed_job, str(exc))
            except Exception:  # noqa: BLE001
                logger.exception("could not persist failure state for scan job %s", job_id)
            raise

    @staticmethod
    def _protect_failed_scope(
        scopes: Optional[set[CollectionScope]],
        source_type: str,
        raw: dict[str, Any],
    ) -> set[CollectionScope]:
        """Remove a malformed resource's scope from deletion authority.

        For an explicit full-snapshot import (``scopes is None``), any malformed
        row makes absence ambiguous, so deletion is disabled for that run.
        """
        if scopes is None:
            return set()
        protected = set(scopes)
        if (source_type, None) in protected:
            protected.discard((source_type, None))
            return protected
        region = raw.get("Region") or raw.get("region") or raw.get("location")
        if region:
            protected.discard((source_type, str(region)))
        else:
            protected = {scope for scope in protected if scope[0] != source_type}
        return protected

    def persist_normalized(
        self,
        provider: str,
        account_identifier: str,
        assets: Sequence[NormalizedAsset],
        *,
        account_name: Optional[str] = None,
        scan_type: str = "config",
    ) -> ScanResult:
        """Persist pre-normalized assets (callers that normalize upstream)."""
        with session_scope(self._url) as session:
            account = AccountRepository.get_or_create(session, provider, account_identifier, account_name)
            job = ScanJobRepository.create(session, account, scan_type)
            ScanJobRepository.start(job)
            account_id = account.id
            job_id = job.id
        try:
            with session_scope(self._url) as session:
                account = session.get(CloudAccount, account_id)
                job = session.get(ScanJob, job_id)
                if account is None or job is None:
                    raise RuntimeError("scan account/job disappeared before persistence")
                stats = AssetRepository.upsert_assets(session, account, job, list(assets))
                ScanJobRepository.complete(job, stats)
                return ScanResult(
                    scan_job_id=job.id, status=job.status, found=stats.found, new=stats.new,
                    changed=stats.changed, deleted=stats.deleted, reactivated=stats.reactivated,
                    errors=job.error_count,
                )
        except Exception as exc:
            try:
                with session_scope(self._url) as session:
                    failed_job = session.get(ScanJob, job_id)
                    if failed_job is not None:
                        ScanJobRepository.fail(session, failed_job, str(exc))
            except Exception:  # noqa: BLE001
                logger.exception("could not persist failure state for scan job %s", job_id)
            raise

    def evaluate_findings(self, provider: str, account_identifier: str) -> FindingSyncStats:
        """Run the rules engine over the account's active assets and persist the
        verdicts (open/resolve/reopen). Idempotent on an unchanged inventory."""
        # Local import avoids a module-level cycle (rules imports db.models).
        from odineyes.inventory.rules import evaluate
        from odineyes.inventory.tuning import dspm_taxonomies_for_account

        with session_scope(self._url) as session:
            account = AccountRepository.get_or_create(session, provider, account_identifier)
            assets = [a for a in account.assets if a.is_active]
            # Finding freshness inherits the asset's last AWS-confirmed time, so a
            # rules-only re-evaluate over stale inventory can't make a deleted
            # resource's finding look freshly seen.
            asset_seen = {a.resource_id: a.last_scanned_at for a in assets}
            # Without this the DSPM tuning layer sees no classifications and
            # every encryption gap reads as "no regulated data proven".
            findings = evaluate(
                assets,
                dspm_taxonomies=dspm_taxonomies_for_account(session, account.id),
                include_suppressed=True,
            )
            stats = FindingRepository.sync(session, account, findings, asset_seen=asset_seen)
            IssueRepository.update_asset_risk(session, account)
            return stats

    def scan_trivy_misconfig(
        self, provider: str, account_identifier: str, *,
        region: Optional[str] = None, session: Optional[Any] = None,
        services: Optional[Sequence[str]] = None,
    ) -> dict[str, Any]:
        """CSPM engine #2: run Trivy's built-in AWS misconfiguration checks
        (AVD-AWS-*) against this account and merge the FAIL findings into the
        same findings table the native rules write to.

        Read-only and skippable: without the trivy binary, usable credentials,
        or a successful scan the step reports skipped and - critically - does
        not touch existing findings, so a transient failure can never
        mass-resolve previously seen Trivy results. Findings are namespaced by
        their AVD-AWS-* rule ids and resolved within that namespace only
        (``resolve_prefix``), so a Trivy-only sync can never resolve a native
        finding.
        """
        from odineyes.cloud import trivy_misconfig
        from odineyes.inventory.repository import FindingRepository

        out: dict[str, Any] = {"engine": "trivy-aws", "account": account_identifier}
        if not trivy_misconfig.available():
            out.update(status="skipped", reason="trivy not installed")
            return out
        if session is None:
            import boto3  # AWS-only engine; keep the service import-surface clean
            session = boto3.Session(region_name=region or "us-east-1")
        results, err = trivy_misconfig.scan_cloud(session, region=region, services=services)
        if err:
            out.update(status="skipped", reason=err)
            return out
        findings = trivy_misconfig.to_findings(results)
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        with session_scope(self._url) as db:
            account = AccountRepository.get_or_create(db, provider, account_identifier)
            assets = [a for a in account.assets if a.is_active]
            stats = FindingRepository.sync(
                db, account, findings,
                asset_seen={a.resource_id: a.last_scanned_at for a in assets},
                resolve_prefix="AVD-",
            )
            IssueRepository.update_asset_risk(db, account)
            out.update(
                status="completed",
                resources_scanned=len(results),
                findings=len(findings),
                by_severity=by_sev,
                total=stats.total, new=stats.new,
                resolved=stats.resolved, reopened=stats.reopened,
            )
        return out

    def snapshot_compliance(self, provider: str, account_identifier: str, frameworks: list[str]) -> dict[str, Any]:
        """Generate a compliance snapshot from the latest active findings."""
        from sqlalchemy import select
        
        from odineyes.core.compliance_mapper import ComplianceMapper
        from odineyes.db.models import Finding
        from odineyes.inventory.repository import ComplianceRepository

        with session_scope(self._url) as session:
            account = AccountRepository.get_or_create(session, provider, account_identifier)
            
            db_findings = session.execute(
                select(Finding).where(Finding.account_id == account.id)
            ).scalars().all()
            
            mapped_findings = [
                {
                    "check_id": f.rule_id,
                    "status": "FAIL" if f.status == "open" else "PASS",
                    "compliance_mappings": f.compliance or {}
                }
                for f in db_findings
            ]
            
            mapper = ComplianceMapper()
            comp = mapper.score(mapped_findings, frameworks)
            
            stats = ComplianceRepository.snapshot(
                session, compliance=comp,
                account=account.account_identifier, region="global",
                origin="inventory"
            )
            return stats

    def build_graph(self, provider: str, account_identifier: Optional[str]) -> dict[str, Any]:
        """Serialize the security graph (nodes + edges) for the canvas, with open
        attack-path issues overlaid as 'finding' nodes anchored to their entry
        asset and every reachable attacker route enumerated under ``paths``.
        Isolated (degree-0) assets are dropped as noise. ``account_identifier``
        None merges every active account into one fleet-wide graph (so
        cross-account trust edges connect)."""
        from sqlalchemy import select

        from odineyes.db.models import CloudAccount
        from odineyes.inventory.graph import AssetGraph
        from odineyes.inventory.reachability_layers import data_labels_for_account
        # Engine selection (Go / Python / shadow) lives in graph_engine; it
        # falls back to the in-process engine whenever Go is unavailable.
        from odineyes.inventory.graph_engine import analyze

        with session_scope(self._url) as session:
            if account_identifier is None:
                accounts = list(session.execute(
                    select(CloudAccount).where(CloudAccount.is_active.is_(True))
                ).scalars())
                assets = [a for acct in accounts for a in acct.assets if a.is_active]
                label = "all accounts"
            else:
                account = AccountRepository.get_or_create(session, provider, account_identifier)
                accounts = [account]
                assets = [a for a in account.assets if a.is_active]
                label = account_identifier
            external_ids = {
                str(acct.account_identifier): str(acct.external_id)
                for acct in accounts if acct.external_id
            }
            role_arns = {
                str(acct.account_identifier): str(acct.role_arn)
                for acct in accounts if acct.is_active and acct.role_arn
            }
            scanner_principal = os.environ.get("ODINEYES_SCANNER_PRINCIPAL_ARN", "").strip() or None
            # Without labels the data layer cannot be proven and nothing ever
            # reaches a toxic verdict. Union across the accounts in scope, since
            # a fleet-wide graph merges them.
            data_labels: dict[str, str] = {}
            for acct in accounts:
                data_labels.update(data_labels_for_account(session, acct.id))
            g = AssetGraph.build(
                assets,
                scanner_principal_arn=scanner_principal,
                account_external_ids=external_ids,
                account_role_arns=role_arns,
                data_labels=data_labels,
            )
            issues = analyze(
                assets,
                scanner_principal_arn=scanner_principal,
                account_external_ids=external_ids,
                account_role_arns=role_arns,
                data_labels=data_labels,
            )
            data = g.serialize()  # while assets are still attached

        data["paths"] = g.enumerate_paths()
        data["analysis"] = g.analysis_summary(total_assets=len(assets), paths=data["paths"])
        node_ids = {n["id"] for n in data["nodes"]}
        for issue in issues:
            fid = "finding:" + issue.path_hash[:12]
            data["nodes"].append({
                "id": fid, "kind": "finding", "name": issue.title,
                "severity": issue.severity, "risk_score": issue.risk_score,
                "issue_type": issue.issue_type, "resource_id": issue.resource_id,
                "is_public": False, "properties": {},
            })
            if issue.resource_id in node_ids:
                data["edges"].append({"source": issue.resource_id, "target": fid, "type": "HAS_FINDING"})

        degree: dict[str, int] = {}
        for e in data["edges"]:
            degree[e["source"]] = degree.get(e["source"], 0) + 1
            degree[e["target"]] = degree.get(e["target"], 0) + 1
        kept = {n["id"] for n in data["nodes"] if degree.get(n["id"], 0) > 0}
        data["nodes"] = [n for n in data["nodes"] if n["id"] in kept]
        # Drop enumerated paths that referenced a pruned (degree-0) node.
        data["paths"] = [p for p in data["paths"] if all(nid in kept for nid in p["nodes"])]
        data["account"] = label
        data["provider"] = provider
        return data

    def scan_vulnerabilities(
        self, provider: str, account_identifier: str,
        region: str = "us-east-1", profile: Optional[str] = None,
    ) -> VulnSyncStats:
        """CWPP: package-inventory the account's EC2 (via SSM) and match against
        OSV, then persist the CVEs with an open/resolved lifecycle. Only
        SSM-managed, Online instances yield data — the rest are reported skipped.
        Requires live AWS credentials; raises on credential/permission failure.
        """
        from types import SimpleNamespace

        from odineyes.cloud.cve_scanner import CveScanner
        from odineyes.inventory.repository import VulnerabilityRepository, VulnSyncStats

        with session_scope(self._url) as session:
            account = AccountRepository.get_or_create(session, provider, account_identifier)
            id_to_arn = {
                a.resource_id.rsplit("/", 1)[-1]: a.resource_id
                for a in account.assets
                if a.is_active and a.asset_type == "aws.ec2.instance"
            }
            if not id_to_arn:
                return VulnSyncStats()

            scanner = CveScanner(region=region, profile=profile)
            results = scanner.scan_instances(list(id_to_arn))

            vulns: list[Any] = []
            scanned = managed = 0
            for res in results:
                scanned += 1
                if res.ssm_managed:
                    managed += 1
                arn = id_to_arn.get(res.instance_id, res.instance_id)
                for v in res.vulnerabilities:
                    if not v.cve_id:
                        continue
                    vulns.append(SimpleNamespace(
                        resource_id=arn, cve_id=v.cve_id, package=v.package,
                        installed_version=v.version,
                        severity=(v.severity or "unknown").lower(),
                        cvss=v.cvss, summary=v.summary, fixed_version=v.fixed_version,
                        epss=v.epss, epss_percentile=v.epss_percentile, kev=v.kev,
                        scanner_source="ssm-osv", package_type=v.ecosystem,
                        target=getattr(v, "target", None),
                        package_path=getattr(v, "package_path", None),
                    ))
                SecurityScanRepository.record(
                    session,
                    account,
                    resource_id=arn,
                    scanner="ssm-osv",
                    scan_kind="host_packages",
                    status="completed" if res.ssm_managed else "skipped",
                    package_count=res.package_count,
                    findings_count=len(res.vulnerabilities),
                    status_reason=res.skipped_reason,
                    evidence={"instance_id": res.instance_id, "ssm_managed": res.ssm_managed},
                )

            # Scope the resolve pass to the EC2 ARNs we actually scanned so a host
            # scan never resolves container-image CVEs sharing this table.
            stats = VulnerabilityRepository.sync(
                session, account, vulns, scanned_resources=set(id_to_arn.values()))
            stats.instances_scanned = scanned
            stats.ssm_managed = managed
            return stats

    def scan_container_vulnerabilities(
        self, provider: str, account_identifier: str,
        region: str = "us-east-1", profile: Optional[str] = None,
        image_refs: Optional[Sequence[str]] = None,
    ) -> VulnSyncStats:
        """CWPP for containers: discover ECR images (or use explicit
        ``image_refs``), scan each with Trivy, and persist the CVEs with the same
        open/resolved lifecycle as the host path. resource_id is the image ref.
        Requires the trivy binary; images that can't be scanned are reported
        skipped, never faked. Requires live AWS credentials for ECR discovery."""
        from types import SimpleNamespace

        from odineyes.cloud.trivy_scanner import TrivyScanner
        from odineyes.inventory.repository import VulnerabilityRepository, VulnSyncStats

        scanner = TrivyScanner(region=region, profile=profile)
        refs = list(image_refs) if image_refs else scanner.discover_ecr_images()
        if not refs:
            return VulnSyncStats()

        with session_scope(self._url) as session:
            account = AccountRepository.get_or_create(session, provider, account_identifier)
            results = scanner.scan_images(refs)

            vulns: list[Any] = []
            scanned = 0
            for res in results:
                if res.scanned:
                    scanned += 1
                for v in res.vulnerabilities:
                    if not v.cve_id:
                        continue
                    vulns.append(SimpleNamespace(
                        resource_id=res.image_ref, cve_id=v.cve_id, package=v.package,
                        installed_version=v.version,
                        severity=(v.severity or "unknown").lower(),
                        cvss=v.cvss, summary=v.summary, fixed_version=v.fixed_version,
                        epss=v.epss, epss_percentile=v.epss_percentile, kev=v.kev,
                        scanner_source="trivy", package_type=v.ecosystem,
                        target=getattr(v, "target", None),
                        package_path=getattr(v, "package_path", None),
                    ))
                SecurityScanRepository.record(
                    session,
                    account,
                    resource_id=res.image_ref,
                    scanner="trivy",
                    scan_kind="container_image",
                    status="completed" if res.scanned else "skipped",
                    package_count=res.component_count,
                    findings_count=len(res.vulnerabilities),
                    status_reason=res.skipped_reason,
                    evidence={"targets": res.targets, "count_basis": "vulnerable_components"},
                )

            # Independent NVD cross-check (opt-in via nvd_audit.audit_enabled).
            # Trivy is fast but a compromised release could fabricate or mute CVEs
            # in its JSON; re-derive each verdict from NVD's own CPE data and flag
            # anything NVD says is a false positive. Best-effort — never sinks the
            # scan, and off the hot path unless a feed mirror is configured.
            from odineyes.cloud.nvd_audit import NvdAuditor, audit_enabled
            if audit_enabled():
                import logging
                log = logging.getLogger(__name__)
                try:
                    audit = NvdAuditor().audit(
                        v for r in results for v in r.vulnerabilities if v.cve_id)
                    summ = NvdAuditor.summarize(audit)
                    log.info("NVD audit of trivy findings: %s", summ["counts"])
                    if summ["refuted"]:
                        log.warning(
                            "NVD audit REFUTED %d trivy finding(s) — possible false "
                            "positive or tampered scanner: %s",
                            len(summ["refuted"]), summ["refuted"][:10])
                except Exception:  # noqa: BLE001 — audit must not break the scan
                    log.warning("NVD audit pass failed", exc_info=True)

            # Resolve only within the image refs we scanned (never host CVEs).
            stats = VulnerabilityRepository.sync(
                session, account, vulns, scanned_resources=set(refs))
            stats.instances_scanned = len(refs)
            stats.ssm_managed = scanned  # reused: images successfully scanned by trivy
            return stats

    def scan_ebs_snapshot_vulnerabilities(
        self, provider: str, account_identifier: str, *, snapshot_id: str,
        region: str = "us-east-1",
    ) -> EbsSnapshotScanStats:
        """Run Trivy VM against an explicitly supplied EBS snapshot.

        This path never creates, shares, mounts or deletes snapshots. It assumes
        only the opt-in disk-scan role that onboarding creates separately, then
        sends temporary credentials to the Trivy process for EBS Direct reads.
        A skipped or failed scan records coverage but never resolves old CVEs.
        """
        from odineyes.cloud.trivy_scanner import TrivyScanner

        with session_scope(self._url) as session:
            account = AccountRepository.get_or_create(session, provider, account_identifier)
            resource_id = next(
                (
                    asset.resource_id for asset in account.assets
                    if asset.is_active and asset.resource_id.endswith(f"snapshot/{snapshot_id}")
                ),
                snapshot_id,
            )
            role_arn = account.disk_scan_role_arn
            external_id = account.external_id

        evidence = {"snapshot_id": snapshot_id, "region": region, "mode": "ebs_direct"}
        if not role_arn:
            reason = "disk scanning is not enabled for this account"
            return self._persist_ebs_result(
                provider, account_identifier, resource_id=resource_id, snapshot_id=snapshot_id,
                scanned=False, skipped_reason=reason, scan_kind="ebs_snapshot", evidence=evidence,
            )
        try:
            disk_session = TrivyScanner.assume_role_session(
                role_arn=role_arn, external_id=external_id, region=region,
            )
        except Exception as exc:  # noqa: BLE001 - store no credential material
            reason = f"could not assume disk-scan role: {str(exc)[:240]}"
            return self._persist_ebs_result(
                provider, account_identifier, resource_id=resource_id, snapshot_id=snapshot_id,
                scanned=False, skipped_reason=reason, scan_kind="ebs_snapshot", evidence=evidence,
            )

        result = TrivyScanner(region=region, session=disk_session).scan_ebs_snapshot(snapshot_id)
        evidence.update({"scanners": ["vuln"], "targets": result.targets})
        return self._persist_ebs_result(
            provider, account_identifier, resource_id=resource_id, snapshot_id=snapshot_id,
            scanned=result.scanned, vulnerabilities=result.vulnerabilities,
            component_count=result.component_count, skipped_reason=result.skipped_reason,
            scan_kind="ebs_snapshot", evidence=evidence,
        )

    def scan_ec2_instance_vulnerabilities(
        self, provider: str, account_identifier: str, *, instance_id: str,
        region: str = "us-east-1",
    ) -> EbsSnapshotScanStats:
        """Create, scan, and delete one tagged root-volume snapshot.

        Aqua Trivy remains the scanner. Odineyes only controls lifecycle and
        persistence. Root-volume-only, cooldown, and volume-size guards bound
        EBS Direct API cost. Cleanup runs even when Trivy or persistence fails.
        """
        from odineyes.cloud.trivy_scanner import TrivyScanner

        instance_id = (instance_id or "").strip()
        if provider != "aws" or not _EC2_INSTANCE_ID_RE.fullmatch(instance_id):
            return EbsSnapshotScanStats(
                snapshot_id="", scanned=False, instance_id=instance_id,
                skipped_reason="invalid AWS EC2 instance id",
            )
        resource_id = f"arn:aws:ec2:{region}:{account_identifier}:instance/{instance_id}"
        with session_scope(self._url) as session:
            account = AccountRepository.get_or_create(session, provider, account_identifier)
            role_arn = account.disk_scan_role_arn
            external_id = account.external_id
            cooldown_hours = self._bounded_env_int("ODINEYES_EBS_SCAN_COOLDOWN_HOURS", 12, 1, 168)
            cutoff = datetime.now(timezone.utc) - timedelta(hours=cooldown_hours)
            recent = session.query(SecurityScanRun.id).filter(
                SecurityScanRun.account_id == account.id,
                SecurityScanRun.resource_id == resource_id,
                SecurityScanRun.scan_kind == "ebs_instance",
                SecurityScanRun.status == "completed",
                SecurityScanRun.scanned_at >= cutoff,
            ).first()
        if not role_arn:
            reason = "disk scanning is not enabled for this account"
            return self._persist_ebs_result(
                provider, account_identifier, resource_id=resource_id, snapshot_id="",
                scanned=False, skipped_reason=reason, scan_kind="ebs_instance",
                evidence={"instance_id": instance_id, "region": region, "mode": "ebs_direct_lifecycle"},
                instance_id=instance_id,
            )
        if recent:
            return EbsSnapshotScanStats(
                snapshot_id="", scanned=False, instance_id=instance_id,
                skipped_reason=f"instance was scanned within the {cooldown_hours} hour cooldown",
            )

        try:
            disk_session = TrivyScanner.assume_role_session(
                role_arn=role_arn, external_id=external_id, region=region,
                session_name="odineyes-ebs-instance-scan",
            )
        except Exception as exc:  # noqa: BLE001
            reason = f"could not assume disk-scan role: {str(exc)[:240]}"
            return self._persist_ebs_result(
                provider, account_identifier, resource_id=resource_id, snapshot_id="",
                scanned=False, skipped_reason=reason, scan_kind="ebs_instance",
                evidence={"instance_id": instance_id, "region": region, "mode": "ebs_direct_lifecycle"},
                instance_id=instance_id,
            )

        ec2 = disk_session.client("ec2", region_name=region)
        snapshot_id = ""
        volume_id = ""
        deleted: Optional[bool] = None
        cleanup_error = ""
        result = None
        failure = ""
        volume_size = 0
        try:
            described = ec2.describe_instances(InstanceIds=[instance_id])
            instances = [
                item for reservation in described.get("Reservations", [])
                for item in reservation.get("Instances", [])
            ]
            if len(instances) != 1:
                raise RuntimeError("EC2 instance was not found in the requested account and region")
            instance = instances[0]
            root_device = instance.get("RootDeviceName")
            volume_id = next(
                (
                    mapping.get("Ebs", {}).get("VolumeId", "")
                    for mapping in instance.get("BlockDeviceMappings", [])
                    if mapping.get("DeviceName") == root_device
                ),
                "",
            )
            if not volume_id:
                raise RuntimeError("EC2 root EBS volume could not be resolved")
            volumes = ec2.describe_volumes(VolumeIds=[volume_id]).get("Volumes", [])
            if len(volumes) != 1:
                raise RuntimeError("EC2 root EBS volume could not be described")
            volume_size = int(volumes[0].get("Size") or 0)
            max_gib = self._bounded_env_int("ODINEYES_EBS_DIRECT_MAX_VOLUME_GIB", 100, 1, 16384)
            if volume_size > max_gib:
                raise RuntimeError(
                    f"root volume is {volume_size} GiB, above EBS Direct scan limit {max_gib} GiB"
                )

            expiry = datetime.now(timezone.utc) + timedelta(hours=2)
            created = ec2.create_snapshot(
                VolumeId=volume_id,
                Description="Odineyes temporary agentless vulnerability scan",
                TagSpecifications=[{
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "ManagedBy", "Value": "CSPM-G3"},
                        {"Key": "Purpose", "Value": "OdineyesAgentlessScan"},
                        {"Key": "SourceInstanceId", "Value": instance_id},
                        {"Key": "ExpiresAt", "Value": expiry.isoformat()},
                    ],
                }],
            )
            snapshot_id = str(created.get("SnapshotId") or "")
            if not snapshot_id:
                raise RuntimeError("EC2 did not return a snapshot id")
            wait_seconds = self._bounded_env_int("ODINEYES_EBS_SNAPSHOT_WAIT_SECONDS", 1800, 60, 7200)
            ec2.get_waiter("snapshot_completed").wait(
                SnapshotIds=[snapshot_id],
                WaiterConfig={"Delay": 15, "MaxAttempts": max(1, wait_seconds // 15)},
            )
            result = TrivyScanner(region=region, session=disk_session).scan_ebs_snapshot(snapshot_id)
        except Exception as exc:  # noqa: BLE001
            failure = str(exc)[:300]
        finally:
            if snapshot_id:
                try:
                    ec2.delete_snapshot(SnapshotId=snapshot_id)
                    deleted = True
                except Exception as exc:  # noqa: BLE001
                    deleted = False
                    cleanup_error = str(exc)[:300]

        evidence = {
            "instance_id": instance_id,
            "volume_id": volume_id,
            "volume_size_gib": volume_size,
            "snapshot_id": snapshot_id,
            "snapshot_deleted": deleted,
            "region": region,
            "mode": "ebs_direct_lifecycle",
            "root_volume_only": True,
            "scanner_engine": "aquasecurity-trivy",
        }
        if cleanup_error:
            evidence["cleanup_error"] = cleanup_error
        if result is None:
            return self._persist_ebs_result(
                provider, account_identifier, resource_id=resource_id, snapshot_id=snapshot_id,
                scanned=False, skipped_reason=failure or "EBS lifecycle scan failed",
                scan_kind="ebs_instance", evidence=evidence, instance_id=instance_id,
                volume_id=volume_id, snapshot_deleted=deleted, cleanup_error=cleanup_error,
            )
        evidence.update({"scanners": ["vuln"], "targets": result.targets})
        return self._persist_ebs_result(
            provider, account_identifier, resource_id=resource_id, snapshot_id=snapshot_id,
            scanned=result.scanned, vulnerabilities=result.vulnerabilities,
            component_count=result.component_count, skipped_reason=result.skipped_reason,
            scan_kind="ebs_instance", evidence=evidence, instance_id=instance_id,
            volume_id=volume_id, snapshot_deleted=deleted, cleanup_error=cleanup_error,
        )

    @staticmethod
    def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
        try:
            return min(maximum, max(minimum, int(os.environ.get(name, str(default)))))
        except ValueError:
            return default

    def _persist_ebs_result(
        self, provider: str, account_identifier: str, *, resource_id: str,
        snapshot_id: str, scanned: bool, skipped_reason: str = "",
        vulnerabilities: Optional[list[Any]] = None, component_count: int = 0,
        scan_kind: str, evidence: Optional[dict[str, Any]] = None,
        instance_id: str = "", volume_id: str = "",
        snapshot_deleted: Optional[bool] = None, cleanup_error: str = "",
    ) -> EbsSnapshotScanStats:
        """Persist normalized Trivy output. No filesystem or snapshot data is stored."""
        from types import SimpleNamespace

        vulnerabilities = vulnerabilities or []
        with session_scope(self._url) as session:
            account = AccountRepository.get_or_create(session, provider, account_identifier)
            status_reason = skipped_reason or cleanup_error
            SecurityScanRepository.record(
                session, account, resource_id=resource_id, scanner="trivy-ebs",
                scan_kind=scan_kind,
                status="cleanup_failed" if cleanup_error else ("completed" if scanned else "skipped"),
                package_count=component_count, findings_count=len(vulnerabilities),
                status_reason=status_reason, evidence=evidence,
            )
            sync = None
            if scanned:
                rows = [
                    SimpleNamespace(
                        resource_id=resource_id, cve_id=v.cve_id, package=v.package,
                        installed_version=v.version, severity=(v.severity or "unknown").lower(),
                        cvss=v.cvss, summary=v.summary, fixed_version=v.fixed_version,
                        epss=v.epss, epss_percentile=v.epss_percentile, kev=v.kev,
                        scanner_source="trivy-ebs", package_type=v.ecosystem,
                        target=v.target, package_path=v.package_path,
                    )
                    for v in vulnerabilities if v.cve_id
                ]
                sync = VulnerabilityRepository.sync(
                    session, account, rows, scanned_resources={resource_id},
                )
        return EbsSnapshotScanStats(
            snapshot_id=snapshot_id, scanned=scanned, component_count=component_count,
            findings_count=len(vulnerabilities), skipped_reason=skipped_reason, sync=sync,
            instance_id=instance_id, volume_id=volume_id,
            snapshot_deleted=snapshot_deleted, cleanup_error=cleanup_error,
        )

    def evaluate_issues(self, provider: str, account_identifier: str) -> IssueSyncStats:
        """Run the attack-path engine over the account's active assets, persist
        the issues (open/resolve/reopen), and refresh per-asset risk scores.
        Idempotent on an unchanged inventory. When ODINEYES_NEO4J_URI is
        set, the security graph is also projected into Neo4j (best-effort)."""
        from odineyes.inventory.graph import AssetGraph
        from odineyes.inventory.reachability_layers import data_labels_for_account
        from odineyes.inventory.graph_store import Neo4jGraphStore
        # Engine selection (Go / Python / shadow) lives in graph_engine; it
        # falls back to the in-process engine whenever Go is unavailable.
        from odineyes.inventory.graph_engine import analyze

        with session_scope(self._url) as session:
            account = AccountRepository.get_or_create(session, provider, account_identifier)
            assets = [a for a in account.assets if a.is_active]
            asset_seen = {a.resource_id: a.last_scanned_at for a in assets}
            scanner_principal = os.environ.get("ODINEYES_SCANNER_PRINCIPAL_ARN", "").strip() or None
            external_ids = (
                {str(account.account_identifier): str(account.external_id)}
                if account.external_id else {}
            )
            role_arns = (
                {str(account.account_identifier): str(account.role_arn)}
                if account.is_active and account.role_arn else {}
            )
            data_labels = data_labels_for_account(session, account.id)
            issues = analyze(
                assets,
                scanner_principal_arn=scanner_principal,
                account_external_ids=external_ids,
                account_role_arns=role_arns,
                data_labels=data_labels,
            )
            stats = IssueRepository.sync(session, account, issues, asset_seen=asset_seen)
            # Persist the derived graph edges (history + restart-survival of the
            # attack-path backbone). Build once, reuse for the Neo4j projection.
            graph = AssetGraph.build(
                assets,
                scanner_principal_arn=scanner_principal,
                account_external_ids=external_ids,
                account_role_arns=role_arns,
                data_labels=data_labels,
            )
            GraphEdgeRepository.sync(session, account, graph.all_edges())
            # Keep live-exploitation state coherent before deriving asset risk:
            # decay stale flags and restore the exploitation floor that sync
            # overwrote, so the floor propagates into per-asset risk too.
            from odineyes.inventory.exploitation import reconcile
            reconcile(session)
            # exploit_maturity: weight paths whose entry host carries a KEV /
            # high-EPSS CVE (a weaponized vuln = a more viable kill chain).
            VulnerabilityRepository.apply_exploit_maturity(session, account)
            session.flush()
            IssueRepository.update_asset_risk(session, account)

            store = Neo4jGraphStore.from_env()
            if store is not None:
                try:
                    store.sync_account(account_identifier, graph)
                except Exception:  # noqa: BLE001 — projection never sinks evaluation
                    import logging
                    logging.getLogger(__name__).warning(
                        "Neo4j graph projection failed for %s", account_identifier, exc_info=True,
                    )
                finally:
                    store.close()
            return stats

    def scan_dspm(
        self, provider: str, account_identifier: str, session: Any, region: str,
        *, read_secret_values: bool = False,
    ) -> DspmSyncStats:
        """Classify + persist DSPM data stores from a live boto3 ``session``.

        Replaces the old ``_run_live`` DSPM path (which needed the in-memory
        SecurityGraph + legacy collector). S3 buckets are read from the
        already-persisted inventory so the normalizer's public/encryption verdict
        is reused; other stores (RDS/DynamoDB/Secrets/SSM/snapshots) are scanned
        directly off the session. Caller runs ``persist_scan`` first so S3 assets
        exist. Each scanner is guarded — a missing permission skips that store,
        never the cycle."""
        import logging
        from types import SimpleNamespace

        from odineyes.dspm.engine import DspmEngine
        from odineyes.dspm.stores import scan_data_stores

        log = logging.getLogger(__name__)
        dspm = DspmEngine()
        stores: list[Any] = []

        with session_scope(self._url) as sess:
            account = AccountRepository.get_or_create(sess, provider, account_identifier)
            s3_recs = [
                SimpleNamespace(
                    name=a.name or a.resource_id, is_public=a.is_public,
                    encrypted=bool(a.encryption_enabled), region=a.region,
                )
                for a in account.assets
                if a.is_active and a.asset_type == "aws.s3.bucket"
            ]

        try:
            s3_client = session.client("s3", region_name=region)
            stores += dspm.scan_s3_inventory(s3_recs, s3_client=s3_client)
        except Exception as e:  # noqa: BLE001
            log.warning("DSPM S3 scan partial/failed: %s", e)
        try:
            stores += scan_data_stores(session, region, read_secret_values=read_secret_values)
        except Exception as e:  # noqa: BLE001
            log.warning("DSPM multi-store scan partial/failed: %s", e)

        return self.persist_dspm(provider, account_identifier, stores)

    def persist_dspm(
        self, provider: str, account_identifier: str, stores: Sequence[Any],
        *, account_name: Optional[str] = None,
    ) -> DspmSyncStats:
        """Persist DSPM store classifications (dspm.engine.StoreSensitivity) so the
        data-sensitivity view survives restart instead of living only in the live
        cache. Idempotent on (account, store_id)."""
        with session_scope(self._url) as session:
            account = AccountRepository.get_or_create(session, provider, account_identifier, account_name)
            return DspmRepository.sync(session, account, list(stores))
