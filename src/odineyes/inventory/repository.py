"""Data-access for the inventory spine.

The heart is ``AssetRepository.upsert_assets``: idempotent on the natural key,
emits an ``asset_event`` on first sight / drift / disappearance, and soft-deletes
resources absent from the current scan. Re-running the same scan over unchanged
data produces no new rows and no new events.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from dateutil import parser as date_parser
from sqlalchemy import and_, delete, or_, select
from sqlalchemy.orm import Session

from odineyes.db.models import (
    Asset,
    AssetEvent,
    CloudAccount,
    ComplianceDrift,
    ComplianceSnapshot,
    DspmFinding,
    Finding,
    GraphEdge,
    Issue,
    IssueHop,
    RuntimeEvent,
    ScanError,
    ScanJob,
    ScanScope,
    SecurityScanRun,
    Vulnerability,
)
from odineyes.inventory.collection import CollectionScope
from odineyes.inventory.schema import NormalizedAsset


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _jsonable(value: Any) -> Any:
    """Make a value safe for a JSON column (boto3 hands back datetimes, sets)."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    return value


def _coerce_dt(value: Any) -> Optional[datetime]:
    if value is None or isinstance(value, datetime):
        return value
    try:
        return date_parser.parse(str(value))
    except (ValueError, OverflowError):
        return None


@dataclass
class UpsertStats:
    found: int = 0
    new: int = 0
    changed: int = 0
    deleted: int = 0
    reactivated: int = 0


@dataclass
class FindingSyncStats:
    total: int = 0        # raw detections currently true (open + suppressed)
    new: int = 0          # opened this run
    reopened: int = 0     # previously resolved, firing again
    resolved: int = 0     # no longer firing, closed this run
    suppressed: int = 0   # true detections withheld by an explainable tuning layer


@dataclass
class IssueSyncStats:
    total: int = 0        # attack paths currently present
    new: int = 0
    reopened: int = 0
    resolved: int = 0


@dataclass
class VulnSyncStats:
    total: int = 0
    new: int = 0
    reopened: int = 0
    resolved: int = 0
    instances_scanned: int = 0
    ssm_managed: int = 0


class AccountRepository:
    @staticmethod
    def get_or_create(
        session: Session,
        provider: str,
        account_identifier: str,
        name: Optional[str] = None,
        role_arn: Optional[str] = None,
    ) -> CloudAccount:
        stmt = select(CloudAccount).where(
            CloudAccount.provider == provider,
            CloudAccount.account_identifier == account_identifier,
        )
        account = session.execute(stmt).scalar_one_or_none()
        if account is None:
            account = CloudAccount(
                provider=provider, account_identifier=account_identifier, name=name, role_arn=role_arn,
                # Server-generated only — a client-supplied ExternalId would let
                # an attacker who controls the request pick their own value and
                # defeat the confused-deputy protection it exists to provide.
                external_id=f"cs-{secrets.token_urlsafe(24)}" if provider == "aws" else None,
            )
            session.add(account)
            session.flush()
        elif role_arn and account.role_arn != role_arn:
            account.role_arn = role_arn
        if provider == "aws" and not account.external_id:
            # Backfill accounts created before this field existed.
            account.external_id = f"cs-{secrets.token_urlsafe(24)}"
        return account


class ScanJobRepository:
    @staticmethod
    def create(session: Session, account: CloudAccount, scan_type: str = "config") -> ScanJob:
        job = ScanJob(account_id=account.id, scan_type=scan_type, status="queued")
        session.add(job)
        session.flush()
        return job

    @staticmethod
    def start(job: ScanJob) -> None:
        job.status = "running"
        job.started_at = _utcnow()

    @staticmethod
    def complete(job: ScanJob, stats: UpsertStats) -> None:
        job.status = "completed"
        job.completed_at = _utcnow()
        job.assets_found = stats.found
        job.assets_changed = stats.changed
        job.assets_deleted = stats.deleted

    @staticmethod
    def fail(session: Session, job: ScanJob, message: str) -> None:
        job.status = "failed"
        job.completed_at = _utcnow()
        ScanJobRepository.add_error(session, job, message)

    @staticmethod
    def add_error(
        session: Session,
        job: ScanJob,
        message: str,
        resource_id: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> None:
        session.add(ScanError(
            scan_job_id=job.id, resource_id=resource_id, resource_type=resource_type, message=message,
        ))
        job.error_count = (job.error_count or 0) + 1


class ScanScopeRepository:
    """Persist collector coverage independently of asset count.

    A completed zero-resource response is evidence; a denied collector is not.
    Keeping that distinction in the relational model prevents a scan failure
    from masquerading as an empty cloud account.
    """

    @staticmethod
    def sync(
        session: Session,
        scan_job: ScanJob,
        authoritative_scopes: Optional[set[CollectionScope]],
        collection_errors: list[Any],
        observed_counts: Optional[dict[tuple[str, str], int]] = None,
    ) -> None:
        counts = observed_counts or {}
        rows: dict[tuple[str, str], dict[str, Any]] = {}

        if authoritative_scopes is None:
            rows[("inventory", "*")] = {"status": "complete", "error_message": None}
        else:
            for source_type, region in authoritative_scopes:
                rows[(source_type, region or "*")] = {
                    "status": "complete", "error_message": None,
                }

        for error in collection_errors:
            key = (str(error.source_type), str(error.region or "*"))
            row = rows.get(key)
            if row is None:
                rows[key] = {"status": "failed", "error_message": error.scan_message()}
            else:
                row["status"] = "partial"
                row["error_message"] = error.scan_message()

        existing = {
            (row.source_type, row.region): row
            for row in session.execute(
                select(ScanScope).where(ScanScope.scan_job_id == scan_job.id)
            ).scalars()
        }
        for (source_type, region), values in rows.items():
            count = counts.get((source_type, region))
            if count is None and region == "*":
                count = sum(value for (kind, _), value in counts.items() if kind == source_type)
            fields = {
                "status": values["status"],
                "resource_count": int(count or 0),
                "error_message": values["error_message"],
                "completed_at": _utcnow(),
            }
            row = existing.get((source_type, region))
            if row is None:
                session.add(ScanScope(
                    scan_job_id=scan_job.id, source_type=source_type, region=region, **fields
                ))
            else:
                for name, value in fields.items():
                    setattr(row, name, value)


class AssetRepository:
    @staticmethod
    def _apply(asset: Asset, na: NormalizedAsset, normalized: dict[str, Any], scanned_at: datetime) -> None:
        asset.asset_type = na.asset_type
        asset.name = na.name
        asset.region = na.region
        asset.tags = _jsonable(na.tags)
        asset.is_public = na.is_public
        asset.encryption_enabled = na.encryption_enabled
        asset.network_exposure = na.network_exposure
        asset.raw = _jsonable(na.raw)
        asset.normalized = normalized
        asset.properties = _jsonable(na.properties)
        asset.relationships = _jsonable(na.relationships)
        asset.resource_created_at = _coerce_dt(na.resource_created_at)
        asset.last_scanned_at = scanned_at
        asset.updated_at = scanned_at

    @classmethod
    def upsert_assets(
        cls,
        session: Session,
        account: CloudAccount,
        scan_job: ScanJob,
        assets: list[NormalizedAsset],
        *,
        authoritative_scopes: Optional[set[CollectionScope]] = None,
    ) -> UpsertStats:
        """Upsert one inventory snapshot and retire safely-missing assets.

        ``authoritative_scopes=None`` preserves the legacy/full-snapshot
        contract used by explicit imports. Live collectors pass a set of
        successful ``(asset_type, region)`` scopes; ``region=None`` covers all
        regions. An empty set means collection produced no trustworthy scope,
        so no existing asset is retired.
        """
        scanned_at = scan_job.started_at or _utcnow()
        # Duplicate rows can occur when an API/page overlaps. Last observation
        # wins, while the natural key remains one asset and one event stream.
        unique_assets: dict[str, NormalizedAsset] = {}
        for na in assets:
            if na.cloud_provider != account.provider or na.account_identifier != account.account_identifier:
                raise ValueError(
                    "normalized asset tenant/provider does not match the target cloud account"
                )
            unique_assets[na.resource_id] = na

        # Load only rows that can be updated/reactivated. This avoids hydrating
        # an account's entire historical inventory on every large scan and keeps
        # SQLite below its bind-parameter limit.
        existing: dict[str, Asset] = {}
        resource_ids = list(unique_assets)
        for start in range(0, len(resource_ids), 400):
            chunk = resource_ids[start:start + 400]
            for row in session.execute(
                select(Asset).where(
                    Asset.account_id == account.id,
                    Asset.resource_id.in_(chunk),
                )
            ).scalars():
                existing[row.resource_id] = row
        stats = UpsertStats()
        seen: set[str] = set()

        for na in unique_assets.values():
            normalized = _jsonable(na.normalized_dict())
            asset = existing.get(na.resource_id)

            if asset is None:
                asset = Asset(
                    resource_id=na.resource_id,
                    cloud_provider=na.cloud_provider,
                    account_id=account.id,
                    first_seen_at=scanned_at,
                )
                cls._apply(asset, na, normalized, scanned_at)
                asset.last_seen_scan_id = scan_job.id
                session.add(asset)
                session.flush()  # assign asset.id before the event references it
                session.add(AssetEvent(
                    asset_id=asset.id, account_id=account.id, scan_job_id=scan_job.id,
                    event_type="created", previous_value=None, new_value=normalized, changed_at=scanned_at,
                ))
                stats.new += 1
                existing[na.resource_id] = asset
            else:
                if asset.normalized != normalized:
                    session.add(AssetEvent(
                        asset_id=asset.id, account_id=account.id, scan_job_id=scan_job.id,
                        event_type="config_change", previous_value=asset.normalized,
                        new_value=normalized, changed_at=scanned_at,
                    ))
                    stats.changed += 1
                if not asset.is_active:
                    asset.is_active = True
                    stats.reactivated += 1
                    session.add(AssetEvent(
                        asset_id=asset.id, account_id=account.id, scan_job_id=scan_job.id,
                        event_type="reactivated", previous_value=None, new_value=normalized, changed_at=scanned_at,
                    ))
                cls._apply(asset, na, normalized, scanned_at)
                asset.last_seen_scan_id = scan_job.id

            seen.add(na.resource_id)
            stats.found += 1

        # Soft-delete only where collection was authoritative. A failed API call
        # means "unknown", not "zero resources"; treating it as zero creates
        # false remediations and silently resolves real CSPM findings.
        candidates_stmt = select(Asset).where(
            Asset.account_id == account.id,
            Asset.is_active.is_(True),
        )
        if authoritative_scopes is not None:
            wildcard_types = {asset_type for asset_type, region in authoritative_scopes if region is None}
            regional: dict[str, set[str]] = {}
            for asset_type, region in authoritative_scopes:
                if region is not None and asset_type not in wildcard_types:
                    regional.setdefault(asset_type, set()).add(region)
            scope_predicates = []
            if wildcard_types:
                scope_predicates.append(Asset.asset_type.in_(wildcard_types))
            scope_predicates.extend(
                and_(Asset.asset_type == asset_type, Asset.region.in_(regions))
                for asset_type, regions in regional.items()
            )
            if not scope_predicates:
                candidates = []
            else:
                candidates = list(session.execute(
                    candidates_stmt.where(or_(*scope_predicates))
                ).scalars())
        else:
            candidates = list(session.execute(candidates_stmt).scalars())

        for asset in candidates:
            if asset.resource_id not in seen:
                asset.is_active = False
                asset.updated_at = scanned_at
                session.add(AssetEvent(
                    asset_id=asset.id, account_id=account.id, scan_job_id=scan_job.id,
                    event_type="deleted", previous_value=asset.normalized, new_value=None, changed_at=scanned_at,
                ))
                stats.deleted += 1

        return stats


class FindingRepository:
    """Persist rule-engine verdicts with an open/resolved lifecycle.

    ``sync`` is idempotent on (account, rule_id, resource_id): a finding still
    firing is refreshed in place, one that stopped firing is resolved (kept for
    audit), and a previously-resolved finding that fires again is reopened.
    """

    @staticmethod
    def sync(session: Session, account: CloudAccount, findings: list[Any],
             asset_seen: dict[str, Any] | None = None,
             resolve_prefix: str | None = None) -> FindingSyncStats:
        # A finding is only as fresh as the asset it describes. ``asset_seen`` maps
        # resource_id -> the asset's last_seen_at (when AWS last confirmed it). Using
        # it for the finding's last_seen means re-evaluating stale inventory (rules
        # only, no fresh collection) can't fake freshness — a deleted resource's
        # finding keeps its real age until a collection prunes the asset.
        #
        # ``resolve_prefix`` scopes the resolve pass to one rule-id family (e.g.
        # "AVD-" for Trivy's checks). An engine-scoped sync — Trivy ran, native
        # rules did not — must never resolve findings it did not evaluate: the
        # default None keeps the historic whole-table resolve.
        now = _utcnow()
        seen_at = asset_seen or {}
        existing = {
            (f.rule_id, f.resource_id): f
            for f in session.execute(
                select(Finding).where(Finding.account_id == account.id)
            ).scalars()
        }
        assets_by_resource = {
            asset.resource_id: asset.id
            for asset in session.execute(
                select(Asset).where(Asset.account_id == account.id)
            ).scalars()
        }
        stats = FindingSyncStats()
        seen: set[tuple[str, str]] = set()

        for ef in findings:
            key = (ef.rule_id, ef.resource_id)
            seen.add(key)
            stats.total += 1
            target_status = "suppressed" if ef.suppressed_by else "open"
            if target_status == "suppressed":
                stats.suppressed += 1
            ts = seen_at.get(ef.resource_id) or now   # asset's last AWS-confirmed time
            row = existing.get(key)
            if row is None:
                session.add(Finding(
                    account_id=account.id, rule_id=ef.rule_id, resource_id=ef.resource_id,
                    asset_id=assets_by_resource.get(ef.resource_id),
                    asset_type=ef.asset_type, title=ef.title, severity=ef.severity,
                    status=target_status, why=ef.why, remediation=ef.remediation,
                    suppressed_by=ef.suppressed_by or None,
                    suppressed_why=ef.suppressed_why or None,
                    compliance=_jsonable(ef.compliance), related=_jsonable(ef.related),
                    # Both stamps come from the same observation. Using the
                    # evaluation clock for first_seen and the asset's
                    # AWS-confirmed time for last_seen made every brand-new
                    # finding display "last seen" before "first seen".
                    first_seen_at=ts, last_seen_at=ts,
                ))
                if target_status == "open":
                    stats.new += 1
            else:
                if target_status == "open" and row.status != "open":
                    row.status = "open"
                    row.resolved_at = None
                    stats.reopened += 1
                elif target_status == "suppressed":
                    row.status = "suppressed"
                    row.resolved_at = None
                # refresh mutable fields (severity/title/why can evolve with rules)
                row.asset_type = ef.asset_type
                row.asset_id = assets_by_resource.get(ef.resource_id)
                row.title = ef.title
                row.severity = ef.severity
                row.why = ef.why
                row.remediation = ef.remediation
                row.suppressed_by = ef.suppressed_by or None
                row.suppressed_why = ef.suppressed_why or None
                row.compliance = _jsonable(ef.compliance)
                row.related = _jsonable(ef.related)
                row.last_seen_at = ts

        # Resolve findings that no longer fire. With ``resolve_prefix`` only the
        # scoped rule family participates: a Trivy-only sync cannot resolve a
        # native finding it never evaluated.
        for key, row in existing.items():
            if resolve_prefix is not None and not key[0].startswith(resolve_prefix):
                continue
            if key not in seen and row.status in {"open", "suppressed"}:
                row.status = "resolved"
                row.resolved_at = now
                stats.resolved += 1

        return stats


# severity → asset-risk contribution when only a single-rule finding (which has
# no contextual path score of its own) touches the asset.
_FINDING_RISK = {"critical": 90.0, "high": 70.0, "medium": 40.0, "low": 15.0, "info": 5.0}

# Collateral assets — reachable on an attack path but not its entry point (e.g.
# every bucket a wildcard-trust admin role can read) — inherit only a decayed
# share of the path risk. Keeps blast radius visible without flattening every
# reachable asset to the entry point's score and drowning the ranking signal.
_BLAST_DECAY = 0.5


class IssueRepository:
    """Persist attack-path issues with the same open/resolved lifecycle as
    findings, keyed on (account, issue_type, path_hash)."""

    @staticmethod
    def sync(session: Session, account: CloudAccount, issues: list[Any],
             asset_seen: dict[str, Any] | None = None) -> IssueSyncStats:
        # Issue freshness inherits the entry asset's last AWS-confirmed time (same
        # reasoning as FindingRepository.sync): a rules-only re-evaluate over stale
        # inventory can't make a deleted entry point's attack path look fresh.
        now = _utcnow()
        seen_at = asset_seen or {}
        existing = {
            (i.issue_type, i.path_hash): i
            for i in session.execute(
                select(Issue).where(Issue.account_id == account.id)
            ).scalars()
        }
        assets_by_resource = {
            asset.resource_id: asset.id
            for asset in session.execute(
                select(Asset).where(Asset.account_id == account.id)
            ).scalars()
        }
        stats = IssueSyncStats()
        seen: set[tuple[str, str]] = set()

        for ei in issues:
            key = (ei.issue_type, ei.path_hash)
            seen.add(key)
            stats.total += 1
            ts = seen_at.get(ei.resource_id) or now   # entry asset's last AWS-confirmed time
            row = existing.get(key)
            if row is None:
                row = Issue(
                    account_id=account.id, issue_type=ei.issue_type, path_hash=ei.path_hash,
                    title=ei.title, severity=ei.severity, status="open",
                    risk_score=ei.risk_score, confidence=getattr(ei, "confidence", 1.0),
                    evidence_status=getattr(ei, "evidence_status", "confirmed"),
                    entry_asset_id=assets_by_resource.get(ei.resource_id),
                    resource_id=ei.resource_id,
                    why=ei.why, remediation=ei.remediation,
                    path=_jsonable(ei.path), compliance=_jsonable(ei.compliance),
                    related=_jsonable(ei.related), evidence=_jsonable(getattr(ei, "evidence", [])),
                    first_seen_at=now, last_seen_at=ts,
                )
                session.add(row)
                session.flush()
                IssueRepository._sync_hops(session, row, ei.path, assets_by_resource)
                stats.new += 1
            else:
                if row.status == "resolved":
                    row.status = "open"
                    row.resolved_at = None
                    stats.reopened += 1
                # refresh mutable fields (risk decays/grows as context changes)
                row.title = ei.title
                row.severity = ei.severity
                row.risk_score = ei.risk_score
                row.confidence = getattr(ei, "confidence", 1.0)
                row.evidence_status = getattr(ei, "evidence_status", "confirmed")
                row.entry_asset_id = assets_by_resource.get(ei.resource_id)
                row.resource_id = ei.resource_id
                row.why = ei.why
                row.remediation = ei.remediation
                row.path = _jsonable(ei.path)
                row.compliance = _jsonable(ei.compliance)
                row.related = _jsonable(ei.related)
                row.evidence = _jsonable(getattr(ei, "evidence", []))
                row.last_seen_at = ts
                IssueRepository._sync_hops(session, row, ei.path, assets_by_resource)

        for key, row in existing.items():
            if key not in seen and row.status == "open":
                row.status = "resolved"
                row.resolved_at = now
                stats.resolved += 1

        return stats

    @staticmethod
    def _sync_hops(
        session: Session,
        issue: Issue,
        path: list[dict[str, Any]],
        assets_by_resource: dict[str, int],
    ) -> None:
        """Keep the normalized ordered path in sync with its JSON API payload."""
        desired = [
            (
                order,
                str(hop.get("id")),
                str(hop.get("kind") or "") or None,
                str(hop.get("name") or hop.get("label") or "") or None,
            )
            for order, hop in enumerate(path or [])
            if isinstance(hop, dict) and hop.get("id")
        ]
        current = [
            (hop.hop_order, hop.node_id, hop.node_kind, hop.label)
            for hop in issue.hops
        ]
        if current == desired:
            return
        session.execute(delete(IssueHop).where(IssueHop.issue_id == issue.id))
        for order, node_id, node_kind, label in desired:
            session.add(IssueHop(
                issue_id=issue.id,
                asset_id=assets_by_resource.get(node_id),
                hop_order=order,
                node_id=node_id,
                node_kind=node_kind,
                label=label,
                evidence={},
            ))

    @staticmethod
    def update_asset_risk(session: Session, account: CloudAccount) -> None:
        """Recompute every asset's risk_score (max across contributions):

          - the entry point of each open issue gets the full path risk;
          - assets merely *reachable* on the path (other hops + related) inherit
            a decayed share (``_BLAST_DECAY``) so collateral never reads the same
            as the actual misconfiguration;
          - an asset's own open findings always apply at full severity weight.
        """
        risk: dict[str, float] = {}

        def bump(rid: Optional[str], score: float) -> None:
            if rid and score > risk.get(rid, 0.0):
                risk[rid] = score

        open_issues = session.execute(
            select(Issue).where(Issue.account_id == account.id, Issue.status == "open")
        ).scalars()
        for issue in open_issues:
            bump(issue.resource_id, issue.risk_score)            # entry point: full
            collateral = {h.get("id") for h in (issue.path or []) if isinstance(h, dict)}
            collateral.update(issue.related or [])
            collateral.discard(issue.resource_id)
            decayed = round(issue.risk_score * _BLAST_DECAY, 1)
            for rid in collateral:
                bump(rid, decayed)                               # reachable: decayed

        open_findings = session.execute(
            select(Finding).where(Finding.account_id == account.id, Finding.status == "open")
        ).scalars()
        for finding in open_findings:
            bump(finding.resource_id, _FINDING_RISK.get(finding.severity, 0.0))

        assets = session.execute(
            select(Asset).where(Asset.account_id == account.id)
        ).scalars()
        for asset in assets:
            asset.risk_score = risk.get(asset.resource_id, 0.0)


class VulnerabilityRepository:
    """Persist CVE matches with the findings-style open/resolved lifecycle,
    keyed on (account, resource_id, cve_id, package)."""

    @staticmethod
    def sync(session: Session, account: CloudAccount, vulns: list[Any],
             scanned_resources: Optional[set[str]] = None) -> VulnSyncStats:
        """Reconcile vulns for an account (open/reopen/resolve). ``scanned_resources``
        scopes the resolve pass to only those resource_ids — required now that
        host (EC2) and container (image) CVEs share this table: a container-only
        scan must not resolve host CVEs it never looked at. None = resolve any
        open row not seen (whole-account scan)."""
        now = _utcnow()
        existing = {
            (v.resource_id, v.cve_id, v.package): v
            for v in session.execute(
                select(Vulnerability).where(Vulnerability.account_id == account.id)
            ).scalars()
        }
        assets_by_resource = {
            asset.resource_id: asset.id
            for asset in session.execute(
                select(Asset).where(Asset.account_id == account.id)
            ).scalars()
        }
        stats = VulnSyncStats()
        seen: set[tuple[str, str, str]] = set()

        for ev in vulns:
            key = (ev.resource_id, ev.cve_id, ev.package)
            if key in seen:
                continue
            seen.add(key)
            stats.total += 1
            row = existing.get(key)
            if row is None:
                session.add(Vulnerability(
                    account_id=account.id, resource_id=ev.resource_id, cve_id=ev.cve_id,
                    asset_id=assets_by_resource.get(ev.resource_id),
                    package=ev.package, installed_version=getattr(ev, "installed_version", None),
                    severity=getattr(ev, "severity", "unknown") or "unknown",
                    cvss=getattr(ev, "cvss", None), summary=getattr(ev, "summary", None),
                    fixed_version=getattr(ev, "fixed_version", None),
                    scanner_source=getattr(ev, "scanner_source", "ssm-osv") or "ssm-osv",
                    package_type=getattr(ev, "package_type", None),
                    target=getattr(ev, "target", None),
                    package_path=getattr(ev, "package_path", None),
                    epss=getattr(ev, "epss", None),
                    epss_percentile=getattr(ev, "epss_percentile", None),
                    kev=bool(getattr(ev, "kev", False)),
                    status="open", first_seen_at=now, last_seen_at=now,
                ))
                stats.new += 1
            else:
                if row.status == "resolved":
                    row.status = "open"
                    row.resolved_at = None
                    stats.reopened += 1
                row.installed_version = getattr(ev, "installed_version", None)
                row.asset_id = assets_by_resource.get(ev.resource_id)
                row.severity = getattr(ev, "severity", "unknown") or "unknown"
                row.cvss = getattr(ev, "cvss", None)
                row.summary = getattr(ev, "summary", None)
                row.fixed_version = getattr(ev, "fixed_version", None)
                row.scanner_source = getattr(ev, "scanner_source", "ssm-osv") or "ssm-osv"
                row.package_type = getattr(ev, "package_type", None)
                row.target = getattr(ev, "target", None)
                row.package_path = getattr(ev, "package_path", None)
                row.epss = getattr(ev, "epss", None)
                row.epss_percentile = getattr(ev, "epss_percentile", None)
                row.kev = bool(getattr(ev, "kev", False))
                row.last_seen_at = now

        for key, row in existing.items():
            if key not in seen and row.status == "open":
                if scanned_resources is not None and row.resource_id not in scanned_resources:
                    continue  # out of this scan's scope (e.g. a host CVE during an image scan)
                row.status = "resolved"
                row.resolved_at = now
                stats.resolved += 1

        return stats

    @staticmethod
    def apply_exploit_maturity(session: Session, account: CloudAccount) -> int:
        """Boost open attack-path issue risk by the exploit_maturity of CVEs on
        the path's entry asset — a path through a host carrying a KEV / high-EPSS
        vuln is a more viable kill chain. factor = 1 + 0.4·maturity (KEV → ×1.4).
        Returns the number of issues boosted."""
        vulns = session.execute(
            select(Vulnerability).where(
                Vulnerability.account_id == account.id, Vulnerability.status == "open")
        ).scalars()
        maturity: dict[str, float] = {}
        for v in vulns:
            m = 1.0 if v.kev else float(v.epss or 0.0)
            if m > maturity.get(v.resource_id, 0.0):
                maturity[v.resource_id] = m

        if not maturity:
            return 0
        boosted = 0
        issues = session.execute(
            select(Issue).where(Issue.account_id == account.id, Issue.status == "open")
        ).scalars()
        for iss in issues:
            # Consider every hop on the path, not only the entry asset — a hot CVE
            # anywhere on the kill chain makes it more viable.
            hop_ids = [h.get("id") for h in (iss.path or []) if h.get("id")] or [iss.resource_id]
            m = max((maturity.get(hid, 0.0) for hid in hop_ids), default=0.0)
            if m <= 0:
                continue
            iss.risk_score = round(min(100.0, iss.risk_score * (1 + 0.4 * m)), 1)
            boosted += 1
        return boosted


class SecurityScanRepository:
    """Persist workload scan coverage independently from discovered CVEs."""

    @staticmethod
    def record(
        session: Session,
        account: CloudAccount,
        *,
        resource_id: str,
        scanner: str,
        scan_kind: str,
        status: str,
        package_count: int = 0,
        findings_count: int = 0,
        status_reason: Optional[str] = None,
        evidence: Optional[dict[str, Any]] = None,
    ) -> SecurityScanRun:
        asset_id = session.execute(
            select(Asset.id).where(
                Asset.account_id == account.id,
                Asset.resource_id == resource_id,
            )
        ).scalar_one_or_none()
        row = SecurityScanRun(
            account_id=account.id,
            asset_id=asset_id,
            resource_id=resource_id,
            scanner=scanner,
            scan_kind=scan_kind,
            status=status,
            package_count=max(0, int(package_count or 0)),
            findings_count=max(0, int(findings_count or 0)),
            status_reason=status_reason or None,
            evidence=_jsonable(evidence or {}),
            scanned_at=_utcnow(),
        )
        session.add(row)
        return row


def _burst_window() -> timedelta:
    # Identical signals inside this window collapse into one row. Tunable so a
    # noisy fleet can widen it. ponytail: env read per-call is cheap; cache if
    # this ever shows on a profile.
    return timedelta(seconds=int(os.environ.get("ODINEYES_RUNTIME_BURST_WINDOW", "300")))


class RuntimeEventRepository:
    """Runtime/threat signals from the eBPF sensor. Mostly append-only, but with
    burst control: a repeated identical signal inside the dedup window collapses
    into the existing row (count++) instead of inserting a flood of duplicates."""

    @staticmethod
    def record(
        session: Session,
        *,
        event_type: str,
        severity: str = "info",
        account_id: Optional[int] = None,
        resource_id: Optional[str] = None,
        workload: Optional[str] = None,
        process: Optional[str] = None,
        pid: Optional[int] = None,
        summary: Optional[str] = None,
        raw: Optional[dict[str, Any]] = None,
    ) -> RuntimeEvent:
        now = _utcnow()
        # Burst control: collapse an identical signal seen again inside the window
        # into the existing row (count++, observed_at refreshed). Identity is the
        # same host + event + process + severity — a recon/shell loop becomes one
        # "×N" row instead of burying the timeline. Detection findings (carrying a
        # rule_id) keep their own row per rule via the process/event identity.
        acct_pred = (
            RuntimeEvent.account_id.is_(None) if account_id is None
            else RuntimeEvent.account_id == account_id
        )
        recent = session.execute(
            select(RuntimeEvent)
            .where(
                acct_pred,
                RuntimeEvent.event_type == event_type,
                RuntimeEvent.severity == severity,
                RuntimeEvent.resource_id == resource_id,
                RuntimeEvent.process == process,
                RuntimeEvent.observed_at >= now - _burst_window(),
            )
            .order_by(RuntimeEvent.observed_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if recent is not None:
            recent.count = (recent.count or 1) + 1
            recent.observed_at = now
            recent.raw = _jsonable(raw or {})  # keep the freshest payload
            return recent

        row = RuntimeEvent(
            account_id=account_id, event_type=event_type, severity=severity,
            resource_id=resource_id, workload=workload, process=process, pid=pid,
            summary=summary, raw=_jsonable(raw or {}),
        )
        session.add(row)
        return row


class ComplianceRepository:
    """Continuous + dynamic compliance: persist a per-framework snapshot each
    cycle and record control state transitions (drift) vs the prior snapshot."""

    # Which (old -> new) control transitions count as drift, and their direction.
    @staticmethod
    def _direction(old: Optional[str], new: str) -> Optional[str]:
        if old == new:
            return None
        if new == "fail" and old in ("pass", "not_assessed"):
            return "regression"
        if new == "pass" and old == "fail":
            return "remediation"
        return None  # pass<->not_assessed etc. is noise, not posture drift

    @classmethod
    def snapshot(
        cls,
        session: Session,
        *,
        compliance: dict[str, Any],
        account: Optional[str] = None,
        region: Optional[str] = None,
        origin: Optional[str] = None,
    ) -> dict[str, int]:
        """Persist one snapshot per framework in ``compliance`` (the dict from
        ComplianceMapper.score) and emit drift rows for control transitions vs
        the latest prior snapshot of the same framework. ``origin`` records the
        scoring engine ('steampipe' | 'python') so versions aren't silently
        mixed. Returns counts."""
        snaps = 0
        drifts = 0
        for fw_id, data in compliance.items():
            controls = {c["id"]: c["state"] for c in data.get("controls", [])}
            titles = {c["id"]: c.get("title", c["id"]) for c in data.get("controls", [])}

            prev = session.execute(
                select(ComplianceSnapshot)
                .where(ComplianceSnapshot.framework == fw_id)
                .order_by(ComplianceSnapshot.captured_at.desc())
                .limit(1)
            ).scalar_one_or_none()

            session.add(ComplianceSnapshot(
                framework=fw_id,
                version=data.get("version"),
                account=account,
                region=region,
                score=float(data.get("score", 0)),
                passing=int(data.get("passing", 0)),
                total=int(data.get("total", 0)),
                not_assessed=int(data.get("not_assessed", 0)),
                origin=origin,
                controls=controls,
            ))
            snaps += 1

            if prev:
                prev_controls = prev.controls or {}
                for cid, state in controls.items():
                    direction = cls._direction(prev_controls.get(cid), state)
                    if direction is None:
                        continue
                    session.add(ComplianceDrift(
                        framework=fw_id,
                        control_id=cid,
                        control_title=titles.get(cid),
                        from_state=prev_controls.get(cid),
                        to_state=state,
                        direction=direction,
                        account=account,
                        region=region,
                    ))
                    drifts += 1
        return {"snapshots": snaps, "drifts": drifts}


@dataclass
class EdgeSyncStats:
    total: int = 0
    new: int = 0
    deactivated: int = 0


class GraphEdgeRepository:
    """Persist the derived security-graph edges with an active/soft-delete
    lifecycle, keyed on (account, src, dst, edge_type). An edge still present is
    refreshed (last_seen + reactivated if it had vanished); one absent from the
    current graph is marked inactive but kept for history."""

    @staticmethod
    def sync(session: Session, account: CloudAccount, edges: list[Any]) -> EdgeSyncStats:
        """``edges`` are AssetGraph.Edge objects (src/dst/edge_type/properties)."""
        now = _utcnow()
        existing = {
            (e.src_id, e.dst_id, e.edge_type): e
            for e in session.execute(
                select(GraphEdge).where(GraphEdge.account_id == account.id)
            ).scalars()
        }
        stats = EdgeSyncStats()
        seen: set[tuple[str, str, str]] = set()

        for e in edges:
            key = (e.src, e.dst, e.edge_type)
            seen.add(key)
            stats.total += 1
            row = existing.get(key)
            if row is None:
                session.add(GraphEdge(
                    account_id=account.id, src_id=e.src, dst_id=e.dst,
                    edge_type=e.edge_type, properties=_jsonable(e.properties or {}),
                    is_active=True, first_seen_at=now, last_seen_at=now,
                ))
                stats.new += 1
            else:
                row.is_active = True
                row.properties = _jsonable(e.properties or {})
                row.last_seen_at = now

        for key, row in existing.items():
            if key not in seen and row.is_active:
                row.is_active = False
                stats.deactivated += 1
        return stats


@dataclass
class DspmSyncStats:
    total: int = 0
    new: int = 0


class DspmRepository:
    """Persist per-store data-sensitivity classifications, keyed on
    (account, store_id). One row per store, upserted each scan — first_seen set
    once, the rest refreshed."""

    @staticmethod
    def sync(session: Session, account: CloudAccount, stores: list[Any]) -> DspmSyncStats:
        """``stores`` are dspm.engine.StoreSensitivity objects."""
        now = _utcnow()
        assets = list(session.execute(
            select(Asset).where(Asset.account_id == account.id)
        ).scalars())
        by_resource = {asset.resource_id: asset.id for asset in assets}

        def store_key(value: str) -> str:
            return value.split("://", 1)[-1].split(":")[-1].split("/")[-1].lower()

        by_store_key: dict[str, list[int]] = {}
        for asset in assets:
            by_store_key.setdefault(store_key(asset.resource_id), []).append(asset.id)

        def asset_id_for(store_id: str) -> Optional[int]:
            direct = by_resource.get(store_id)
            if direct is not None:
                return direct
            candidates = by_store_key.get(store_key(store_id), [])
            return candidates[0] if len(candidates) == 1 else None

        existing = {
            d.store_id: d
            for d in session.execute(
                select(DspmFinding).where(DspmFinding.account_id == account.id)
            ).scalars()
        }
        stats = DspmSyncStats()
        for s in stores:
            stats.total += 1
            row = existing.get(s.store_id)
            fields = dict(
                asset_id=asset_id_for(s.store_id),
                store_name=s.store_name, store_type=s.store_type, label=s.label,
                data_types=list(s.pii_types), taxonomies=list(s.taxonomies),
                frameworks=list(s.frameworks), posture_findings=list(s.posture_findings),
                record_estimate=int(s.record_estimate), objects_sampled=int(s.objects_sampled),
                sensitivity_score=float(s.sensitivity_score),
                exposure_score=float(s.exposure_score), risk_score=float(s.risk_score),
                public=bool(s.public),
            )
            if row is None:
                session.add(DspmFinding(
                    account_id=account.id, store_id=s.store_id,
                    first_seen_at=now, last_seen_at=now, **fields,
                ))
                stats.new += 1
            else:
                for k, v in fields.items():
                    setattr(row, k, v)
                row.last_seen_at = now
        return stats
