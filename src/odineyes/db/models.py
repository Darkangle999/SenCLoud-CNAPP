"""Phase 1 relational schema.

Five tables: cloud_accounts, assets (raw + normalized), scan_jobs, scan_errors,
asset_events (delta/drift). Asset natural key is (resource_id, cloud_provider) —
resource_id alone is not globally unique across providers/subscriptions.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from odineyes.db.base import Base, JSONType


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CloudAccount(Base):
    __tablename__ = "cloud_accounts"
    __table_args__ = (
        UniqueConstraint("provider", "account_identifier", name="uq_account_provider_identifier"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)  # aws | azure | gcp
    # AWS account id / Azure subscription id / GCP project id.
    account_identifier: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String(256))
    # AWS: the read-only role ARN we assume per-scan (only credential stored).
    role_arn: Mapped[Optional[str]] = mapped_column(String(512))
    disk_scan_role_arn: Mapped[Optional[str]] = mapped_column(String(512))
    realtime_role_arn: Mapped[Optional[str]] = mapped_column(String(512))
    # sts:ExternalId required in the role's trust condition — closes the
    # confused-deputy hole (anyone who learns the role ARN can't assume it
    # without also knowing this). Generated server-side, never client-supplied.
    external_id: Mapped[Optional[str]] = mapped_column(String(64))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # A draft is created before the customer opens CloudFormation. It becomes
    # connected only after the stack's custom resource submits the role ARN.
    onboarding_status: Mapped[str] = mapped_column(String(32), default="connected", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    
    # Credentials for machine-to-machine autoconnect (Aqua pattern)
    api_key: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    api_secret: Mapped[Optional[str]] = mapped_column(String(128))
    # CloudFormation receives a short-lived bearer value; only its SHA-256 is
    # persisted. A successful callback consumes it, while an identical retry
    # remains idempotent for CloudFormation delivery semantics.
    onboarding_token_hash: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    onboarding_token_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    onboarding_token_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    # Last permission-probe outcome, so the accounts table can show standing
    # health instead of only whatever the operator last clicked.
    last_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_verify_status: Mapped[Optional[str]] = mapped_column(String(32))
    # JSON array of regions the operator removed from the discovery sweep
    # (e.g. regions an SCP physically blocks). Default [] scans every enabled
    # region — dormant ones included, which is the tripwire advantage.
    excluded_regions: Mapped[Optional[str]] = mapped_column(Text, default="[]")

    # Every per-account child table cascades on account delete, so removing an
    # account removes ALL its data in one operation. Keep this list complete —
    # a new account-scoped table MUST be added here (or it orphans on delete).
    assets: Mapped[list["Asset"]] = relationship(back_populates="account", cascade="all, delete-orphan")
    scan_jobs: Mapped[list["ScanJob"]] = relationship(back_populates="account", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="account", cascade="all, delete-orphan")
    issues: Mapped[list["Issue"]] = relationship(back_populates="account", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="account", cascade="all, delete-orphan")
    security_scans: Mapped[list["SecurityScanRun"]] = relationship(back_populates="account", cascade="all, delete-orphan")
    runtime_events: Mapped[list["RuntimeEvent"]] = relationship(back_populates="account", cascade="all, delete-orphan")
    graph_edges: Mapped[list["GraphEdge"]] = relationship(back_populates="account", cascade="all, delete-orphan")
    dspm_findings: Mapped[list["DspmFinding"]] = relationship(back_populates="account", cascade="all, delete-orphan")
    mutation_events: Mapped[list["CloudMutationEvent"]] = relationship(back_populates="account", cascade="all, delete-orphan")
    realtime_regions: Mapped[list["RealtimeRegion"]] = relationship(back_populates="account", cascade="all, delete-orphan")


class RealtimeRegion(Base):
    """One customer delivery role registered for one AWS Region."""

    __tablename__ = "realtime_regions"
    __table_args__ = (UniqueConstraint("account_id", "region", name="uq_realtime_region_account_region"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    delivery_role_arn: Mapped[str] = mapped_column(String(512), nullable=False)
    queue_arn: Mapped[str] = mapped_column(String(512), nullable=False)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    account: Mapped["CloudAccount"] = relationship(back_populates="realtime_regions")


class OnboardingSession(Base):
    """A launch link issued before anyone knows which AWS account will run it.

    The per-account onboarding flow keys everything on a 12-digit account id the
    operator types up front. This one deliberately does not: the customer signs
    into whichever account they want connected and the stack's callback reports
    which account it actually ran in, so the account is *discovered*. Until that
    happens there is no CloudAccount row to hang state on, and this table is
    that missing home.

    ``external_id`` is generated here and stays authoritative on our side. The
    template takes it as a parameter, so a customer who edits it ends up with a
    role we cannot assume — a visible failed connection rather than a silent
    trust mismatch.
    """

    __tablename__ = "onboarding_sessions"

    PENDING = "pending"
    REDEEMED = "redeemed"
    SUPERSEDED = "superseded"
    EXPIRED = "expired"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(16), default="aws", nullable=False)
    external_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_mode: Mapped[str] = mapped_column(String(32), default="managed", nullable=False)
    label: Mapped[Optional[str]] = mapped_column(String(256), index=True)
    status: Mapped[str] = mapped_column(String(16), default=PENDING, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    redeemed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    # Populated on redemption, from the role ARN CloudFormation produced.
    account_identifier: Mapped[Optional[str]] = mapped_column(String(128))
    role_arn: Mapped[Optional[str]] = mapped_column(String(512))
    # SET NULL, not CASCADE: purging an account must not erase the audit trail
    # of which link enrolled it.
    account_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("cloud_accounts.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    def effective_status(self, now: Optional[datetime] = None) -> str:
        """Pending links go stale on the clock, not on a write. Report that."""
        if self.status != self.PENDING:
            return self.status
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return self.EXPIRED if (now or _utcnow()) > expires_at else self.PENDING


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("account_id", "cloud_provider", "resource_id", name="uq_asset_natural_key"),
        Index("ix_assets_account_type", "account_id", "asset_type"),
        Index("ix_assets_account_active_scanned", "account_id", "is_active", "last_scanned_at"),
        Index("ix_assets_account_active_region", "account_id", "is_active", "region"),
        Index("ix_assets_account_active_public", "account_id", "is_active", "is_public"),
        Index("ix_assets_region", "region"),
        Index("ix_assets_is_public", "is_public"),
        Index("ix_assets_is_active", "is_active"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Natural key.
    resource_id: Mapped[str] = mapped_column(String(1024), nullable=False)
    cloud_provider: Mapped[str] = mapped_column(String(16), nullable=False)

    account_id: Mapped[int] = mapped_column(ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False)

    # Normalized standard fields — what the Phase 2 rules engine queries against.
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. aws.s3.bucket
    name: Mapped[Optional[str]] = mapped_column(String(512))
    region: Mapped[str] = mapped_column(String(64), default="global", nullable=False)
    tags: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    is_public: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    encryption_enabled: Mapped[Optional[bool]] = mapped_column(Boolean)
    network_exposure: Mapped[str] = mapped_column(String(16), default="private", nullable=False)  # private|vpc|public

    # Two-column raw + normalized pattern. `raw` is the untouched API response;
    # `normalized` is re-derivable from raw and is the canonical delta source.
    raw: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    normalized: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    properties: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    relationships: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list, nullable=False)

    # Contextual risk (0-100) — max over open issues/findings touching this
    # asset; recomputed by IssueRepository.update_asset_risk after evaluation.
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    resource_created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    # The successful collection job that last observed this asset.  This is
    # provenance, not an update timestamp: it lets the UI distinguish a fresh
    # AWS observation from a later rule-only re-evaluation.
    last_seen_scan_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    account: Mapped["CloudAccount"] = relationship(back_populates="assets")
    events: Mapped[list["AssetEvent"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="asset")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="asset")
    security_scans: Mapped[list["SecurityScanRun"]] = relationship(back_populates="asset")
    data_classifications: Mapped[list["DspmFinding"]] = relationship(back_populates="asset")
    issue_entry_points: Mapped[list["Issue"]] = relationship(back_populates="entry_asset")
    issue_hops: Mapped[list["IssueHop"]] = relationship(back_populates="asset")


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("ix_scan_jobs_account_status", "account_id", "status"),
        Index("ix_scan_jobs_account_created", "account_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(32), default="config", nullable=False)  # config | workload
    status: Mapped[str] = mapped_column(String(16), default="queued", nullable=False)  # queued|running|completed|failed
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    assets_found: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    assets_changed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    assets_deleted: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    account: Mapped["CloudAccount"] = relationship(back_populates="scan_jobs")
    errors: Mapped[list["ScanError"]] = relationship(back_populates="scan_job", cascade="all, delete-orphan")
    scopes: Mapped[list["ScanScope"]] = relationship(back_populates="scan_job", cascade="all, delete-orphan")

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class ScanError(Base):
    __tablename__ = "scan_errors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(1024))
    resource_type: Mapped[Optional[str]] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    scan_job: Mapped["ScanJob"] = relationship(back_populates="errors")


class ScanScope(Base):
    """Per-service/per-region collection evidence for a scan.

    A zero-resource result is meaningful only when the underlying collector
    completed.  This table preserves that distinction for coverage, safe
    soft-deletion, and operator-facing scan diagnostics.  ``*`` represents a
    global/all-regions scope so the natural key stays portable across SQLite
    and PostgreSQL (where NULL uniqueness semantics differ).
    """

    __tablename__ = "scan_scopes"
    __table_args__ = (
        UniqueConstraint("scan_job_id", "source_type", "region", name="uq_scan_scope"),
        CheckConstraint("status IN ('complete', 'partial', 'failed')", name="ck_scan_scope_status"),
        Index("ix_scan_scopes_job_status", "scan_job_id", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    region: Mapped[str] = mapped_column(String(64), default="*", nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    resource_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    scan_job: Mapped["ScanJob"] = relationship(back_populates="scopes")


class Finding(Base):
    """A rule-engine verdict against a normalized asset.

    Natural key (account_id, rule_id, resource_id) makes re-evaluation
    idempotent: a still-true finding is updated in place (status stays open,
    last_seen bumped), one that no longer fires is resolved (not deleted), so
    the table doubles as an audit trail of when issues opened and closed.
    """

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("account_id", "rule_id", "resource_id", name="uq_finding_natural_key"),
        Index("ix_findings_account_status", "account_id", "status"),
        Index("ix_findings_account_status_severity", "account_id", "status", "severity"),
        Index("ix_findings_asset_status", "asset_id", "status"),
        Index("ix_findings_severity", "severity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False)
    # Optional during the additive migration; all newly evaluated findings are
    # linked to the canonical asset row whenever it exists.
    asset_id: Mapped[Optional[int]] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))

    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(1024), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)  # critical|high|medium|low
    status: Mapped[str] = mapped_column(String(16), default="open", nullable=False)  # open|suppressed|resolved
    suppressed_by: Mapped[Optional[str]] = mapped_column(String(32))
    suppressed_why: Mapped[Optional[str]] = mapped_column(Text)
    why: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    compliance: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    related: Mapped[list[Any]] = mapped_column(JSONType, default=list, nullable=False)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    account: Mapped["CloudAccount"] = relationship(back_populates="findings")
    asset: Mapped[Optional["Asset"]] = relationship(back_populates="findings")


class Issue(Base):
    """A correlated attack path — distinct from a single-rule Finding.

    An issue is a chain of individually-minor conditions that combine into a
    walkable path (Wiz-style toxic combination). Natural key
    (account_id, issue_type, path_hash) where path_hash fingerprints the ordered
    hop resource_ids, so re-analysis is idempotent: a path still present is
    refreshed, one that closed is resolved (kept for audit), a regression reopens.
    """

    __tablename__ = "issues"
    __table_args__ = (
        UniqueConstraint("account_id", "issue_type", "path_hash", name="uq_issue_natural_key"),
        Index("ix_issues_account_status", "account_id", "status"),
        Index("ix_issues_account_status_risk", "account_id", "status", "risk_score"),
        Index("ix_issues_entry_asset", "entry_asset_id"),
        Index("ix_issues_risk", "risk_score"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False)
    entry_asset_id: Mapped[Optional[int]] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))

    issue_type: Mapped[str] = mapped_column(String(64), nullable=False)
    path_hash: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)  # critical|high|medium|low
    status: Mapped[str] = mapped_column(String(16), default="open", nullable=False)  # open|resolved
    # base × exposure × blast_radius × freshness, 0-100.
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    # Route confidence 0–1: how completely the path is evidenced (freshness ×
    # completeness). Distinct from risk — lets the operator sort certainty from
    # severity. See inventory.issues._confidence.
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    # confirmed | stale | partial. Kept separately from risk so operators can
    # distinguish impact from evidence quality.
    evidence_status: Mapped[str] = mapped_column(
        String(16), default="confirmed", nullable=False
    )
    # The entry-point asset the attacker compromises first.
    resource_id: Mapped[str] = mapped_column(String(1024), nullable=False)
    why: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    # Ordered hops: [{kind, id, name}, ...] — internet/external pseudo-nodes included.
    path: Mapped[list[Any]] = mapped_column(JSONType, default=list, nullable=False)
    compliance: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    related: Mapped[list[Any]] = mapped_column(JSONType, default=list, nullable=False)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list, nullable=False)

    # Step-4 correlation: a runtime (eBPF) event landed on an asset that is a hop
    # in this path — the predicted path is being actively walked RIGHT NOW.
    actively_exploited: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # actively_exploited is a *live* state and decays on a TTL. That is correct
    # for "is this happening right now" and wrong for "did this ever happen":
    # an attacker who lands at 23:00 Friday and goes quiet would be invisible by
    # the time an analyst reads the queue on Monday. This flag never decays — it
    # is cleared only when the issue itself is resolved.
    historically_exploited: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    exploit_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    first_exploit_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_exploit_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    account: Mapped["CloudAccount"] = relationship(back_populates="issues")
    entry_asset: Mapped[Optional["Asset"]] = relationship(back_populates="issue_entry_points")
    hops: Mapped[list["IssueHop"]] = relationship(
        back_populates="issue", cascade="all, delete-orphan", order_by="IssueHop.hop_order"
    )


class IssueHop(Base):
    """An ordered, queryable node in a correlated attack path.

    ``node_id`` retains pseudo-nodes such as ``internet`` while ``asset_id``
    provides a real foreign key for cloud resources.  Keeping both avoids
    inventing fake asset rows solely to satisfy graph traversal.
    """

    __tablename__ = "issue_hops"
    __table_args__ = (
        UniqueConstraint("issue_id", "hop_order", name="uq_issue_hop_order"),
        Index("ix_issue_hops_asset", "asset_id"),
        Index("ix_issue_hops_issue", "issue_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    issue_id: Mapped[int] = mapped_column(ForeignKey("issues.id", ondelete="CASCADE"), nullable=False)
    asset_id: Mapped[Optional[int]] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    hop_order: Mapped[int] = mapped_column(Integer, nullable=False)
    node_id: Mapped[str] = mapped_column(String(1024), nullable=False)
    node_kind: Mapped[Optional[str]] = mapped_column(String(64))
    label: Mapped[Optional[str]] = mapped_column(String(512))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)

    issue: Mapped["Issue"] = relationship(back_populates="hops")
    asset: Mapped[Optional["Asset"]] = relationship(back_populates="issue_hops")


class Vulnerability(Base):
    """A CVE matched against a package installed on a workload (Phase 4 CWPP).

    Natural key (account_id, resource_id, cve_id, package) makes re-scanning
    idempotent the same way findings are: a still-present CVE is refreshed, one
    that's been patched away is resolved (kept for audit), a regression reopens.
    Source is ``cloud.cve_scanner`` (SSM package inventory → OSV match), so rows
    only exist for SSM-managed instances.
    """

    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("account_id", "resource_id", "cve_id", "package", name="uq_vuln_natural_key"),
        Index("ix_vulns_account_status", "account_id", "status"),
        Index("ix_vulns_asset_status", "asset_id", "status"),
        Index("ix_vulns_severity", "severity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False)
    asset_id: Mapped[Optional[int]] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))

    resource_id: Mapped[str] = mapped_column(String(1024), nullable=False)  # affected workload
    cve_id: Mapped[str] = mapped_column(String(64), nullable=False)
    package: Mapped[str] = mapped_column(String(256), nullable=False)
    installed_version: Mapped[Optional[str]] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)
    cvss: Mapped[Optional[float]] = mapped_column(Float)
    summary: Mapped[Optional[str]] = mapped_column(Text)
    fixed_version: Mapped[Optional[str]] = mapped_column(String(128))
    scanner_source: Mapped[str] = mapped_column(String(32), default="ssm-osv", nullable=False)
    package_type: Mapped[Optional[str]] = mapped_column(String(64))
    target: Mapped[Optional[str]] = mapped_column(String(1024))
    package_path: Mapped[Optional[str]] = mapped_column(String(1024))
    # exploit_maturity: EPSS probability + CISA KEV (known exploited in the wild).
    epss: Mapped[Optional[float]] = mapped_column(Float)
    epss_percentile: Mapped[Optional[float]] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="open", nullable=False)  # open|resolved

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    account: Mapped["CloudAccount"] = relationship(back_populates="vulnerabilities")
    asset: Mapped[Optional["Asset"]] = relationship(back_populates="vulnerabilities")


class SecurityScanRun(Base):
    """Append-only evidence that a workload target was actually inspected.

    Keeping scan evidence separate from vulnerability rows lets the product tell
    a completed clean scan from a target that has never been scanned.
    """

    __tablename__ = "security_scan_runs"
    __table_args__ = (
        Index("ix_security_scans_resource_time", "account_id", "resource_id", "scanned_at"),
        Index("ix_security_scans_asset_time", "asset_id", "scanned_at"),
        Index("ix_security_scans_scanner_status", "scanner", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[int] = mapped_column(
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL")
    )
    resource_id: Mapped[str] = mapped_column(String(1024), nullable=False)
    scanner: Mapped[str] = mapped_column(String(32), nullable=False)
    scan_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    package_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status_reason: Mapped[Optional[str]] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    account: Mapped["CloudAccount"] = relationship(back_populates="security_scans")
    asset: Mapped[Optional["Asset"]] = relationship(back_populates="security_scans")


class RuntimeEvent(Base):
    """A runtime/threat signal from the eBPF sensor (Phase 5 threat detection).
    Append-only — these are point-in-time observations, not reconciled state, so
    there is no natural key / resolve cycle.
    """

    __tablename__ = "runtime_events"
    __table_args__ = (
        Index("ix_runtime_events_account_ts", "account_id", "observed_at"),
        Index("ix_runtime_events_type", "event_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[Optional[int]] = mapped_column(ForeignKey("cloud_accounts.id", ondelete="CASCADE"))

    event_type: Mapped[str] = mapped_column(String(64), nullable=False)  # process_execution|...
    severity: Mapped[str] = mapped_column(String(16), default="info", nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(1024))  # node/instance/pod
    workload: Mapped[Optional[str]] = mapped_column(String(512))       # pod / container name
    process: Mapped[Optional[str]] = mapped_column(String(512))        # exec'd binary + args
    pid: Mapped[Optional[int]] = mapped_column(Integer)
    summary: Mapped[Optional[str]] = mapped_column(Text)
    # Burst control: identical signals seen again inside the dedup window collapse
    # into this row (count bumped, observed_at refreshed) instead of flooding the
    # table — a recon loop is one "×47" row, not 47 rows.
    count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    raw: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    account: Mapped[Optional["CloudAccount"]] = relationship(back_populates="runtime_events")


class CloudMutationEvent(Base):
    """Immutable, idempotent ledger of security-relevant CloudTrail mutations."""

    __tablename__ = "cloud_mutation_events"
    __table_args__ = (
        UniqueConstraint("event_id", name="uq_cloud_mutation_event_id"),
        Index("ix_cloud_mutations_account_status", "account_id", "reconcile_status"),
        Index("ix_cloud_mutations_received", "received_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    account_id: Mapped[int] = mapped_column(
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False
    )
    event_name: Mapped[str] = mapped_column(String(128), nullable=False)
    event_source: Mapped[str] = mapped_column(String(128), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_hint: Mapped[Optional[str]] = mapped_column(String(1024))
    event_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    alert: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONType)
    reconcile_status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)
    reconciled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    account: Mapped["CloudAccount"] = relationship(back_populates="mutation_events")


class ComplianceSnapshot(Base):
    """A point-in-time compliance score for one framework (continuous
    compliance). Captured on a schedule and on demand so the platform has a
    history/trend, not just a momentary number. Per-control states live in
    ``controls`` for drift diffing.
    """

    __tablename__ = "compliance_snapshots"
    __table_args__ = (
        Index("ix_compliance_snap_fw_ts", "framework", "captured_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    framework: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(32))
    account: Mapped[Optional[str]] = mapped_column(String(64))
    region: Mapped[Optional[str]] = mapped_column(String(32))
    score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    passing: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    not_assessed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Scoring provenance — 'steampipe' (Powerpipe benchmark) or 'python' (in-tree
    # fallback engine). Surfaced so the two are never silently mixed across a trend.
    origin: Mapped[Optional[str]] = mapped_column(String(32))
    controls: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)  # {control_id: state}
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)


class ComplianceDrift(Base):
    """A control changing state between two snapshots (dynamic compliance).
    direction: 'regression' (pass/not_assessed -> fail) or 'remediation'
    (fail -> pass). Append-only audit of when posture moved and which way.
    """

    __tablename__ = "compliance_drift"
    __table_args__ = (
        Index("ix_compliance_drift_ts", "framework", "detected_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    framework: Mapped[str] = mapped_column(String(64), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    control_title: Mapped[Optional[str]] = mapped_column(Text)
    from_state: Mapped[Optional[str]] = mapped_column(String(16))
    to_state: Mapped[str] = mapped_column(String(16), nullable=False)
    direction: Mapped[str] = mapped_column(String(16), nullable=False)  # regression|remediation
    account: Mapped[Optional[str]] = mapped_column(String(64))
    region: Mapped[Optional[str]] = mapped_column(String(32))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)


class AssetEvent(Base):
    __tablename__ = "asset_events"
    __table_args__ = (Index("ix_asset_events_asset", "asset_id", "changed_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    account_id: Mapped[int] = mapped_column(ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False)
    scan_job_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"))
    event_type: Mapped[str] = mapped_column(String(24), nullable=False)  # created|config_change|deleted|reactivated
    previous_value: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONType)
    new_value: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONType)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    asset: Mapped["Asset"] = relationship(back_populates="events")


class CveCatalog(Base):
    """The NVD CVE reference catalog — every published CVE, independent of whether
    it affects any of our assets. This is the *dictionary* (lookup/browse); the
    ``vulnerabilities`` table is the per-asset *findings* that reference it by
    ``cve_id``. Bulk-ingested from NVD feeds, then refreshed by lastModified delta.

    Indexed for the no-latency browse tab: filter by severity / published date and
    paginate. Keyword search is a LIKE over ``description`` (portable sqlite↔pg).
    """

    __tablename__ = "cve_catalog"
    __table_args__ = (
        Index("ix_cve_catalog_severity", "cvss_severity"),
        Index("ix_cve_catalog_published", "published"),
        Index("ix_cve_catalog_modified", "last_modified"),
    )

    # CVE id is the natural key — store it as the PK so upserts are trivial and
    # per-asset findings can FK-join on it.
    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    source: Mapped[str] = mapped_column(String(32), default="nvd", nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)

    # Best available CVSS (prefer v3.1 > v3.0 > v2) flattened for fast sort/filter,
    # plus the vector + raw metrics kept in ``raw`` for the detail view.
    cvss_score: Mapped[Optional[float]] = mapped_column(Float)
    cvss_severity: Mapped[Optional[str]] = mapped_column(String(16))  # CRITICAL|HIGH|MEDIUM|LOW|NONE
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(128))
    cvss_version: Mapped[Optional[str]] = mapped_column(String(8))    # 3.1|3.0|2.0

    cwes: Mapped[Optional[list[str]]] = mapped_column(JSONType)        # ["CWE-79", ...]
    refs: Mapped[Optional[list[str]]] = mapped_column(JSONType)        # reference URLs
    raw: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)

    published: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_modified: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)


class GraphEdge(Base):
    """A persisted relationship between two graph nodes (assets). The live graph
    is *derived* from ``assets`` by AssetGraph.build each request; persisting the
    edges gives history — "when did this EC2 get this IAM role?" — and lets
    attack-path queries run without re-deriving. Synced with the same
    open/soft-delete lifecycle as assets: an edge still present is refreshed, one
    that disappeared is marked inactive (kept for history).
    """

    __tablename__ = "graph_edges"
    __table_args__ = (
        UniqueConstraint("account_id", "src_id", "dst_id", "edge_type", name="uq_edge_natural_key"),
        Index("ix_graph_edges_account_src", "account_id", "src_id"),
        Index("ix_graph_edges_type", "edge_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[int] = mapped_column(
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False)

    src_id: Mapped[str] = mapped_column(String(1024), nullable=False)   # graph_nodes.id (asset resource_id / "internet")
    dst_id: Mapped[str] = mapped_column(String(1024), nullable=False)
    edge_type: Mapped[str] = mapped_column(String(48), nullable=False)  # HAS_ROLE|CAN_ASSUME|EXPOSED_TO|...
    properties: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    account: Mapped["CloudAccount"] = relationship(back_populates="graph_edges")


class DspmFinding(Base):
    """Data-sensitivity classification for one data store (S3/RDS/DynamoDB/…).
    DSPM previously lived only in the in-memory live cache; persisting it gives
    history + survives restart, keyed on (account, store_id). One row per store,
    upserted each scan.
    """

    __tablename__ = "dspm_findings"
    __table_args__ = (
        UniqueConstraint("account_id", "store_id", name="uq_dspm_natural_key"),
        Index("ix_dspm_account_label", "account_id", "label"),
        Index("ix_dspm_asset", "asset_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[int] = mapped_column(
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False)
    asset_id: Mapped[Optional[int]] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))

    store_id: Mapped[str] = mapped_column(String(1024), nullable=False)   # graph node id, e.g. s3://bucket
    store_name: Mapped[Optional[str]] = mapped_column(String(512))
    store_type: Mapped[str] = mapped_column(String(32), default="S3", nullable=False)
    label: Mapped[str] = mapped_column(String(16), default="NONE", nullable=False)  # CRITICAL|HIGH|MEDIUM|LOW|NONE
    data_types: Mapped[Optional[list[str]]] = mapped_column(JSONType)     # ["SSN","CREDIT_CARD",...]
    taxonomies: Mapped[Optional[list[str]]] = mapped_column(JSONType)     # ["PII","PCI",...]
    frameworks: Mapped[Optional[list[str]]] = mapped_column(JSONType)
    posture_findings: Mapped[Optional[list[str]]] = mapped_column(JSONType)
    record_estimate: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    objects_sampled: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sensitivity_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    exposure_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    public: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    account: Mapped["CloudAccount"] = relationship(back_populates="dspm_findings")
    asset: Mapped[Optional["Asset"]] = relationship(back_populates="data_classifications")


# ── Customization layer (product config, not scan data) ───────────────────────
# These three tables turn hardcoded controls into editable product config. They
# are sparse overlays: an empty table = stock behaviour. Global (not per-account)
# for now — single-tenant config.
# ponytail: no account_id; add one + a UniqueConstraint(account_id, …) the day
# this is multi-tenant. Until then global config is the lazy-correct choice.


class ControlOverride(Base):
    """A per-control tweak applied at score time. Sparse — only controls the user
    actually changed get a row. enabled=False drops the control from scoring;
    severity overrides the check's default; note/waived_until record a waiver.
    """

    __tablename__ = "control_overrides"
    __table_args__ = (
        UniqueConstraint("framework", "control_id", name="uq_control_override"),
        Index("ix_control_override_fw", "framework"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    framework: Mapped[str] = mapped_column(String(64), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    severity: Mapped[Optional[str]] = mapped_column(String(16))  # critical|high|medium|low|info
    note: Mapped[Optional[str]] = mapped_column(Text)            # waiver / acceptance rationale
    waived_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)


class CustomFramework(Base):
    """A user-defined compliance framework. ``controls`` is the whole control set
    as JSON: {control_id: {title, section, checks: [check_id, ...]}}. Scored
    exactly like a built-in — its controls map to checks via their own ``checks``
    list (and to custom policies via the policy's framework mapping).
    """

    __tablename__ = "custom_frameworks"
    __table_args__ = (UniqueConstraint("framework_id", name="uq_custom_framework"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    framework_id: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "ACME-BASELINE"
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(32))
    controls: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)


class CustomPolicy(Base):
    """A user-defined check, evaluated by ``core.policy_engine`` over normalized
    asset fields. ``rule`` is {type, params} (e.g. tag_required / encryption_required
    / no_public / network_max). ``frameworks`` maps this policy to controls:
    {framework_id: [control_id, ...]} so its findings score like any other check.
    """

    __tablename__ = "custom_policies"
    __table_args__ = (UniqueConstraint("policy_id", name="uq_custom_policy"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    policy_id: Mapped[str] = mapped_column(String(64), nullable=False)  # used as the synthetic check_id
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(64))   # asset_type filter; null = all
    rule: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    frameworks: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)
