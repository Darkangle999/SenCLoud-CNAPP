"""Source coverage per pillar — makes the platform's "no data" principle
*measurable* instead of only visual.

For each security pillar (inventory, vulnerabilities, runtime, compliance) it
answers two questions from already-persisted data: is there any data, and is it
fresh. The point is the honest negative: "runtime = absent (sensor not
deployed)" or "vulnerabilities = degraded (EC2 present but no SSM/Trivy data)"
is a first-class, queryable signal — not something the operator has to infer
from an empty table.

Pure DB reads, no new write path, no migration. Reused by the API, the
dashboard, and support/debugging.

ponytail: derived on read, not stored. If a historical coverage *trend* is ever
needed, persist one row per scan cycle and diff it; until then the live
derivation answers "does runtime coverage even exist right now".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from odineyes.db.models import Asset, ComplianceSnapshot, RuntimeEvent, Vulnerability

# Data older than this is "stale"; inside it, "fresh". Scans are expected at
# least daily. ponytail: fixed window — lift to config if scan cadence is tuned.
_FRESH = timedelta(hours=24)

HEALTHY = "healthy"            # data present and fresh
DEGRADED = "degraded"         # data exists but stale, or expected-but-missing
ABSENT = "absent"             # pillar has produced nothing
NOT_APPLICABLE = "not_applicable"  # nothing in the account this pillar could cover


@dataclass
class PillarCoverage:
    pillar: str
    status: str                # healthy | degraded | absent | not_applicable
    detail: str                # human reason for the status
    observed: int              # row count backing the pillar
    last_seen: Optional[str]   # ISO of the freshest backing row, or None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _as_utc(ts: Optional[datetime]) -> Optional[datetime]:
    # sqlite hands back naive datetimes; treat naive as UTC so the age math is sound.
    if ts is None:
        return None
    return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts


def _fresh(ts: Optional[datetime]) -> bool:
    ts = _as_utc(ts)
    return ts is not None and datetime.now(timezone.utc) - ts <= _FRESH


def _iso(ts: Optional[datetime]) -> Optional[str]:
    ts = _as_utc(ts)
    return ts.isoformat() if ts else None


def _count_latest(session: Session, model, ts_col, account_id, extra=None):
    stmt = select(func.count(), func.max(ts_col))
    if account_id is not None and hasattr(model, "account_id"):
        stmt = stmt.where(model.account_id == account_id)
    if extra is not None:
        stmt = stmt.where(extra)
    count, latest = session.execute(stmt).one()
    return count or 0, latest


def _fresh_or_stale(count, latest, healthy_detail, stale_detail) -> PillarCoverage:
    if _fresh(latest):
        return PillarCoverage("", HEALTHY, healthy_detail, count, _iso(latest))
    return PillarCoverage("", DEGRADED, stale_detail, count, _iso(latest))


def compute_coverage(session: Session, *, account_id: Optional[int] = None) -> dict[str, Any]:
    """Per-pillar coverage for one account (or the whole fleet when account_id
    is None). Returns {pillars: [...], healthy: int, total: int}."""
    pillars: list[PillarCoverage] = []

    # ── inventory ──────────────────────────────────────────────
    n_assets, last = _count_latest(
        session, Asset, Asset.last_scanned_at, account_id, extra=Asset.is_active.is_(True))
    if n_assets == 0:
        pillars.append(PillarCoverage(
            "inventory", ABSENT, "No assets collected — run an inventory scan.", 0, None))
    else:
        p = _fresh_or_stale(
            n_assets, last,
            f"{n_assets} active assets, last scan fresh.",
            f"{n_assets} assets but last scan is stale (>{_FRESH}).")
        p.pillar = "inventory"
        pillars.append(p)

    # ── vulnerabilities (CWPP) ─────────────────────────────────
    # The honest negative lives here: EC2 present but zero CVE rows means the
    # SSM/Trivy scan never ran or returned nothing — not that the fleet is clean.
    n_vulns, vlast = _count_latest(session, Vulnerability, Vulnerability.last_seen_at, account_id)
    n_workloads, _ = _count_latest(
        session, Asset, Asset.last_scanned_at, account_id,
        extra=Asset.is_active.is_(True) & (Asset.asset_type == "aws.ec2.instance"))
    if n_vulns > 0:
        p = _fresh_or_stale(
            n_vulns, vlast,
            f"{n_vulns} open CVE findings.",
            f"{n_vulns} CVE findings but last scan is stale (>{_FRESH}).")
        p.pillar = "vulnerabilities"
        pillars.append(p)
    elif n_workloads > 0:
        pillars.append(PillarCoverage(
            "vulnerabilities", DEGRADED,
            f"{n_workloads} EC2 workload(s) but no CVE data — SSM/Trivy scan absent.", 0, None))
    else:
        pillars.append(PillarCoverage(
            "vulnerabilities", NOT_APPLICABLE, "No scannable workloads in inventory.", 0, None))

    # ── runtime (eBPF sensor) ──────────────────────────────────
    n_rt, rlast = _count_latest(session, RuntimeEvent, RuntimeEvent.observed_at, account_id)
    if n_rt == 0:
        pillars.append(PillarCoverage(
            "runtime", ABSENT, "No runtime events — sensor not deployed.", 0, None))
    else:
        p = _fresh_or_stale(
            n_rt, rlast,
            f"{n_rt} runtime events observed.",
            f"{n_rt} runtime events but newest is stale (>{_FRESH}) — sensor may be offline.")
        p.pillar = "runtime"
        pillars.append(p)

    # ── compliance ─────────────────────────────────────────────
    # Snapshots are global (no account_id column), so this pillar is fleet-wide.
    c_count, c_last = session.execute(
        select(func.count(), func.max(ComplianceSnapshot.captured_at))
    ).one()
    c_count = c_count or 0
    if c_count == 0:
        pillars.append(PillarCoverage(
            "compliance", ABSENT, "No compliance snapshot — run a compliance scan.", 0, None))
    else:
        p = _fresh_or_stale(
            c_count, c_last,
            f"{c_count} framework snapshot(s).",
            f"{c_count} snapshot(s) but newest is stale (>{_FRESH}).")
        p.pillar = "compliance"
        pillars.append(p)

    return {
        "pillars": [p.to_dict() for p in pillars],
        "healthy": sum(1 for p in pillars if p.status == HEALTHY),
        "total": len(pillars),
    }
