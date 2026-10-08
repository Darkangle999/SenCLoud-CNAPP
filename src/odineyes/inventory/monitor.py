"""Continuous monitoring: a periodic scan -> findings -> issues cycle with
webhook alerts on findings that newly cross into open + critical/high.

Reuses InventoryService and the existing AwsRawCollector — no second scan stack.
Off by default. Two entry points:
  * ``run_cycle(...)`` — one full cycle (called by the server background loop and
    the POST /api/live/scan-cycle endpoint, or directly from a cron/systemd unit).
  * alerts fire to ``ODINEYES_ALERT_WEBHOOK`` (Slack-compatible JSON).

"New critical" is computed as a set diff of open critical/high findings before vs
after the cycle, so it catches both brand-new and reopened findings without
depending on per-row timestamps.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from typing import Any, Optional

from odineyes.inventory.service import InventoryService

logger = logging.getLogger(__name__)

# Severities worth paging a human about. Medium/low ride the dashboard, not Slack.
ALERT_SEVERITIES = ("critical", "high")

# (rule_id, resource_id) -> finding detail
AlertMap = dict[tuple[str, str], dict[str, Any]]


def _open_alertable(database_url: Optional[str], provider: str, account: str) -> AlertMap:
    """Open critical/high findings for the account, keyed on (rule_id, resource_id)."""
    from sqlalchemy import select

    from odineyes.db.base import session_scope
    from odineyes.db.models import CloudAccount, Finding

    out: AlertMap = {}
    with session_scope(database_url) as session:
        acct = session.execute(
            select(CloudAccount).where(
                CloudAccount.provider == provider,
                CloudAccount.account_identifier == account,
            )
        ).scalar_one_or_none()
        if acct is None:
            return out
        rows = session.execute(
            select(Finding).where(
                Finding.account_id == acct.id,
                Finding.status == "open",
                Finding.severity.in_(ALERT_SEVERITIES),
            )
        ).scalars()
        for f in rows:
            out[(f.rule_id, f.resource_id)] = {
                "rule_id": f.rule_id,
                "resource_id": f.resource_id,
                "severity": f.severity,
                "title": f.title,
                "remediation": f.remediation,
            }
    return out


def _new_alertable(before: AlertMap, after: AlertMap) -> list[dict[str, Any]]:
    """Findings present in `after` but not `before` — newly open + critical/high.
    Critical first, then high; stable within a severity."""
    order = {s: i for i, s in enumerate(ALERT_SEVERITIES)}
    new = [v for k, v in after.items() if k not in before]
    return sorted(new, key=lambda f: order.get(f["severity"], 99))


def _format_alert(account: str, region: str, findings: list[dict[str, Any]]) -> str:
    """Slack-friendly text body (also fine in any plain webhook viewer)."""
    lines = [
        f"*Odineyes* — {len(findings)} new critical/high finding(s) "
        f"on AWS `{account}` ({region})"
    ]
    for f in findings[:20]:
        lines.append(f"• [{f['severity'].upper()}] {f['title']} — `{f['resource_id']}`")
    if len(findings) > 20:
        lines.append(f"…and {len(findings) - 20} more")
    return "\n".join(lines)


def send_alert(webhook: str, account: str, region: str,
               findings: list[dict[str, Any]]) -> int:
    """POST a Slack-compatible payload. Returns count alerted (0 on failure —
    a bad webhook must never sink the scan cycle)."""
    payload = json.dumps({
        "text": _format_alert(account, region, findings),
        "account": account,
        "region": region,
        "new_critical_high": len(findings),
        "findings": findings[:50],
    }).encode()
    req = urllib.request.Request(
        webhook, payload, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10).read()
        return len(findings)
    except Exception as e:  # noqa: BLE001
        logger.error("alert webhook failed: %s", e)
        return 0


def run_cycle(
    provider: str = "aws",
    account: Optional[str] = None,
    region: str = "us-east-1",
    profile: Optional[str] = None,
    database_url: Optional[str] = None,
    webhook: Optional[str] = None,
    regions: Optional[list[str]] = None,
) -> dict[str, Any]:
    """One full monitoring cycle: collect -> persist -> evaluate findings + issues
    -> alert on newly-open critical/high. Blocking (boto3 + DB); run off the event
    loop when called from async.

    `region` is the home region (STS identity, alert label, DSPM). `regions` is
    the sweep set: None means every enabled region (shadow-IT default); pass an
    explicit list to scope it."""
    from odineyes.inventory.aws_raw_collector import AwsRawCollector

    collector = AwsRawCollector(region=region, profile=profile, regions=regions)
    account = account or collector.account_id()
    if account == "unknown":
        raise RuntimeError("could not resolve AWS account (check credentials)")

    service = InventoryService(database_url=database_url)
    before = _open_alertable(database_url, provider, account)

    resources = collector.collect()
    # Per-region asset counts — the shadow-IT lens: resources in regions you
    # didn't expect stand out here.
    by_region: dict[str, int] = {}
    for _src, raw in resources:
        r = raw.get("Region", "global")
        by_region[r] = by_region.get(r, 0) + 1
    scan = service.persist_scan(
        provider=provider, account_identifier=account,
        resources=resources, scan_type="config",
        authoritative_scopes=collector.authoritative_scopes,
        collection_errors=collector.collection_errors,
    )
    fstats = service.evaluate_findings(provider, account)
    istats = service.evaluate_issues(provider, account)

    # DSPM: classify data stores off the same session and persist (S3 assets are
    # already in the spine from persist_scan above). Best-effort — a DSPM failure
    # must not sink the scan cycle.
    dstats = None
    try:
        dstats = service.scan_dspm(provider, account, collector.session, region)
    except Exception as e:  # noqa: BLE001
        logger.warning("DSPM scan skipped: %s", e)

    after = _open_alertable(database_url, provider, account)
    new = _new_alertable(before, after)

    webhook = webhook or os.environ.get("ODINEYES_ALERT_WEBHOOK")
    alerted = send_alert(webhook, account, region, new) if (new and webhook) else 0

    result = {
        "account": account,
        "region": region,
        "regions_scanned": sorted(by_region),
        "by_region": by_region,
        "assets": scan.found,
        "findings_new": fstats.new,
        "findings_resolved": fstats.resolved,
        "issues_new": istats.new,
        "dspm_stores": (dstats.total if dstats else 0),
        "new_critical_high": len(new),
        "alerted": alerted,
    }
    logger.info("scan cycle: %s", result)
    return result


if __name__ == "__main__":
    # Offline self-check (no AWS, no DB) for the alert logic — the set-diff and the
    # formatter are the only non-trivial pure pieces.
    _before: AlertMap = {("OPEN_PORT", "sg-1"): {"severity": "critical"}}
    _after: AlertMap = {
        ("OPEN_PORT", "sg-1"): {"severity": "critical"},  # pre-existing, no alert
        ("PUBLIC_ADMIN_ROLE", "role-x"): {
            "severity": "critical", "title": "Public admin role", "resource_id": "role-x"},
        ("PUBLIC_LAMBDA_URL", "fn-y"): {
            "severity": "high", "title": "Public Lambda URL", "resource_id": "fn-y"},
    }
    _new = _new_alertable(_before, _after)
    assert [f["resource_id"] for f in _new] == ["role-x", "fn-y"], "diff must skip pre-existing, critical first"
    _txt = _format_alert("123456789012", "us-east-1", _new)
    assert "us-east-1" in _txt and "Public admin role" in _txt and "2 new" in _txt
    print("monitor self-check OK")
