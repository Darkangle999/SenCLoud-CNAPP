"""Read-side queries over the inventory store.

Pure functions returning JSON-ready dicts — the FastAPI layer is a thin shell
over these, and they are unit-testable without HTTP. SQL-expressible filters run
in the database with LIMIT/OFFSET, including JSON tag filters on the supported
SQLite and PostgreSQL stores.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Sequence
from urllib.parse import quote

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session, selectinload

from odineyes.inventory.rules import NETWORK_HYGIENE_RULES, finding_signal, remediation_command
from odineyes.inventory.finding_risk import finding_risk, store_key
from odineyes.inventory.normalizers import extract_trust_statement_evidence
from odineyes.inventory.reachability import (
    assess_ec2_internet_reachability,
    assess_rds_internet_reachability,
    build_network_topology,
    public_endpoint_configured,
)
from odineyes.db.models import (
    Asset,
    AssetEvent,
    CloudAccount,
    ComplianceDrift,
    ComplianceSnapshot,
    CveCatalog,
    DspmFinding,
    Finding,
    GraphEdge,
    Issue,
    RuntimeEvent,
    ScanJob,
    SecurityScanRun,
    Vulnerability,
)

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_CATEGORY_LABELS = {
    "identity": "Identity",
    "compute": "Compute",
    "network": "Network",
    "data": "Data",
    "security": "Security",
    "management": "Management",
    "other": "Other",
}


def _asset_taxonomy(asset_type: str) -> tuple[str, str, str]:
    """Convert canonical provider.service.kind types into UI taxonomy."""
    parts = [part for part in (asset_type or "").lower().split(".") if part]
    service = parts[1] if len(parts) > 1 else (parts[0] if parts else "unknown")
    kind = ".".join(parts[2:]) if len(parts) > 2 else "resource"
    tokens = set(parts[1:]) | set(kind.replace("-", "_").split("_"))

    # Network first: ``security_group`` also contains the generic word ``group``.
    if tokens & {"security_group", "vpc", "subnet", "network", "firewall", "route", "load_balancer", "gateway"}:
        category = "network"
    elif tokens & {"iam", "identity", "user", "users", "role", "roles", "group", "policy", "service_account"}:
        category = "identity"
    elif tokens & {"bucket", "database", "db", "table", "storage", "snapshot", "secret", "key", "queue", "topic"}:
        category = "data"
    elif tokens & {"instance", "vm", "function", "lambda", "cluster", "container", "node", "compute"}:
        category = "compute"
    elif service in {"guardduty", "securityhub", "defender", "kms", "waf", "shield"}:
        category = "security"
    elif service in {"cloudtrail", "config", "monitor", "cloudwatch", "logging", "organizations"}:
        category = "management"
    else:
        category = "other"
    return category, service, kind


def _cloud_console_url(asset: Asset) -> Optional[str]:
    """Best-effort deep link for resource types with stable AWS console routes."""
    if asset.cloud_provider != "aws":
        return None
    resource_id = asset.resource_id or ""
    name = asset.name or resource_id.rsplit("/", 1)[-1]
    region = asset.region if asset.region and asset.region != "global" else "us-east-1"
    if asset.asset_type == "aws.ec2.instance":
        instance_id = resource_id.rsplit("/", 1)[-1]
        return (
            f"https://{region}.console.aws.amazon.com/ec2/home"
            f"?region={quote(region)}#InstanceDetails:instanceId={quote(instance_id)}"
        )
    if asset.asset_type == "aws.s3.bucket":
        return f"https://s3.console.aws.amazon.com/s3/buckets/{quote(name)}"
    if asset.asset_type == "aws.iam.role":
        return f"https://console.aws.amazon.com/iam/home#/roles/details/{quote(name)}"
    if asset.asset_type == "aws.iam.user":
        return f"https://console.aws.amazon.com/iam/home#/users/details/{quote(name)}"
    if asset.asset_type == "aws.lambda.function":
        return (
            f"https://{region}.console.aws.amazon.com/lambda/home"
            f"?region={quote(region)}#/functions/{quote(name)}"
        )
    if asset.asset_type.startswith("aws.rds."):
        return f"https://{region}.console.aws.amazon.com/rds/home?region={quote(region)}#databases:"
    return None


def _risk_severity(score: float, finding_severities: dict[str, int]) -> str:
    for severity in ("critical", "high", "medium", "low"):
        if finding_severities.get(severity, 0):
            return severity
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _facet(values: dict[str, int], *, labels: Optional[dict[str, str]] = None) -> list[dict[str, Any]]:
    labels = labels or {}
    return [
        {"value": value, "label": labels.get(value, value), "count": count}
        for value, count in sorted(values.items(), key=lambda item: (-item[1], item[0]))
    ]


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, (tuple, set)):
        return [str(item) for item in value]
    if isinstance(value, str) and value:
        return [value]
    return []


def identity_ciem_view(properties: dict[str, Any]) -> dict[str, Any]:
    """Boundary-aware CIEM evidence derived purely from Asset.properties.

    Shared by the Identity list and the asset detail so both explain privilege
    the same way: policy grant vs boundary-permitted candidate, policy sources,
    statement counts, and the authorization layers not yet evaluated. Never
    claims effective access when required layers are unknown.
    """
    return {
        "privilege": {
            "admin": bool(properties.get("has_admin")),
            "admin_grant": bool(
                properties.get("has_admin_grant")
                if "has_admin_grant" in properties
                else properties.get("has_admin")
            ),
            "boundary_restricts_admin": bool(properties.get("boundary_restricts_admin")),
            "admin_reason": str(properties.get("admin_reason") or ""),
            "privilege_escalation_actions": _string_list(properties.get("privesc_actions")),
            "effective_privilege_escalation_actions": _string_list(
                properties.get("effective_privesc_actions")
                if "effective_privesc_actions" in properties
                else properties.get("privesc_actions")
            ),
        },
        "authorization": {
            "scope": str(properties.get("authorization_scope") or "identity_policies"),
            "effective_access_complete": bool(properties.get("effective_access_complete")),
            "unevaluated_policy_layers": _string_list(
                properties.get("unevaluated_policy_layers")
            ),
            "policy_sources": int(properties.get("policy_source_count") or 0),
            "direct_policy_sources": int(properties.get("direct_policy_count") or 0),
            "inherited_policy_sources": int(properties.get("inherited_policy_count") or 0),
            "allow_statements": int(properties.get("allow_statement_count") or 0),
            "explicit_denies": int(properties.get("explicit_deny_count") or 0),
            "conditional_statements": int(properties.get("conditional_statement_count") or 0),
            "wildcard_action_statements": int(
                properties.get("wildcard_action_statement_count") or 0
            ),
            "wildcard_resource_statements": int(
                properties.get("wildcard_resource_statement_count") or 0
            ),
            "groups": _string_list(properties.get("group_names")),
            "permissions_boundary_arn": (
                str(properties.get("permissions_boundary_arn"))
                if properties.get("permissions_boundary_arn") else None
            ),
            "permissions_boundary_state": str(
                properties.get("permissions_boundary_state") or "not_configured"
            ),
            "analysis_complete": bool(properties.get("policy_analysis_complete")),
        },
    }


def _is_verified_onboarding_trust(
    asset: Asset,
    account: CloudAccount,
    principals: list[str],
    scanner_principal_arn: Optional[str],
) -> bool:
    """Return whether an IAM role's only external trust is Odineyes onboarding.

    A cross-account trust is normally security-relevant. Odineyes creates one
    deliberately, however, so the identity UI must not label a registered
    read-only role as an unknown external trust. Fail closed: the registered
    role ARN, exact scanner principal, and account-scoped ExternalId must all
    match, and there cannot be another external principal in the same role.
    """
    if (
        not scanner_principal_arn
        or not account.external_id
        or not account.role_arn
        or asset.resource_id != account.role_arn
        or not principals
        or set(principals) != {scanner_principal_arn}
    ):
        return False

    properties = asset.properties or {}
    evidence = properties.get("trust_statements") or []
    if not evidence:
        raw = asset.raw or {}
        evidence = extract_trust_statement_evidence(raw.get("AssumeRolePolicyDocument"))

    for statement in evidence:
        if not isinstance(statement, dict):
            continue
        statement_principals = {str(value) for value in statement.get("principals") or []}
        external_ids = {str(value) for value in statement.get("external_ids") or []}
        if (
            scanner_principal_arn in statement_principals
            and str(account.external_id) in external_ids
        ):
            return True
    return False


def _normalized_score(value: Any) -> float:
    try:
        score = float(value or 0)
    except (TypeError, ValueError):
        return 0.0
    if 0 < score <= 1:
        score *= 100
    return round(min(max(score, 0), 100), 1)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else None


def account_to_dict(a: CloudAccount, latest_scan: Optional[ScanJob] = None) -> dict[str, Any]:
    data = {
        "id": a.id,
        "provider": a.provider,
        "account_identifier": a.account_identifier,
        "name": a.name,
        "role_arn": a.role_arn,
        "disk_scan_role_arn": a.disk_scan_role_arn,
        "realtime_role_arn": a.realtime_role_arn,
        "is_active": a.is_active,
        "onboarding_status": a.onboarding_status,
        "last_verify_status": a.last_verify_status,
        "last_verified_at": _iso(a.last_verified_at),
        "created_at": _iso(a.created_at),
    }
    if latest_scan is not None:
        data["latest_scan"] = scan_job_to_dict(latest_scan, include_error=True)
    else:
        data["latest_scan"] = None
    return data


def asset_to_dict(a: Asset, *, detail: bool = False) -> dict[str, Any]:
    base = {
        "id": a.id,
        "resource_id": a.resource_id,
        "cloud_provider": a.cloud_provider,
        "account_id": a.account_id,
        "asset_type": a.asset_type,
        "name": a.name,
        "region": a.region,
        "tags": a.tags,
        "is_public": a.is_public,
        "encryption_enabled": a.encryption_enabled,
        "network_exposure": a.network_exposure,
        "properties": a.properties,
        "risk_score": a.risk_score,
        "is_active": a.is_active,
        "first_seen_at": _iso(a.first_seen_at),
        "last_scanned_at": _iso(a.last_scanned_at),
    }
    if detail:
        base.update({
            "raw": a.raw,
            "normalized": a.normalized,
            "properties": a.properties,
            "relationships": a.relationships,
            "resource_created_at": _iso(a.resource_created_at),
        })
    return base


def scan_job_to_dict(j: ScanJob, *, include_error: bool = False) -> dict[str, Any]:
    data = {
        "id": j.id,
        "account_id": j.account_id,
        "scan_type": j.scan_type,
        "status": j.status,
        "started_at": _iso(j.started_at),
        "completed_at": _iso(j.completed_at),
        "duration_seconds": j.duration_seconds,
        "assets_found": j.assets_found,
        "assets_changed": j.assets_changed,
        "assets_deleted": j.assets_deleted,
        "error_count": j.error_count,
    }
    if include_error:
        # One concise diagnostic is enough for list/status views. The detailed
        # ScanError rows remain available through the individual job endpoint.
        latest = max(j.errors, key=lambda e: (e.created_at, e.id), default=None)
        data["error"] = latest.message if latest is not None else None
    return data


def list_accounts(session: Session) -> list[dict[str, Any]]:
    accounts = session.execute(
        select(CloudAccount).options(
            selectinload(CloudAccount.scan_jobs).selectinload(ScanJob.errors),
        )
    ).scalars()
    result: list[dict[str, Any]] = []
    for account in accounts:
        latest = max(account.scan_jobs, key=lambda job: (job.created_at, job.id), default=None)
        result.append(account_to_dict(account, latest))
    return result


def list_assets(
    session: Session,
    *,
    provider: Optional[str] = None,
    account_id: Optional[int] = None,
    asset_type: Optional[str] = None,
    region: Optional[str] = None,
    is_public: Optional[bool] = None,
    is_active: Optional[bool] = True,
    tag_key: Optional[str] = None,
    tag_value: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    page = max(page, 1)
    page_size = min(max(page_size, 1), 500)

    stmt = select(Asset)
    if provider:
        stmt = stmt.where(Asset.cloud_provider == provider)
    if account_id is not None:
        stmt = stmt.where(Asset.account_id == account_id)
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    if region:
        stmt = stmt.where(Asset.region == region)
    if is_public is not None:
        stmt = stmt.where(Asset.is_public == is_public)
    if is_active is not None:
        stmt = stmt.where(Asset.is_active == is_active)
    stmt = stmt.order_by(Asset.last_scanned_at.desc())

    tag_filter_in_db = False
    if tag_key is not None:
        dialect = session.get_bind().dialect.name
        if dialect == "sqlite":
            escaped_key = tag_key.replace("\\", "\\\\").replace('"', '\\"')
            json_path = f'$."{escaped_key}"'
            tag_expr = func.json_extract(Asset.tags, json_path)
            predicate = (
                func.json_type(Asset.tags, json_path).is_not(None)
                if tag_value is None
                else tag_expr == tag_value
            )
            stmt = stmt.where(predicate)
            tag_filter_in_db = True
        elif dialect == "postgresql":
            predicate = (
                Asset.tags.op("?")(tag_key)
                if tag_value is None
                else Asset.tags[tag_key].as_string() == tag_value
            )
            stmt = stmt.where(predicate)
            tag_filter_in_db = True

    if tag_key is not None and not tag_filter_in_db:
        # Fallback for unsupported development dialects only.
        rows = list(session.execute(stmt).scalars())
        matched = [
            a for a in rows
            if tag_key in (a.tags or {}) and (tag_value is None or a.tags.get(tag_key) == tag_value)
        ]
        total = len(matched)
        start = (page - 1) * page_size
        items = matched[start:start + page_size]
    else:
        total = session.execute(
            select(func.count()).select_from(stmt.order_by(None).subquery())
        ).scalar_one()
        rows = session.execute(stmt.limit(page_size).offset((page - 1) * page_size)).scalars()
        items = list(rows)

    return {
        "items": [asset_to_dict(a) for a in items],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


def list_inventory_resources(
    session: Session,
    *,
    provider: Optional[str] = None,
    account_id: Optional[int] = None,
    query: Optional[str] = None,
    category: Optional[str] = None,
    service: Optional[str] = None,
    asset_type: Optional[str] = None,
    region: Optional[str] = None,
    exposure: Optional[str] = None,
    min_risk: Optional[float] = None,
    is_active: Optional[bool] = True,
    sort: str = "risk",
    direction: str = "desc",
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    """Product-facing inventory model with server-side facets and posture.

    The legacy list endpoint intentionally remains storage-shaped.  This view is
    organized around resource identity, scope, security posture, and lifecycle.
    """
    page = max(page, 1)
    page_size = min(max(page_size, 1), 200)

    scope_conditions = []
    if provider:
        scope_conditions.append(Asset.cloud_provider == provider)
    if account_id is not None:
        scope_conditions.append(Asset.account_id == account_id)
    if is_active is not None:
        scope_conditions.append(Asset.is_active == is_active)

    # One grouped query supplies stable facets for the selected account/provider
    # scope. Filters then narrow results without making options disappear.
    facet_rows = session.execute(
        select(
            Asset.asset_type,
            Asset.region,
            Asset.network_exposure,
            Asset.cloud_provider,
            func.count(),
        )
        .where(*scope_conditions)
        .group_by(Asset.asset_type, Asset.region, Asset.network_exposure, Asset.cloud_provider)
    ).all()

    category_counts: dict[str, int] = {}
    service_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    region_counts: dict[str, int] = {}
    exposure_counts: dict[str, int] = {}
    scoped_types: set[str] = set()
    for row_type, row_region, row_exposure, _row_provider, count in facet_rows:
        row_category, row_service, _kind = _asset_taxonomy(row_type)
        scoped_types.add(row_type)
        category_counts[row_category] = category_counts.get(row_category, 0) + count
        service_counts[row_service] = service_counts.get(row_service, 0) + count
        type_counts[row_type] = type_counts.get(row_type, 0) + count
        region_counts[row_region] = region_counts.get(row_region, 0) + count
        exposure_counts[row_exposure] = exposure_counts.get(row_exposure, 0) + count

    totals_row = session.execute(
        select(
            func.count(),
            func.coalesce(func.sum(case((Asset.is_public.is_(True), 1), else_=0)), 0),
            func.coalesce(func.sum(case((Asset.risk_score >= 60, 1), else_=0)), 0),
        ).where(*scope_conditions)
    ).one()
    scoped_total, public_total, elevated_risk_total = (int(value or 0) for value in totals_row)

    stmt = select(Asset).where(*scope_conditions)
    if query and query.strip():
        needle = f"%{query.strip().lower()}%"
        stmt = stmt.where(or_(
            func.lower(func.coalesce(Asset.name, "")).like(needle),
            func.lower(Asset.resource_id).like(needle),
            func.lower(Asset.asset_type).like(needle),
        ))
    if category:
        matching_types = [value for value in scoped_types if _asset_taxonomy(value)[0] == category]
        stmt = stmt.where(Asset.asset_type.in_(matching_types))
    if service:
        matching_types = [value for value in scoped_types if _asset_taxonomy(value)[1] == service]
        stmt = stmt.where(Asset.asset_type.in_(matching_types))
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    if region:
        stmt = stmt.where(Asset.region == region)
    if exposure:
        stmt = stmt.where(Asset.network_exposure == exposure)
    if min_risk is not None:
        stmt = stmt.where(Asset.risk_score >= min_risk)

    filtered_total = int(session.execute(
        select(func.count()).select_from(stmt.order_by(None).subquery())
    ).scalar_one())

    sort_columns = {
        "name": func.lower(func.coalesce(Asset.name, Asset.resource_id)),
        "type": Asset.asset_type,
        "region": Asset.region,
        "risk": Asset.risk_score,
        "last_scanned": Asset.last_scanned_at,
    }
    sort_column = sort_columns.get(sort, Asset.risk_score)
    order = sort_column.asc() if direction == "asc" else sort_column.desc()
    rows = list(session.execute(
        stmt.order_by(order, Asset.id.asc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    ).scalars())

    account_ids = {asset.account_id for asset in rows}
    accounts = {
        account.id: account.name or account.account_identifier
        for account in session.execute(
            select(CloudAccount).where(CloudAccount.id.in_(account_ids))
        ).scalars()
    } if account_ids else {}

    resource_keys = {(asset.account_id, asset.resource_id) for asset in rows}
    finding_counts: dict[tuple[int, str], dict[str, int]] = {}
    if resource_keys:
        finding_rows = session.execute(
            select(Finding.account_id, Finding.resource_id, Finding.severity, func.count())
            .where(
                Finding.status == "open",
                Finding.account_id.in_(account_ids),
                Finding.resource_id.in_({resource_id for _, resource_id in resource_keys}),
            )
            .group_by(Finding.account_id, Finding.resource_id, Finding.severity)
        ).all()
        for finding_account_id, resource_id, severity, count in finding_rows:
            key = (finding_account_id, resource_id)
            if key not in resource_keys:
                continue
            finding_counts.setdefault(key, {})[severity] = int(count)

    items: list[dict[str, Any]] = []
    for asset in rows:
        row_category, row_service, kind = _asset_taxonomy(asset.asset_type)
        severities = finding_counts.get((asset.account_id, asset.resource_id), {})
        encryption = (
            "not_applicable" if asset.encryption_enabled is None
            else "enabled" if asset.encryption_enabled else "disabled"
        )
        items.append({
            "id": asset.id,
            "identity": {
                "name": asset.name or asset.resource_id,
                "resource_id": asset.resource_id,
                "provider": asset.cloud_provider,
                "account_id": asset.account_id,
                "account_name": accounts.get(asset.account_id),
                "asset_type": asset.asset_type,
                "service": row_service,
                "category": row_category,
                "kind": kind,
            },
            "scope": {
                "region": asset.region,
                "level": "global" if asset.region == "global" else "regional",
            },
            "posture": {
                "exposure": asset.network_exposure,
                "is_public": asset.is_public,
                "encryption": {"status": encryption},
                "risk": {
                    "score": float(asset.risk_score or 0),
                    "severity": _risk_severity(float(asset.risk_score or 0), severities),
                },
                "findings": {
                    "total": sum(severities.values()),
                    "by_severity": severities,
                },
            },
            "lifecycle": {
                "status": "active" if asset.is_active else "inactive",
                "first_seen_at": _iso(asset.first_seen_at),
                "last_scanned_at": _iso(asset.last_scanned_at),
                "resource_created_at": _iso(asset.resource_created_at),
            },
            "metadata": {
                "tags": asset.tags or {},
                "relationship_count": len(asset.relationships or []),
            },
        })

    pages = (filtered_total + page_size - 1) // page_size if filtered_total else 0
    return {
        "schema_version": "1.0",
        "items": items,
        "totals": {
            "assets": scoped_total,
            "filtered": filtered_total,
            "public": public_total,
            "elevated_risk": elevated_risk_total,
        },
        "facets": {
            "categories": _facet(category_counts, labels=_CATEGORY_LABELS),
            "services": _facet(service_counts),
            "types": _facet(type_counts),
            "regions": _facet(region_counts, labels={"global": "Global"}),
            "exposures": _facet(exposure_counts),
        },
        "pagination": {
            "page": page,
            "page_size": page_size,
            "pages": pages,
            "total": filtered_total,
        },
    }


def list_identity_principals(
    session: Session,
    *,
    provider: Optional[str] = None,
    account_id: Optional[int] = None,
    query: Optional[str] = None,
    principal_type: Optional[str] = None,
    trust_level: Optional[str] = None,
    min_risk: Optional[float] = None,
    sort: str = "risk",
    direction: str = "desc",
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    """CIEM resource view over all identity asset types, not IAM roles only."""
    page = max(page, 1)
    page_size = min(max(page_size, 1), 200)
    scope = [Asset.is_active.is_(True)]
    if provider:
        scope.append(Asset.cloud_provider == provider)
    if account_id is not None:
        scope.append(Asset.account_id == account_id)

    available_types = list(session.execute(select(Asset.asset_type).where(*scope).distinct()).scalars())
    identity_types = [asset_type for asset_type in available_types if _asset_taxonomy(asset_type)[0] == "identity"]
    stmt = select(Asset).where(*scope, Asset.asset_type.in_(identity_types))
    if query and query.strip():
        needle = f"%{query.strip().lower()}%"
        stmt = stmt.where(or_(
            func.lower(func.coalesce(Asset.name, "")).like(needle),
            func.lower(Asset.resource_id).like(needle),
            func.lower(Asset.asset_type).like(needle),
        ))
    assets = list(session.execute(stmt).scalars())
    account_ids = {asset.account_id for asset in assets}
    account_names = {
        account.id: account.name or account.account_identifier
        for account in session.execute(select(CloudAccount).where(CloudAccount.id.in_(account_ids))).scalars()
    } if account_ids else {}
    accounts_by_id = {
        account.id: account
        for account in session.execute(select(CloudAccount).where(CloudAccount.id.in_(account_ids))).scalars()
    } if account_ids else {}
    scanner_principal_arn = os.environ.get("ODINEYES_SCANNER_PRINCIPAL_ARN", "").strip() or None
    resource_ids = {asset.resource_id for asset in assets}

    finding_counts: dict[tuple[int, str], int] = {}
    issue_counts: dict[tuple[int, str], int] = {}
    if resource_ids:
        for aid, rid, count in session.execute(
            select(Finding.account_id, Finding.resource_id, func.count())
            .where(Finding.status == "open", Finding.account_id.in_(account_ids), Finding.resource_id.in_(resource_ids))
            .group_by(Finding.account_id, Finding.resource_id)
        ):
            finding_counts[(aid, rid)] = int(count)
        for aid, rid, count in session.execute(
            select(Issue.account_id, Issue.resource_id, func.count())
            .where(Issue.status == "open", Issue.account_id.in_(account_ids), Issue.resource_id.in_(resource_ids))
            .group_by(Issue.account_id, Issue.resource_id)
        ):
            issue_counts[(aid, rid)] = int(count)

    modeled: list[dict[str, Any]] = []
    for asset in assets:
        properties = asset.properties or {}
        _category, _service, kind = _asset_taxonomy(asset.asset_type)
        principal_kind = kind.split(".")[-1]
        public_trust = bool(properties.get("publicly_assumable"))
        external_trust = bool(properties.get("trust_external"))
        principals = _string_list(
            properties.get("trusted_principals")
            or properties.get("trust_principals")
            or properties.get("principals")
        )
        account = accounts_by_id.get(asset.account_id)
        verified_onboarding = bool(
            account
            and not public_trust
            and external_trust
            and _is_verified_onboarding_trust(
                asset, account, principals, scanner_principal_arn,
            )
        )
        trust = (
            "public" if public_trust
            else "verified" if verified_onboarding
            else "external" if external_trust
            else "account" if principals
            else "none"
        )
        score = _normalized_score(asset.risk_score)
        modeled.append({
            "id": asset.id,
            "identity": {
                "name": asset.name or asset.resource_id,
                "resource_id": asset.resource_id,
                "provider": asset.cloud_provider,
                "account_id": asset.account_id,
                "account_name": account_names.get(asset.account_id),
                "principal_type": principal_kind,
            },
            **identity_ciem_view(properties),
            "authentication": {
                "console_enabled": bool(properties.get("console_enabled")),
                "mfa_enabled": bool(properties.get("mfa_enabled")),
                "access_key_active": bool(properties.get("access_key_active")),
                "access_key_max_age_days": int(properties.get("access_key_max_age_days") or 0),
                "access_key_last_used_days": properties.get("access_key_last_used_days"),
            },
            "trust": {
                "level": trust,
                "publicly_assumable": public_trust,
                "external": external_trust and not verified_onboarding,
                "onboarding_verified": verified_onboarding,
                "principals": principals,
            },
            "posture": {
                "risk_score": score,
                "severity": _risk_severity(score, {}),
                "open_findings": finding_counts.get((asset.account_id, asset.resource_id), 0),
                "attack_paths": issue_counts.get((asset.account_id, asset.resource_id), 0),
            },
            "lifecycle": {
                "age_days": properties.get("age_days"),
                "last_used_days": properties.get("last_used_days"),
                "last_scanned_at": _iso(asset.last_scanned_at),
            },
            "metadata": {"tags": asset.tags or {}, "path": properties.get("path")},
        })

    type_counts: dict[str, int] = {}
    trust_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for item in modeled:
        kind = item["identity"]["principal_type"]
        trust = item["trust"]["level"]
        severity = item["posture"]["severity"]
        type_counts[kind] = type_counts.get(kind, 0) + 1
        trust_counts[trust] = trust_counts.get(trust, 0) + 1
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    filtered = [item for item in modeled if (
        (not principal_type or item["identity"]["principal_type"] == principal_type)
        and (not trust_level or item["trust"]["level"] == trust_level)
        and (min_risk is None or item["posture"]["risk_score"] >= min_risk)
    )]
    sort_keys = {
        "risk": lambda item: item["posture"]["risk_score"],
        "name": lambda item: item["identity"]["name"].lower(),
        "last_scanned": lambda item: item["lifecycle"]["last_scanned_at"] or "",
        "findings": lambda item: item["posture"]["open_findings"],
    }
    filtered.sort(key=sort_keys.get(sort, sort_keys["risk"]), reverse=direction == "desc")
    filtered_total = len(filtered)
    items = filtered[(page - 1) * page_size:page * page_size]
    return {
        "schema_version": "1.0",
        "items": items,
        "totals": {
            "principals": len(modeled),
            "roles": sum(item["identity"]["principal_type"] == "role" for item in modeled),
            "users": sum(item["identity"]["principal_type"] == "user" for item in modeled),
            "admins": sum(item["privilege"]["admin"] for item in modeled),
            "admin_grants": sum(item["privilege"]["admin_grant"] for item in modeled),
            "bounded": sum(
                item["authorization"]["permissions_boundary_state"] != "not_configured"
                for item in modeled
            ),
            "inherited_access": sum(
                item["authorization"]["inherited_policy_sources"] > 0
                for item in modeled
            ),
            "incomplete_evaluations": sum(
                not item["authorization"]["effective_access_complete"]
                for item in modeled
            ),
            "mfa_gaps": sum(
                item["authentication"]["console_enabled"] and not item["authentication"]["mfa_enabled"]
                for item in modeled
            ),
            "external_trust": sum(item["trust"]["level"] in {"public", "external"} for item in modeled),
            "filtered": filtered_total,
        },
        "facets": {
            "principal_types": _facet(type_counts),
            "trust_levels": _facet(
                trust_counts,
                labels={"verified": "Odineyes verified"},
            ),
            "severities": _facet(severity_counts),
        },
        "pagination": {
            "page": page, "page_size": page_size,
            "pages": (filtered_total + page_size - 1) // page_size if filtered_total else 0,
            "total": filtered_total,
        },
    }


def _resolve_related_resources(session: Session, asset: Asset) -> list[dict[str, Any]]:
    """Resolve each relationship target_id to the account asset it points at.

    Relationships are stored as {type, target_id} where target_id is a raw
    ARN/short-id (e.g. "sg-0aa..."). The detail view groups these Wiz-style, so
    resolve every target to its asset row (name, type, region, link) when one
    exists, and keep the raw id as an evidence row when it does not (accounts,
    boundary policies, ids outside the scanned inventory).

    ponytail: loads all active account assets once per detail view; fine at
    per-account scale. Add a resource_id index / IN-query if a mega-account
    makes this the hot path.
    """
    rels = asset.relationships or []
    if not rels:
        return []
    rows = session.execute(
        select(Asset).where(Asset.account_id == asset.account_id, Asset.is_active.is_(True))
    ).scalars()
    lookup: dict[str, Asset] = {}
    for row in rows:
        for key in (row.resource_id, row.name, row.resource_id.rsplit("/", 1)[-1]):
            if key:
                lookup.setdefault(str(key), row)
    resolved: list[dict[str, Any]] = []
    for rel in rels:
        target = str(rel.get("target_id") or "")
        match = (
            lookup.get(target)
            or lookup.get(target.rsplit("/", 1)[-1])
            or lookup.get(target.rsplit(":", 1)[-1])
        )
        resolved.append({
            "type": rel.get("type"),
            "target_id": target,
            "asset": {
                "id": match.id,
                "name": match.name or match.resource_id,
                "resource_id": match.resource_id,
                "asset_type": match.asset_type,
                "region": match.region,
                "is_active": match.is_active,
                "cloud_provider": match.cloud_provider,
            } if match else None,
        })
    return resolved


_NETWORK_EVIDENCE_TYPES = (
    "aws.ec2.security_group",
    "aws.ec2.route_table",
    "aws.ec2.network_acl",
    "aws.ec2.internet_gateway",
)


_DATABASE_TYPES = frozenset({
    "aws.rds.db_instance", "aws.rds.db_cluster",
    "aws.redshift.cluster", "aws.docdb.cluster", "aws.neptune.cluster",
})


def _internet_reachability(session: Session, asset: Asset) -> Optional[dict[str, Any]]:
    """Reachability verdict for the resource types that actually terminate a
    network path — a database with a public endpoint, or a public EC2 instance —
    and None for everything else.

    The asset-type gate matters: ``public_endpoint_configured`` also trips on the
    generic ``is_public`` flag, so without it the RDS assessor ran against any
    public non-RDS asset (a security group, bucket, ALB or assumable role) and
    stamped ``rds:DescribeDBInstances`` evidence on it. A security group is not an
    RDS endpoint; it gets no reachability verdict of its own.

    Computed on read, not stored: the verdict derives from the whole account's
    network evidence, so persisting it would make an unchanged resource look like
    it drifted whenever an unrelated route table changed.
    """
    kind = asset.asset_type
    is_db = kind in _DATABASE_TYPES
    is_ec2 = kind == "aws.ec2.instance"
    if not (is_db or is_ec2):
        return None

    props = asset.properties or {}
    if is_db and not public_endpoint_configured(asset):
        return None
    if is_ec2 and not (asset.is_public or props.get("public_ip")):
        return None

    network_assets = list(session.execute(
        select(Asset).where(
            Asset.account_id == asset.account_id,
            Asset.is_active.is_(True),
            Asset.asset_type.in_(_NETWORK_EVIDENCE_TYPES),
        )
    ).scalars())
    topology = build_network_topology(network_assets)

    if is_db:
        return assess_rds_internet_reachability(asset, topology=topology).as_dict()

    # EC2: probe every port its security groups open to the world; the verdict is
    # the best proven path (reachable > unverified > blocked), same as the graph.
    sg_ids = [
        str(rel["target_id"])
        for rel in (asset.relationships or [])
        if rel.get("type") == "USES_SECURITY_GROUP" and rel.get("target_id")
    ] or [str(v) for v in props.get("security_group_ids") or [] if v]
    ports = sorted({
        int(port)
        for sg_id in sg_ids if sg_id in topology.security_groups
        for port in topology.security_groups[sg_id].properties.get("open_ports") or []
    }) or [0]
    assessments = [
        assess_ec2_internet_reachability(asset, 22 if port == 0 else port, topology=topology)
        for port in ports
    ]
    best = (
        next((a for a in assessments if a.status == "reachable"), None)
        or next((a for a in assessments if a.status == "unverified"), None)
        or assessments[0]
    )
    return best.as_dict()


def get_asset(session: Session, asset_id: int, *, event_limit: int = 20) -> Optional[dict[str, Any]]:
    asset = session.get(Asset, asset_id)
    if asset is None:
        return None
    events = session.execute(
        select(AssetEvent)
        .where(AssetEvent.asset_id == asset_id)
        .order_by(AssetEvent.changed_at.desc())
        .limit(event_limit)
    ).scalars()
    data = asset_to_dict(asset, detail=True)
    account = session.get(CloudAccount, asset.account_id)
    data["account"] = {
        "id": account.id,
        "identifier": account.account_identifier,
        "name": account.name,
        "provider": account.provider,
    } if account else None
    data["cloud_console_url"] = _cloud_console_url(asset)
    data["internet_reachability"] = _internet_reachability(session, asset)
    data["related_resources"] = _resolve_related_resources(session, asset)
    # Detailed CIEM evidence for principals; null for non-identity assets so the
    # UI shows the privilege panel only where it means something.
    data["identity"] = (
        identity_ciem_view(asset.properties or {})
        if _asset_taxonomy(asset.asset_type)[0] == "identity" else None
    )

    open_findings = list(session.execute(
        select(Finding)
        .where(
            Finding.account_id == asset.account_id,
            Finding.status == "open",
            or_(Finding.asset_id == asset.id, Finding.resource_id == asset.resource_id),
        )
        .order_by(case(
            (Finding.severity == "critical", 0),
            (Finding.severity == "high", 1),
            (Finding.severity == "medium", 2),
            (Finding.severity == "low", 3),
            else_=4,
        ), Finding.title)
    ).scalars())
    data["findings"] = [
        {
            "id": row.id,
            "rule_id": row.rule_id,
            "title": row.title,
            "severity": row.severity,
            "why": row.why,
            "remediation": row.remediation,
            "compliance": row.compliance,
            "first_seen_at": _iso(row.first_seen_at),
            "last_seen_at": _iso(row.last_seen_at),
        }
        for row in open_findings
    ]

    attack_paths = list(session.execute(
        select(Issue)
        .where(
            Issue.account_id == asset.account_id,
            Issue.status == "open",
            or_(Issue.entry_asset_id == asset.id, Issue.resource_id == asset.resource_id),
        )
        .order_by(Issue.risk_score.desc())
    ).scalars())
    data["attack_paths"] = [
        {
            "id": row.id,
            "title": row.title,
            "severity": row.severity,
            "risk_score": row.risk_score,
            "confidence": row.confidence,
            "actively_exploited": row.actively_exploited,
        }
        for row in attack_paths
    ]

    vuln_rows = list(session.execute(
        select(Vulnerability).where(
            Vulnerability.account_id == asset.account_id,
            Vulnerability.status == "open",
            or_(
                Vulnerability.asset_id == asset.id,
                Vulnerability.resource_id == asset.resource_id,
            ),
        )
    ).scalars())
    vuln_rows.sort(
        key=lambda row: (
            -_maturity(row),
            _SEVERITY_RANK.get((row.severity or "").lower(), 9),
            -(row.cvss or 0.0),
        )
    )
    latest_scan = session.execute(
        select(SecurityScanRun)
        .where(
            SecurityScanRun.account_id == asset.account_id,
            or_(
                SecurityScanRun.asset_id == asset.id,
                SecurityScanRun.resource_id == asset.resource_id,
            ),
        )
        .order_by(SecurityScanRun.scanned_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    severity_counts: dict[str, int] = {}
    for row in vuln_rows:
        severity = (row.severity or "unknown").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    if latest_scan:
        coverage = {
            "status": latest_scan.status,
            "scanner": latest_scan.scanner,
            "scan_kind": latest_scan.scan_kind,
            "scanned_at": _iso(latest_scan.scanned_at),
            "package_count": latest_scan.package_count,
            "findings_count": latest_scan.findings_count,
            "reason": latest_scan.status_reason,
            "evidence": latest_scan.evidence,
        }
    elif vuln_rows:
        coverage = {
            "status": "legacy_evidence",
            "scanner": ", ".join(sorted({row.scanner_source for row in vuln_rows})),
            "scan_kind": None,
            "scanned_at": max((_iso(row.last_seen_at) for row in vuln_rows), default=None),
            "package_count": None,
            "findings_count": len(vuln_rows),
            "reason": "Vulnerability evidence predates scan coverage tracking.",
            "evidence": {},
        }
    else:
        applicable = asset.asset_type == "aws.ec2.instance"
        coverage = {
            "status": "not_scanned" if applicable else "not_applicable",
            "scanner": "ssm-osv" if applicable else None,
            "scan_kind": "host_packages" if applicable else None,
            "scanned_at": None,
            "package_count": None,
            "findings_count": 0,
            "reason": (
                "Run a workload scan. EC2 package inspection requires an online SSM-managed instance."
                if applicable else
                "The current workload scanners do not inspect this resource type."
            ),
            "evidence": {},
        }
    data["vulnerability_posture"] = {
        "coverage": coverage,
        "summary": {
            "open": len(vuln_rows),
            "fixable": sum(1 for row in vuln_rows if row.fixed_version),
            "affected_components": len({
                (row.package, row.installed_version, row.package_type)
                for row in vuln_rows
            }),
            "kev": sum(1 for row in vuln_rows if row.kev),
            "by_severity": severity_counts,
        },
        "components": _vulnerability_components(vuln_rows),
        "items": [vuln_to_dict(row) for row in vuln_rows],
    }
    data["events"] = [
        {
            "event_type": e.event_type,
            "previous_value": e.previous_value,
            "new_value": e.new_value,
            "changed_at": _iso(e.changed_at),
        }
        for e in events
    ]
    return data


def summary(session: Session, *, account_id: Optional[int] = None) -> dict[str, Any]:
    def scoped(stmt):
        stmt = stmt.where(Asset.is_active.is_(True))
        return stmt.where(Asset.account_id == account_id) if account_id is not None else stmt

    total = session.execute(scoped(select(func.count()).select_from(Asset))).scalar_one()
    public = session.execute(
        scoped(select(func.count()).select_from(Asset)).where(Asset.is_public.is_(True))
    ).scalar_one()

    def grouped(column):
        rows = session.execute(
            scoped(select(column, func.count())).group_by(column)
        ).all()
        return {str(k): v for k, v in rows}

    # region -> {asset_type: count} — the per-region service breakdown. "global"
    # is just another key here; the UI splits it out as account-wide services.
    region_type_rows = session.execute(
        scoped(select(Asset.region, Asset.asset_type, func.count()))
        .group_by(Asset.region, Asset.asset_type)
    ).all()
    by_region_type: dict[str, dict[str, int]] = {}
    for region, asset_type, n in region_type_rows:
        by_region_type.setdefault(str(region), {})[str(asset_type)] = n

    return {
        "total_assets": total,
        "public_assets": public,
        "by_type": grouped(Asset.asset_type),
        "by_provider": grouped(Asset.cloud_provider),
        "by_exposure": grouped(Asset.network_exposure),
        "by_region": grouped(Asset.region),
        "by_region_type": by_region_type,
    }


def finding_to_dict(
    f: Finding,
    *,
    risk: Optional[dict[str, Any]] = None,
    dspm: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    d = {
        "id": f.id,
        "account_id": f.account_id,
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity,
        "status": f.status,
        "signal": finding_signal(f.rule_id),
        "suppressed_by": f.suppressed_by,
        "suppressed_why": f.suppressed_why,
        "resource_id": f.resource_id,
        "asset_type": f.asset_type,
        "why": f.why,
        "remediation": f.remediation,
        "remediation_cli": remediation_command(f.rule_id, f.resource_id),
        "compliance": f.compliance,
        "related": f.related,
        "first_seen_at": _iso(f.first_seen_at),
        "last_seen_at": _iso(f.last_seen_at),
        "resolved_at": _iso(f.resolved_at),
    }
    # §4.2 risk weighting + §4.5 DSPM cross-signal — additive, absent when
    # there's no matching asset/DSPM row (older consumers ignore the new keys).
    if risk is not None:
        d["risk_score"] = risk["risk_score"]
        d["exposure"] = risk["exposure"]
        d["elevated"] = risk["elevated"]
    if dspm is not None:
        d["data_sensitivity"] = {
            "label": dspm.get("label", "NONE"),
            "taxonomies": dspm.get("taxonomies") or [],
        }
    return d


def _finding_context(
    session: Session, findings: Sequence[Finding]
) -> tuple[dict[tuple[int, str], str], dict[tuple[int, str], dict[str, Any]]]:
    """Batch-load, for the given accounts: asset network_exposure keyed by
    (account_id, resource_id), and DSPM label/taxonomies keyed by
    (account_id, store_key). Two queries total, not N per finding."""
    exposure: dict[tuple[int, str], str] = {}
    dspm: dict[tuple[int, str], dict[str, Any]] = {}
    account_ids = {finding.account_id for finding in findings}
    if not account_ids:
        return exposure, dspm
    resource_ids = list({finding.resource_id for finding in findings})
    # A filtered findings page should not hydrate every asset in the tenant.
    # Chunking keeps large pages below SQLite's bind-parameter ceiling.
    for start in range(0, len(resource_ids), 400):
        chunk = resource_ids[start:start + 400]
        for aid, rid, exp in session.execute(
            select(Asset.account_id, Asset.resource_id, Asset.network_exposure)
            .where(
                Asset.account_id.in_(account_ids),
                Asset.resource_id.in_(chunk),
            )
        ):
            exposure[(aid, rid)] = exp
    for aid, sid, label, tax in session.execute(
        select(DspmFinding.account_id, DspmFinding.store_id,
               DspmFinding.label, DspmFinding.taxonomies)
        .where(DspmFinding.account_id.in_(account_ids))
    ):
        dspm[(aid, store_key(sid))] = {"label": label, "taxonomies": tax}
    return exposure, dspm


def list_findings(
    session: Session,
    *,
    account_id: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = "open",
    rule_id: Optional[str] = None,
    signal: Optional[str] = None,
) -> dict[str, Any]:
    stmt = select(Finding)
    if account_id is not None:
        stmt = stmt.where(Finding.account_id == account_id)
    if severity is not None:
        stmt = stmt.where(Finding.severity == severity)
    if status is not None:
        stmt = stmt.where(Finding.status == status)
    if rule_id is not None:
        stmt = stmt.where(Finding.rule_id == rule_id)
    if signal == "network_hygiene":
        stmt = stmt.where(Finding.rule_id.in_(NETWORK_HYGIENE_RULES))
    elif signal == "active_threat":
        stmt = stmt.where(Finding.rule_id.notin_(NETWORK_HYGIENE_RULES))

    rows = list(session.execute(stmt).scalars())
    exposure_map, dspm_map = _finding_context(session, rows)

    items = []
    for f in rows:
        exp = exposure_map.get((f.account_id, f.resource_id))
        dspm = dspm_map.get((f.account_id, store_key(f.resource_id)))
        risk = finding_risk(
            f.severity, exposure=exp, data_label=(dspm or {}).get("label"),
        )
        items.append(finding_to_dict(f, risk=risk, dspm=dspm))
    # Rank by computed risk (severity × exposure × data), then severity, stable.
    items.sort(key=lambda d: (
        -d.get("risk_score", 0.0), _SEVERITY_RANK.get(d["severity"], 9),
        d["rule_id"], d["resource_id"],
    ))
    return {"items": items, "total": len(items)}


def issue_to_dict(i: Issue) -> dict[str, Any]:
    return {
        "id": i.id,
        "issue_type": i.issue_type,
        "title": i.title,
        "severity": i.severity,
        "status": i.status,
        "risk_score": i.risk_score,
        "confidence": getattr(i, "confidence", 1.0),
        "evidence_status": getattr(i, "evidence_status", "confirmed"),
        "resource_id": i.resource_id,
        "why": i.why,
        "remediation": i.remediation,
        "path": i.path,
        "compliance": i.compliance,
        "related": i.related,
        "actively_exploited": bool(getattr(i, "actively_exploited", False)),
        "exploit_count": getattr(i, "exploit_count", 0) or 0,
        "last_exploit_at": _iso(getattr(i, "last_exploit_at", None)),
        "first_seen_at": _iso(i.first_seen_at),
        "last_seen_at": _iso(i.last_seen_at),
        "resolved_at": _iso(i.resolved_at),
    }


def exploitation_summary(session: Session, *, account_id: Optional[int] = None) -> dict[str, Any]:
    """Open issues that are being actively exploited (Step-4 correlation)."""
    stmt = select(Issue).where(Issue.status == "open", Issue.actively_exploited.is_(True))
    if account_id is not None:
        stmt = stmt.where(Issue.account_id == account_id)
    rows = list(session.execute(stmt).scalars())
    rows.sort(key=lambda i: (i.last_exploit_at or i.last_seen_at), reverse=True)
    return {
        "items": [issue_to_dict(i) for i in rows],
        "total": len(rows),
    }


def list_issues(
    session: Session,
    *,
    account_id: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = "open",
    issue_type: Optional[str] = None,
) -> dict[str, Any]:
    stmt = select(Issue)
    if account_id is not None:
        stmt = stmt.where(Issue.account_id == account_id)
    if severity is not None:
        stmt = stmt.where(Issue.severity == severity)
    if status is not None:
        stmt = stmt.where(Issue.status == status)
    if issue_type is not None:
        stmt = stmt.where(Issue.issue_type == issue_type)

    rows = list(session.execute(stmt).scalars())
    rows.sort(key=lambda i: (-i.risk_score, _SEVERITY_RANK.get(i.severity, 9), i.issue_type))
    return {"items": [issue_to_dict(i) for i in rows], "total": len(rows)}


def issues_summary(session: Session, *, account_id: Optional[int] = None) -> dict[str, Any]:
    def scoped(stmt):
        return stmt.where(Issue.account_id == account_id) if account_id is not None else stmt

    open_only = lambda stmt: stmt.where(Issue.status == "open")  # noqa: E731

    by_severity = session.execute(
        open_only(scoped(select(Issue.severity, func.count()))).group_by(Issue.severity)
    ).all()
    by_type = session.execute(
        open_only(scoped(select(Issue.issue_type, func.count()))).group_by(Issue.issue_type)
    ).all()
    open_total = session.execute(
        open_only(scoped(select(func.count()).select_from(Issue)))
    ).scalar_one()
    resolved_total = session.execute(
        scoped(select(func.count()).select_from(Issue)).where(Issue.status == "resolved")
    ).scalar_one()
    max_risk = session.execute(
        open_only(scoped(select(func.max(Issue.risk_score))))
    ).scalar_one()

    return {
        "open": open_total,
        "resolved": resolved_total,
        "max_risk": max_risk or 0.0,
        "by_severity": {str(k): v for k, v in by_severity},
        "by_type": {str(k): v for k, v in by_type},
    }


def findings_summary(session: Session, *, account_id: Optional[int] = None) -> dict[str, Any]:
    def scoped(stmt):
        return stmt.where(Finding.account_id == account_id) if account_id is not None else stmt

    open_only = lambda stmt: stmt.where(Finding.status == "open")  # noqa: E731

    by_severity_rows = session.execute(
        open_only(scoped(select(Finding.severity, func.count()))).group_by(Finding.severity)
    ).all()
    by_rule_rows = session.execute(
        open_only(scoped(select(Finding.rule_id, func.count()))).group_by(Finding.rule_id)
    ).all()
    active_threat_by_severity_rows = session.execute(
        open_only(scoped(select(Finding.severity, func.count())))
        .where(Finding.rule_id.notin_(NETWORK_HYGIENE_RULES))
        .group_by(Finding.severity)
    ).all()
    open_total = session.execute(
        open_only(scoped(select(func.count()).select_from(Finding)))
    ).scalar_one()
    resolved_total = session.execute(
        scoped(select(func.count()).select_from(Finding)).where(Finding.status == "resolved")
    ).scalar_one()
    suppressed_total = session.execute(
        scoped(select(func.count()).select_from(Finding)).where(Finding.status == "suppressed")
    ).scalar_one()
    network_hygiene_total = session.execute(
        open_only(scoped(select(func.count()).select_from(Finding)))
        .where(Finding.rule_id.in_(NETWORK_HYGIENE_RULES))
    ).scalar_one()
    active_threat_total = open_total - network_hygiene_total
    active_threat_by_rule = {
        str(rule): count for rule, count in by_rule_rows if rule not in NETWORK_HYGIENE_RULES
    }
    network_hygiene_by_rule = {
        str(rule): count for rule, count in by_rule_rows if rule in NETWORK_HYGIENE_RULES
    }

    return {
        "open": open_total,
        "active_threats": active_threat_total,
        "network_hygiene": network_hygiene_total,
        "resolved": resolved_total,
        "suppressed": suppressed_total,
        "by_severity": {str(k): v for k, v in by_severity_rows},
        "active_threat_by_severity": {str(k): v for k, v in active_threat_by_severity_rows},
        "by_rule": {str(k): v for k, v in by_rule_rows},
        "active_threat_by_rule": active_threat_by_rule,
        "network_hygiene_by_rule": network_hygiene_by_rule,
    }


def list_modeled_findings(
    session: Session,
    *,
    account_id: Optional[int] = None,
    query: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = "open",
    rule_id: Optional[str] = None,
    category: Optional[str] = None,
    service: Optional[str] = None,
    signal: Optional[str] = None,
    sort: str = "risk",
    direction: str = "desc",
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    """Modeled finding read view with contextual risk and stable facets."""
    page = max(page, 1)
    page_size = min(max(page_size, 1), 200)
    all_items = list_findings(session, account_id=account_id, status=None)["items"]

    severity_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    service_counts: dict[str, int] = {}
    signal_counts: dict[str, int] = {}
    for item in all_items:
        item_category, item_service, _kind = _asset_taxonomy(item["asset_type"])
        severity_counts[item["severity"]] = severity_counts.get(item["severity"], 0) + 1
        status_counts[item["status"]] = status_counts.get(item["status"], 0) + 1
        rule_counts[item["rule_id"]] = rule_counts.get(item["rule_id"], 0) + 1
        category_counts[item_category] = category_counts.get(item_category, 0) + 1
        service_counts[item_service] = service_counts.get(item_service, 0) + 1
        signal_counts[item["signal"]] = signal_counts.get(item["signal"], 0) + 1

    needle = (query or "").strip().lower()
    filtered = []
    for item in all_items:
        item_category, item_service, _kind = _asset_taxonomy(item["asset_type"])
        if status and item["status"] != status:
            continue
        if severity and item["severity"] != severity:
            continue
        if rule_id and item["rule_id"] != rule_id:
            continue
        if category and item_category != category:
            continue
        if service and item_service != service:
            continue
        if signal and item["signal"] != signal:
            continue
        if needle and needle not in " ".join((
            item["title"], item["rule_id"], item["resource_id"], item["asset_type"],
        )).lower():
            continue
        filtered.append(item)

    sort_keys = {
        "risk": lambda item: float(item.get("risk_score", 0)),
        "severity": lambda item: -_SEVERITY_RANK.get(item["severity"], 9),
        "last_seen": lambda item: item.get("last_seen_at") or "",
        "title": lambda item: item["title"].lower(),
    }
    reverse = direction == "desc"
    filtered.sort(key=sort_keys.get(sort, sort_keys["risk"]), reverse=reverse)
    filtered_total = len(filtered)
    page_items = filtered[(page - 1) * page_size:page * page_size]

    account_ids = {int(item["account_id"]) for item in page_items}
    account_names = {
        account.id: account.name or account.account_identifier
        for account in session.execute(select(CloudAccount).where(CloudAccount.id.in_(account_ids))).scalars()
    } if account_ids else {}
    resource_ids = {item["resource_id"] for item in page_items}
    asset_map = {
        (asset.account_id, asset.resource_id): asset
        for asset in session.execute(
            select(Asset).where(Asset.account_id.in_(account_ids), Asset.resource_id.in_(resource_ids))
        ).scalars()
    } if resource_ids else {}

    modeled = []
    for item in page_items:
        finding_account_id = int(item["account_id"])
        asset = asset_map.get((finding_account_id, item["resource_id"]))
        item_category, item_service, _kind = _asset_taxonomy(item["asset_type"])
        sensitivity = item.get("data_sensitivity")
        modeled.append({
            "id": item["id"],
            "verdict": {
                "title": item["title"], "rule_id": item["rule_id"], "category": item_category,
                "signal": item["signal"],
            },
            "resource": {
                "resource_id": item["resource_id"],
                "name": (asset.name if asset is not None else None) or item["resource_id"],
                "asset_type": item["asset_type"],
                "provider": asset.cloud_provider if asset is not None else item["asset_type"].split(".", 1)[0],
                "service": item_service,
                "account_id": finding_account_id,
                "account_name": account_names.get(finding_account_id),
            },
            "posture": {
                "severity": item["severity"],
                "status": item["status"],
                "risk_score": float(item.get("risk_score", 0)),
                "exposure": item.get("exposure") or "unknown",
                "elevated": bool(item.get("elevated", False)),
                "data_sensitivity": sensitivity,
            },
            "evidence": {
                "why": item["why"],
                "compliance": item.get("compliance") or {},
                "related_resources": item.get("related") or [],
                "suppressed_by": item.get("suppressed_by"),
                "suppressed_why": item.get("suppressed_why"),
            },
            "remediation": {
                "guidance": item["remediation"], "cli": item.get("remediation_cli") or None,
            },
            "lifecycle": {
                "first_seen_at": item.get("first_seen_at"),
                "last_seen_at": item.get("last_seen_at"),
                "resolved_at": item.get("resolved_at"),
            },
        })

    open_items = [item for item in all_items if item["status"] == "open"]
    resolved_items = [item for item in all_items if item["status"] == "resolved"]
    suppressed_items = [item for item in all_items if item["status"] == "suppressed"]
    active_threat_items = [
        item for item in open_items if item["signal"] == "active_threat"
    ]
    network_hygiene_items = [
        item for item in open_items if item["signal"] == "network_hygiene"
    ]
    return {
        "schema_version": "1.0",
        "items": modeled,
        "totals": {
            "open": len(open_items),
            "resolved": len(resolved_items),
            "suppressed": len(suppressed_items),
            "active_threats": len(active_threat_items),
            "network_hygiene": len(network_hygiene_items),
            # Hygiene cannot inflate the primary decision KPIs. It remains
            # visible through its own total and filter.
            "critical": sum(item["severity"] == "critical" for item in active_threat_items),
            "elevated": sum(
                bool(item.get("elevated", False)) for item in active_threat_items
            ),
            "filtered": filtered_total,
        },
        "facets": {
            "severities": _facet(severity_counts),
            "statuses": _facet(status_counts),
            "rules": _facet(rule_counts),
            "categories": _facet(category_counts, labels=_CATEGORY_LABELS),
            "services": _facet(service_counts),
            "signals": _facet(signal_counts, labels={
                "active_threat": "Active threats",
                "network_hygiene": "Network hygiene",
            }),
        },
        "pagination": {
            "page": page, "page_size": page_size,
            "pages": (filtered_total + page_size - 1) // page_size if filtered_total else 0,
            "total": filtered_total,
        },
    }


# ── vulnerabilities (CWPP) ─────────────────────────────────────

def vuln_to_dict(v: Vulnerability) -> dict[str, Any]:
    epss = getattr(v, "epss", None)
    kev = bool(getattr(v, "kev", False))
    return {
        "id": v.id,
        "resource_id": v.resource_id,
        "cve_id": v.cve_id,
        "package": v.package,
        "installed_version": v.installed_version,
        "severity": v.severity,
        "cvss": v.cvss,
        "summary": v.summary,
        "fixed_version": v.fixed_version,
        "scanner_source": getattr(v, "scanner_source", "ssm-osv"),
        "package_type": getattr(v, "package_type", None),
        "target": getattr(v, "target", None),
        "package_path": getattr(v, "package_path", None),
        "epss": epss,
        "epss_percentile": getattr(v, "epss_percentile", None),
        "kev": kev,
        # exploit_maturity 0–1: KEV is ground-truth (1.0), else EPSS probability.
        "exploit_maturity": 1.0 if kev else float(epss or 0.0),
        "status": v.status,
        "first_seen_at": _iso(v.first_seen_at),
        "last_seen_at": _iso(v.last_seen_at),
        "resolved_at": _iso(v.resolved_at),
    }


# A vuln is "exploitable now" if it's KEV or has a high EPSS probability.
_EPSS_HOT = 0.5


def _maturity(v: Vulnerability) -> float:
    return 1.0 if getattr(v, "kev", False) else float(getattr(v, "epss", None) or 0.0)


def list_vulnerabilities(
    session: Session,
    *,
    account_id: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = "open",
    resource_id: Optional[str] = None,
) -> dict[str, Any]:
    stmt = select(Vulnerability)
    if account_id is not None:
        stmt = stmt.where(Vulnerability.account_id == account_id)
    if severity is not None:
        stmt = stmt.where(Vulnerability.severity == severity)
    if status is not None:
        stmt = stmt.where(Vulnerability.status == status)
    if resource_id is not None:
        stmt = stmt.where(Vulnerability.resource_id == resource_id)

    rows = list(session.execute(stmt).scalars())
    # Prioritize by exploit_maturity first (KEV / high EPSS to the top — the
    # Wiz insight: a weaponized 7.5 outranks a theoretical 9.8), then severity.
    rows.sort(key=lambda v: (-_maturity(v), _SEVERITY_RANK.get((v.severity or "").lower(), 9), -(v.cvss or 0.0)))

    # Enrich from the NVD catalog (one batched lookup): CVSS vector + CWEs the
    # per-asset finding doesn't carry, and description/cvss fallbacks.
    cve_ids = {v.cve_id for v in rows if v.cve_id}
    catalog: dict[str, CveCatalog] = {}
    if cve_ids:
        catalog = {
            c.cve_id: c
            for c in session.execute(select(CveCatalog).where(CveCatalog.cve_id.in_(cve_ids))).scalars()
        }
    items = []
    for v in rows:
        d = vuln_to_dict(v)
        c = catalog.get(v.cve_id)
        if c:
            d["cvss_vector"] = c.cvss_vector
            d["cwes"] = c.cwes or []
            d["nvd_url"] = f"https://nvd.nist.gov/vuln/detail/{c.cve_id}"
            d.setdefault("summary", None)
            if not d.get("summary"):
                d["summary"] = c.description
            if d.get("cvss") is None:
                d["cvss"] = c.cvss_score
        items.append(d)
    return {"items": items, "total": len(items)}


def vulnerabilities_summary(session: Session, *, account_id: Optional[int] = None) -> dict[str, Any]:
    def scoped(stmt):
        return stmt.where(Vulnerability.account_id == account_id) if account_id is not None else stmt

    open_only = lambda stmt: stmt.where(Vulnerability.status == "open")  # noqa: E731

    by_severity = session.execute(
        open_only(scoped(select(Vulnerability.severity, func.count()))).group_by(Vulnerability.severity)
    ).all()
    open_total = session.execute(
        open_only(scoped(select(func.count()).select_from(Vulnerability)))
    ).scalar_one()
    affected = session.execute(
        open_only(scoped(select(func.count(func.distinct(Vulnerability.resource_id)))))
    ).scalar_one()
    kev_count = session.execute(
        open_only(scoped(select(func.count()).select_from(Vulnerability))).where(Vulnerability.kev.is_(True))
    ).scalar_one()
    high_epss = session.execute(
        open_only(scoped(select(func.count()).select_from(Vulnerability))).where(Vulnerability.epss >= _EPSS_HOT)
    ).scalar_one()
    return {
        "open": open_total,
        "affected_assets": affected,
        "by_severity": {str(k).lower(): v for k, v in by_severity},
        "kev": kev_count,
        "high_epss": high_epss,
    }


# ── NVD CVE catalog (browse the full CVE dictionary) ───────────

def cve_to_dict(c: CveCatalog, *, full: bool = False) -> dict[str, Any]:
    d = {
        "cve_id": c.cve_id,
        "severity": c.cvss_severity,
        "cvss_score": c.cvss_score,
        "cvss_version": c.cvss_version,
        "description": c.description,
        "published": _iso(c.published),
        "last_modified": _iso(c.last_modified),
    }
    if full:  # detail view adds vector, weaknesses, references
        d.update({
            "cvss_vector": c.cvss_vector,
            "cwes": c.cwes or [],
            "refs": c.refs or [],
            "source": c.source,
        })
    return d


def list_cve_catalog(
    session: Session,
    *,
    severity: Optional[str] = None,
    keyword: Optional[str] = None,
    since: Optional[datetime] = None,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    """Server-side paginated browse over the full CVE catalog — the no-latency
    path: filter + sort + LIMIT/OFFSET run in the DB on indexed columns, so the
    tab never loads more than one page regardless of catalog size."""
    stmt = select(CveCatalog)
    count_stmt = select(func.count()).select_from(CveCatalog)
    if severity is not None:
        cond = CveCatalog.cvss_severity == severity.lower()
        stmt, count_stmt = stmt.where(cond), count_stmt.where(cond)
    if since is not None:
        cond = CveCatalog.last_modified >= since
        stmt, count_stmt = stmt.where(cond), count_stmt.where(cond)
    if keyword:
        # portable substring match (sqlite + Postgres); a pg_trgm/FTS index can
        # be layered on later if keyword search becomes the hot path.
        like = f"%{keyword}%"
        cond = CveCatalog.cve_id.ilike(like) | CveCatalog.description.ilike(like)
        stmt, count_stmt = stmt.where(cond), count_stmt.where(cond)

    total = session.execute(count_stmt).scalar_one()
    page = max(1, page)
    page_size = max(1, min(page_size, 200))
    # newest-modified first — most relevant for a security browse.
    stmt = stmt.order_by(CveCatalog.last_modified.desc().nullslast()).limit(page_size).offset((page - 1) * page_size)
    rows = list(session.execute(stmt).scalars())
    return {
        "items": [cve_to_dict(c) for c in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


def get_cve(session: Session, cve_id: str) -> Optional[dict[str, Any]]:
    c = session.get(CveCatalog, cve_id.upper())
    return cve_to_dict(c, full=True) if c else None


def cve_catalog_summary(session: Session) -> dict[str, Any]:
    total = session.execute(select(func.count()).select_from(CveCatalog)).scalar_one()
    by_sev = session.execute(
        select(CveCatalog.cvss_severity, func.count()).group_by(CveCatalog.cvss_severity)
    ).all()
    return {
        "total": total,
        "by_severity": {str(k).lower(): v for k, v in by_sev if k},
    }


# ── persisted graph edges (attack-path backbone, with history) ──

def edge_to_dict(e: GraphEdge) -> dict[str, Any]:
    return {
        "source": e.src_id, "target": e.dst_id, "type": e.edge_type,
        "properties": e.properties or {}, "is_active": e.is_active,
        "first_seen_at": _iso(e.first_seen_at), "last_seen_at": _iso(e.last_seen_at),
    }


def list_graph_edges(
    session: Session, *, account_id: Optional[int] = None,
    edge_type: Optional[str] = None, src_id: Optional[str] = None,
    is_active: Optional[bool] = True,
) -> dict[str, Any]:
    stmt = select(GraphEdge)
    if account_id is not None:
        stmt = stmt.where(GraphEdge.account_id == account_id)
    if edge_type is not None:
        stmt = stmt.where(GraphEdge.edge_type == edge_type)
    if src_id is not None:
        stmt = stmt.where(GraphEdge.src_id == src_id)
    if is_active is not None:
        stmt = stmt.where(GraphEdge.is_active.is_(is_active))
    rows = list(session.execute(stmt).scalars())
    return {"items": [edge_to_dict(e) for e in rows], "total": len(rows)}


# ── persisted DSPM findings (data-sensitivity per store) ────────

def dspm_to_dict(d: DspmFinding) -> dict[str, Any]:
    return {
        "store_id": d.store_id, "store_name": d.store_name, "store_type": d.store_type,
        "label": d.label, "data_types": d.data_types or [], "taxonomies": d.taxonomies or [],
        "frameworks": d.frameworks or [], "posture_findings": d.posture_findings or [],
        "record_estimate": d.record_estimate, "objects_sampled": d.objects_sampled,
        "sensitivity_score": d.sensitivity_score, "exposure_score": d.exposure_score,
        "risk_score": d.risk_score, "public": d.public,
        "first_seen_at": _iso(d.first_seen_at), "last_seen_at": _iso(d.last_seen_at),
    }


_DSPM_LABEL_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


def list_dspm(
    session: Session, *, account_id: Optional[int] = None,
    label: Optional[str] = None, store_type: Optional[str] = None,
) -> dict[str, Any]:
    stmt = select(DspmFinding)
    if account_id is not None:
        stmt = stmt.where(DspmFinding.account_id == account_id)
    if label is not None:
        stmt = stmt.where(DspmFinding.label == label.upper())
    if store_type is not None:
        stmt = stmt.where(DspmFinding.store_type == store_type)
    rows = list(session.execute(stmt).scalars())
    rows.sort(key=lambda d: (_DSPM_LABEL_RANK.get((d.label or "none").lower(), 9), -d.risk_score))
    return {"items": [dspm_to_dict(d) for d in rows], "total": len(rows)}


def dspm_summary(session: Session, *, account_id: Optional[int] = None) -> dict[str, Any]:
    def scoped(stmt):
        return stmt.where(DspmFinding.account_id == account_id) if account_id is not None else stmt

    total = session.execute(scoped(select(func.count()).select_from(DspmFinding))).scalar_one()
    by_label = session.execute(
        scoped(select(DspmFinding.label, func.count())).group_by(DspmFinding.label)
    ).all()
    public_sensitive = session.execute(
        scoped(select(func.count()).select_from(DspmFinding))
        .where(DspmFinding.public.is_(True)).where(DspmFinding.label.in_(["CRITICAL", "HIGH"]))
    ).scalar_one()
    return {
        "total": total,
        "by_label": {str(k).lower(): v for k, v in by_label if k},
        "public_sensitive": public_sensitive,
    }


def _vulnerability_components(rows: Sequence[Vulnerability]) -> list[dict[str, Any]]:
    """Group per-CVE rows into remediation-oriented package components."""
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (
            row.package,
            row.installed_version or "",
            getattr(row, "package_type", None) or "unknown",
        )
        group = grouped.setdefault(key, {
            "package": row.package,
            "installed_version": row.installed_version,
            "package_type": getattr(row, "package_type", None),
            "fixed_versions": set(),
            "paths": set(),
            "targets": set(),
            "scanner_sources": set(),
            "vulnerability_count": 0,
            "fixable_count": 0,
            "by_severity": {},
        })
        group["vulnerability_count"] += 1
        if row.fixed_version:
            group["fixable_count"] += 1
            group["fixed_versions"].add(row.fixed_version)
        if getattr(row, "package_path", None):
            group["paths"].add(row.package_path)
        if getattr(row, "target", None):
            group["targets"].add(row.target)
        group["scanner_sources"].add(getattr(row, "scanner_source", "ssm-osv"))
        severity = (row.severity or "unknown").lower()
        group["by_severity"][severity] = group["by_severity"].get(severity, 0) + 1

    components = []
    for group in grouped.values():
        components.append({
            **group,
            "fixed_versions": sorted(group["fixed_versions"]),
            "paths": sorted(group["paths"]),
            "targets": sorted(group["targets"]),
            "scanner_sources": sorted(group["scanner_sources"]),
        })
    components.sort(key=lambda group: (
        -group["by_severity"].get("critical", 0),
        -group["by_severity"].get("high", 0),
        -group["vulnerability_count"],
        group["package"].lower(),
    ))
    return components


def list_data_security_resources(
    session: Session,
    *,
    provider: Optional[str] = None,
    account_id: Optional[int] = None,
    query: Optional[str] = None,
    service: Optional[str] = None,
    store_type: Optional[str] = None,
    label: Optional[str] = None,
    region: Optional[str] = None,
    exposure: Optional[str] = None,
    min_risk: Optional[float] = None,
    sort: str = "risk",
    direction: str = "desc",
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    """Unified inventory + DSPM data-store model.

    Inventory-only stores remain visible as unclassified instead of disappearing
    until DSPM sampling succeeds.
    """
    page = max(page, 1)
    page_size = min(max(page_size, 1), 200)
    scope = [Asset.is_active.is_(True)]
    if provider:
        scope.append(Asset.cloud_provider == provider)
    if account_id is not None:
        scope.append(Asset.account_id == account_id)
    available_types = list(session.execute(select(Asset.asset_type).where(*scope).distinct()).scalars())
    data_types = [asset_type for asset_type in available_types if _asset_taxonomy(asset_type)[0] == "data"]
    stmt = select(Asset).where(*scope, Asset.asset_type.in_(data_types))
    if query and query.strip():
        needle = f"%{query.strip().lower()}%"
        stmt = stmt.where(or_(
            func.lower(func.coalesce(Asset.name, "")).like(needle),
            func.lower(Asset.resource_id).like(needle),
            func.lower(Asset.asset_type).like(needle),
        ))
    assets = list(session.execute(stmt).scalars())
    account_ids = {asset.account_id for asset in assets}
    account_names = {
        account.id: account.name or account.account_identifier
        for account in session.execute(select(CloudAccount).where(CloudAccount.id.in_(account_ids))).scalars()
    } if account_ids else {}
    dspm_map = {
        (finding.account_id, store_key(finding.store_id)): finding
        for finding in session.execute(
            select(DspmFinding).where(DspmFinding.account_id.in_(account_ids))
        ).scalars()
    } if account_ids else {}
    resource_ids = {asset.resource_id for asset in assets}
    finding_counts: dict[tuple[int, str], int] = {}
    if resource_ids:
        for aid, rid, count in session.execute(
            select(Finding.account_id, Finding.resource_id, func.count())
            .where(Finding.status == "open", Finding.account_id.in_(account_ids), Finding.resource_id.in_(resource_ids))
            .group_by(Finding.account_id, Finding.resource_id)
        ):
            finding_counts[(aid, rid)] = int(count)

    modeled: list[dict[str, Any]] = []
    for asset in assets:
        _category, item_service, kind = _asset_taxonomy(asset.asset_type)
        dspm = dspm_map.get((asset.account_id, store_key(asset.resource_id)))
        classification_label = (dspm.label if dspm is not None else "UNCLASSIFIED") or "UNCLASSIFIED"
        classified = dspm is not None
        dspm_risk = _normalized_score(dspm.risk_score) if dspm is not None else 0.0
        risk = max(_normalized_score(asset.risk_score), dspm_risk)
        public = bool(asset.is_public or (dspm.public if dspm is not None else False))
        item_exposure = "public" if public else asset.network_exposure
        encryption = "unknown" if asset.encryption_enabled is None else "enabled" if asset.encryption_enabled else "disabled"
        modeled.append({
            "id": asset.id,
            "identity": {
                "name": asset.name or asset.resource_id,
                "resource_id": asset.resource_id,
                "provider": asset.cloud_provider,
                "account_id": asset.account_id,
                "account_name": account_names.get(asset.account_id),
                "asset_type": asset.asset_type,
                "service": item_service,
                "store_type": (dspm.store_type if dspm is not None else kind).upper(),
                "region": asset.region,
            },
            "classification": {
                "status": "classified" if classified else "unclassified",
                "label": classification_label.lower(),
                "data_types": list(dspm.data_types or []) if dspm is not None else [],
                "taxonomies": list(dspm.taxonomies or []) if dspm is not None else [],
                "frameworks": list(dspm.frameworks or []) if dspm is not None else [],
                "sensitivity_score": float(dspm.sensitivity_score or 0) if dspm is not None else 0.0,
                "records_estimated": int(dspm.record_estimate or 0) if dspm is not None else 0,
                "objects_sampled": int(dspm.objects_sampled or 0) if dspm is not None else 0,
            },
            "protection": {
                "public": public,
                "exposure": item_exposure,
                "encryption": encryption,
                "posture_findings": list(dspm.posture_findings or []) if dspm is not None else [],
            },
            "risk": {
                "score": risk,
                "severity": _risk_severity(risk, {}),
                "open_findings": finding_counts.get((asset.account_id, asset.resource_id), 0),
            },
            "lifecycle": {
                "first_seen_at": _iso(dspm.first_seen_at if dspm is not None else asset.first_seen_at),
                "last_seen_at": _iso(dspm.last_seen_at if dspm is not None else asset.last_scanned_at),
            },
            "metadata": {"tags": asset.tags or {}, "properties": asset.properties or {}},
        })

    service_counts: dict[str, int] = {}
    store_counts: dict[str, int] = {}
    label_counts: dict[str, int] = {}
    region_counts: dict[str, int] = {}
    exposure_counts: dict[str, int] = {}
    for item in modeled:
        for counts, value in (
            (service_counts, item["identity"]["service"]),
            (store_counts, item["identity"]["store_type"]),
            (label_counts, item["classification"]["label"]),
            (region_counts, item["identity"]["region"]),
            (exposure_counts, item["protection"]["exposure"]),
        ):
            counts[value] = counts.get(value, 0) + 1

    filtered = [item for item in modeled if (
        (not service or item["identity"]["service"] == service)
        and (not store_type or item["identity"]["store_type"].lower() == store_type.lower())
        and (not label or item["classification"]["label"] == label.lower())
        and (not region or item["identity"]["region"] == region)
        and (not exposure or item["protection"]["exposure"] == exposure)
        and (min_risk is None or item["risk"]["score"] >= min_risk)
    )]
    sort_keys = {
        "risk": lambda item: item["risk"]["score"],
        "name": lambda item: item["identity"]["name"].lower(),
        "sensitivity": lambda item: item["classification"]["sensitivity_score"],
        "last_seen": lambda item: item["lifecycle"]["last_seen_at"] or "",
    }
    filtered.sort(key=sort_keys.get(sort, sort_keys["risk"]), reverse=direction == "desc")
    filtered_total = len(filtered)
    items = filtered[(page - 1) * page_size:page * page_size]
    return {
        "schema_version": "1.0",
        "items": items,
        "totals": {
            "stores": len(modeled),
            "classified": sum(item["classification"]["status"] == "classified" for item in modeled),
            "public": sum(item["protection"]["public"] for item in modeled),
            "unencrypted": sum(item["protection"]["encryption"] == "disabled" for item in modeled),
            "sensitive": sum(item["classification"]["label"] in {"critical", "high"} for item in modeled),
            "filtered": filtered_total,
        },
        "facets": {
            "services": _facet(service_counts),
            "store_types": _facet(store_counts),
            "labels": _facet(label_counts),
            "regions": _facet(region_counts, labels={"global": "Global"}),
            "exposures": _facet(exposure_counts),
        },
        "pagination": {
            "page": page, "page_size": page_size,
            "pages": (filtered_total + page_size - 1) // page_size if filtered_total else 0,
            "total": filtered_total,
        },
    }


# ── runtime / threat events ────────────────────────────────────

def runtime_event_to_dict(e: RuntimeEvent) -> dict[str, Any]:
    raw = e.raw or {}
    # Lineage/enrichment fields live in the raw sensor payload; surface the
    # ones the Threats process-tree view needs (parent/child + container).
    return {
        "id": e.id,
        "event_type": e.event_type,
        "severity": e.severity,
        "resource_id": e.resource_id,
        "workload": e.workload,
        "process": e.process,
        "pid": e.pid,
        "summary": e.summary,
        "count": getattr(e, "count", 1) or 1,
        "observed_at": _iso(e.observed_at),
        "comm": raw.get("comm"),
        "command": raw.get("command"),
        "parent": raw.get("parent"),
        "ppid": raw.get("ppid"),
        "lineage": raw.get("lineage"),
        "container": raw.get("container"),
        "dest": raw.get("dest"),
        "node": raw.get("node"),
        # Detection-engine metadata (present when the event came from a fired
        # rule/sequence/anomaly in sensor.detection); None for raw signals.
        "rule_id": raw.get("rule_id"),
        "rule_name": raw.get("rule_name"),
        "tactic": raw.get("tactic"),
        "technique": raw.get("technique"),
        "benign": bool(raw.get("benign", False)),
        "simulated": bool(raw.get("simulated", False)),
    }


def list_runtime_events(
    session: Session,
    *,
    account_id: Optional[int] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 200,
) -> dict[str, Any]:
    stmt = select(RuntimeEvent)
    if account_id is not None:
        stmt = stmt.where(RuntimeEvent.account_id == account_id)
    if event_type is not None:
        stmt = stmt.where(RuntimeEvent.event_type == event_type)
    if severity is not None:
        stmt = stmt.where(RuntimeEvent.severity == severity)
    stmt = stmt.order_by(RuntimeEvent.observed_at.desc()).limit(limit)
    rows = list(session.execute(stmt).scalars())
    return {"items": [runtime_event_to_dict(e) for e in rows], "total": len(rows)}


def list_runtime_findings(
    session: Session,
    *,
    account_id: Optional[int] = None,
    host_id: Optional[str] = None,
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    since: Optional[Any] = None,   # datetime
    limit: int = 500,
) -> dict[str, Any]:
    """Runtime events that are *detection findings* — i.e. they carry a
    ``rule_id`` from sensor.detection (rules / sequences / anomalies). The
    rule_id lives in the JSON ``raw`` blob, so narrow in SQL on the indexed
    columns and filter the rule predicate in Python (portable across sqlite/PG).
    """
    stmt = select(RuntimeEvent)
    if account_id is not None:
        stmt = stmt.where(RuntimeEvent.account_id == account_id)
    if host_id:
        stmt = stmt.where(RuntimeEvent.resource_id == host_id)
    if severity:
        stmt = stmt.where(RuntimeEvent.severity == severity)
    if since is not None:
        stmt = stmt.where(RuntimeEvent.observed_at >= since)
    stmt = stmt.order_by(RuntimeEvent.observed_at.desc()).limit(limit * 5)
    items: list[dict[str, Any]] = []
    for e in session.execute(stmt).scalars():
        d = runtime_event_to_dict(e)
        if not d.get("rule_id"):
            continue
        if rule_id and d["rule_id"] != rule_id:
            continue
        items.append(d)
        if len(items) >= limit:
            break
    return {"items": items, "total": len(items)}


# ── eBPF sensor agents (derived: EC2 inventory ∪ runtime-event hosts) ──────────
# There is no agent-registration table; an "agent" is a host that either could run
# the sensor (an EC2 instance in inventory) or has reported runtime events. OS comes
# from the matching EC2 asset's raw PlatformDetails — eBPF is Linux-only, so Windows
# /other hosts are surfaced honestly as 'unsupported', not silently missing.
# ponytail: derived on read. If sensors ever self-register (POST hostname/os/version
# /uptime), persist an Agent row and read that instead — the shape here is the target.

_INSTANCE_RE = re.compile(r"(i-[0-9a-f]{8,17})")


def _host_key(s: Optional[str]) -> Optional[str]:
    """Collapse an ARN / node name / bare id to a stable host key (the instance id
    when present, so a runtime event's host matches its EC2 asset)."""
    if not s:
        return None
    m = _INSTANCE_RE.search(s)
    return m.group(1) if m else s


def _os_of(raw: dict[str, Any]) -> tuple[str, str]:
    """(os_family, os_detail) from an EC2 raw dict. Platform=='windows' or a
    'Windows' PlatformDetails ⇒ windows; otherwise linux (carry the detail label)."""
    detail = raw.get("PlatformDetails") or ""
    if str(raw.get("Platform", "")).lower() == "windows" or "windows" in detail.lower():
        return "windows", detail or "Windows"
    return "linux", detail or "Linux/UNIX"


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def runtime_agents(
    session: Session, *, account_id: Optional[int] = None, fresh_minutes: int = 60,
) -> dict[str, Any]:
    """Sensor agents grouped by OS platform with deployment/liveness status:
      online       runtime events seen within ``fresh_minutes``
      stale        has events, but none recently (sensor may be offline)
      no_sensor    Linux EC2 host with no runtime data (sensor not deployed)
      unsupported  Windows/other host — eBPF can't run there
    """
    agents: dict[str, dict[str, Any]] = {}

    # Candidate hosts = EC2 instances (the things a sensor could run on).
    a_stmt = select(Asset).where(
        Asset.is_active.is_(True), Asset.asset_type == "aws.ec2.instance")
    if account_id is not None:
        a_stmt = a_stmt.where(Asset.account_id == account_id)
    for a in session.execute(a_stmt).scalars():
        key = _host_key(a.resource_id) or a.resource_id
        os_family, os_detail = _os_of(a.raw or {})
        agents[key] = {
            "host": key, "name": a.name, "region": a.region,
            "resource_id": a.resource_id, "os": os_family, "os_detail": os_detail,
            "ebpf_supported": os_family == "linux",
            "events": 0, "findings": 0, "last_seen": None, "status": None,
            "_last": None,
        }

    # Overlay runtime activity. Bounded scan (newest first) — burst control already
    # collapses floods, so the row count here is sane.
    r_stmt = select(RuntimeEvent).order_by(RuntimeEvent.observed_at.desc()).limit(5000)
    if account_id is not None:
        r_stmt = r_stmt.where(RuntimeEvent.account_id == account_id)
    for e in session.execute(r_stmt).scalars():
        key = _host_key(e.resource_id)
        if key is None:
            continue
        ag = agents.get(key)
        if ag is None:  # reported a sensor but isn't an EC2 asset we inventoried
            ag = {
                "host": key, "name": e.workload or key, "region": None,
                "resource_id": e.resource_id, "os": "unknown", "os_detail": "unknown",
                "ebpf_supported": True, "events": 0, "findings": 0,
                "last_seen": None, "status": None, "_last": None,
            }
            agents[key] = ag
        n = getattr(e, "count", 1) or 1
        ag["events"] += n
        if (e.raw or {}).get("rule_id"):
            ag["findings"] += n
        ts = _aware(e.observed_at)
        if ts and (ag["_last"] is None or ts > ag["_last"]):
            ag["_last"] = ts

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=fresh_minutes)
    for ag in agents.values():
        if ag["events"] > 0:
            ag["status"] = "online" if (ag["_last"] and ag["_last"] >= cutoff) else "stale"
        elif not ag["ebpf_supported"]:
            ag["status"] = "unsupported"
        else:
            ag["status"] = "no_sensor"
        ag["last_seen"] = ag["_last"].isoformat() if ag["_last"] else None
        del ag["_last"]

    items = sorted(agents.values(), key=lambda x: (x["os"], -x["events"], x["host"]))
    by_os: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for ag in items:
        by_os[ag["os"]] = by_os.get(ag["os"], 0) + 1
        by_status[ag["status"]] = by_status.get(ag["status"], 0) + 1
    return {"items": items, "by_os": by_os, "by_status": by_status, "total": len(items)}


def runtime_events_summary(session: Session, *, account_id: Optional[int] = None) -> dict[str, Any]:
    def scoped(stmt):
        return stmt.where(RuntimeEvent.account_id == account_id) if account_id is not None else stmt

    by_type = session.execute(
        scoped(select(RuntimeEvent.event_type, func.count())).group_by(RuntimeEvent.event_type)
    ).all()
    by_severity = session.execute(
        scoped(select(RuntimeEvent.severity, func.count())).group_by(RuntimeEvent.severity)
    ).all()
    total = session.execute(scoped(select(func.count()).select_from(RuntimeEvent))).scalar_one()
    return {
        "total": total,
        "by_type": {str(k): v for k, v in by_type},
        "by_severity": {str(k): v for k, v in by_severity},
    }


# ── continuous compliance (snapshots + drift) ──────────────────

def _snapshot_to_dict(s: ComplianceSnapshot) -> dict[str, Any]:
    return {
        "framework": s.framework,
        "version": s.version,
        "account": s.account,
        "region": s.region,
        "score": s.score,
        "passing": s.passing,
        "total": s.total,
        "not_assessed": s.not_assessed,
        "origin": s.origin,
        "captured_at": _iso(s.captured_at),
    }


def compliance_current(session: Session, *, account: Optional[str] = None) -> dict[str, Any]:
    """Latest snapshot per framework. ``account`` (account_identifier) scopes to
    one account's snapshots — snapshots carry the account they were captured
    against, so a scoped view never shows another account's score."""
    stmt = select(ComplianceSnapshot).order_by(ComplianceSnapshot.captured_at.desc())
    if account is not None:
        stmt = stmt.where(ComplianceSnapshot.account == account)
    rows = list(session.execute(stmt).scalars())
    latest: dict[str, ComplianceSnapshot] = {}
    for s in rows:
        latest.setdefault(s.framework, s)
    items = [_snapshot_to_dict(s) for s in latest.values()]
    items.sort(key=lambda d: d["framework"])
    return {"items": items, "total": len(items)}


def compliance_history(session: Session, *, framework: str, limit: int = 100) -> dict[str, Any]:
    """Score time-series for one framework (oldest→newest), for trend charts."""
    rows = list(session.execute(
        select(ComplianceSnapshot)
        .where(ComplianceSnapshot.framework == framework)
        .order_by(ComplianceSnapshot.captured_at.desc())
        .limit(limit)
    ).scalars())
    rows.reverse()
    return {
        "framework": framework,
        "points": [
            {"captured_at": _iso(s.captured_at), "score": s.score,
             "passing": s.passing, "total": s.total}
            for s in rows
        ],
    }


def compliance_drift(session: Session, *, framework: Optional[str] = None, limit: int = 100) -> dict[str, Any]:
    """Recent control state transitions (newest first)."""
    stmt = select(ComplianceDrift)
    if framework is not None:
        stmt = stmt.where(ComplianceDrift.framework == framework)
    stmt = stmt.order_by(ComplianceDrift.detected_at.desc()).limit(limit)
    rows = list(session.execute(stmt).scalars())
    items = [{
        "framework": d.framework,
        "control_id": d.control_id,
        "control_title": d.control_title,
        "from_state": d.from_state,
        "to_state": d.to_state,
        "direction": d.direction,
        "detected_at": _iso(d.detected_at),
    } for d in rows]
    regressions = sum(1 for d in rows if d.direction == "regression")
    return {
        "items": items,
        "total": len(items),
        "regressions": regressions,
        "remediations": len(items) - regressions,
    }
