"""Private persistence bridge for the Go real-time worker."""

from __future__ import annotations

import logging
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from odineyes.db.base import session_scope
from odineyes.db.models import CloudAccount, CloudMutationEvent

router = APIRouter(prefix="/internal/realtime", tags=["internal-realtime"])
logger = logging.getLogger(__name__)

_SENSITIVE = re.compile(r"secret|password|token|authorization|credential|accesskey", re.I)
_PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}
_SENSITIVE_PORTS = {22, 23, 3389, 5432, 3306, 1433, 1521, 6379, 9200, 27017}


class MutationEnvelope(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    account: str = Field(pattern=r"^\d{12}$")
    region: str = Field(min_length=1, max_length=64)
    source: str = Field(min_length=1, max_length=128)
    time: str | None = None
    detail: dict[str, Any]


class ReconcileIn(BaseModel):
    account: str = Field(pattern=r"^\d{12}$")
    regions: list[str] = Field(default_factory=list, max_length=32)


def _redact(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        return "[truncated]"
    if isinstance(value, dict):
        return {
            str(key)[:128]: "[redacted]" if _SENSITIVE.search(str(key)) else _redact(child, depth + 1)
            for key, child in list(value.items())[:200]
        }
    if isinstance(value, list):
        return [_redact(child, depth + 1) for child in value[:200]]
    return value[:4096] if isinstance(value, str) else value


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _resource_hint(detail: dict[str, Any]) -> str | None:
    params = detail.get("requestParameters") or {}
    for key in ("groupId", "bucketName", "roleName", "policyArn", "dBInstanceIdentifier", "dbInstanceIdentifier", "userName", "keyId", "resourceArn"):
        if params.get(key):
            return str(params[key])[:1024]
    return None


def _ports_and_cidrs(params: dict[str, Any]) -> tuple[set[int], set[str]]:
    ports: set[int] = set()
    cidrs: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                lowered = str(key).lower()
                if lowered in {"fromport", "toport"}:
                    try:
                        ports.add(int(child))
                    except (TypeError, ValueError):
                        pass
                elif lowered in {"cidrip", "cidripv6"} and child:
                    cidrs.add(str(child))
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(params)
    return ports, cidrs


def _provisional_alert(event_name: str, detail: dict[str, Any], account: str) -> dict[str, Any] | None:
    params = detail.get("requestParameters") or {}
    if event_name in {"AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"}:
        ports, cidrs = _ports_and_cidrs(params)
        sensitive = sorted(ports & _SENSITIVE_PORTS)
        if cidrs & _PUBLIC_CIDRS and sensitive:
            return {"kind": "fast_path", "severity": "high", "title": f"Public ingress added to sensitive port {sensitive[0]}", "account": account, "verification": "pending_reconciliation"}
    messages = {
        "PutBucketPolicy": ("medium", "S3 bucket policy changed"),
        "PutBucketAcl": ("medium", "S3 bucket ACL changed"),
        "AttachRolePolicy": ("medium", "IAM managed policy attached"),
        "PutRolePolicy": ("medium", "IAM inline role policy changed"),
        "UpdateAssumeRolePolicy": ("high", "IAM role trust policy changed"),
        "ModifyDBInstance": ("medium", "RDS instance security configuration changed"),
        "CreateAccessKey": ("high", "Long-lived IAM access key created"),
    }
    message = messages.get(event_name)
    if not message:
        return None
    return {"kind": "fast_path", "severity": message[0], "title": message[1], "account": account, "verification": "pending_reconciliation"}


@router.post("/events")
def ingest_mutation(body: MutationEnvelope) -> dict[str, Any]:
    event_name = str(body.detail.get("eventName") or "")
    if not event_name:
        raise HTTPException(status_code=422, detail="detail.eventName is required")
    if body.detail.get("errorCode"):
        return {"status": "ignored", "reason": "failed_api_call", "account": body.account}
    alert = _provisional_alert(event_name, body.detail, body.account)
    with session_scope() as session:
        account = session.execute(select(CloudAccount).where(CloudAccount.provider == "aws", CloudAccount.account_identifier == body.account, CloudAccount.is_active.is_(True))).scalar_one_or_none()
        if account is None:
            raise HTTPException(status_code=403, detail="event account is not enrolled")
        existing = session.execute(select(CloudMutationEvent).where(CloudMutationEvent.event_id == body.id)).scalar_one_or_none()
        if existing is not None:
            return {"status": "accepted", "duplicate": True, "account": body.account, "account_id": account.id, "alert": existing.alert}
        session.add(CloudMutationEvent(
            event_id=body.id, account_id=account.id, event_name=event_name,
            event_source=str(body.detail.get("eventSource") or body.source), region=body.region,
            resource_hint=_resource_hint(body.detail), event_time=_parse_time(body.time or body.detail.get("eventTime")),
            payload=_redact(body.model_dump()), alert=alert, reconcile_status="pending",
        ))
        session.flush()
        account_id = account.id
    return {"status": "accepted", "duplicate": False, "account": body.account, "account_id": account_id, "alert": alert}


@router.post("/reconcile", status_code=202)
def reconcile(body: ReconcileIn, background_tasks: BackgroundTasks) -> dict[str, Any]:
    regions = sorted(set(body.regions)) or ["us-east-1"]
    with session_scope() as session:
        account = session.execute(select(CloudAccount).where(CloudAccount.provider == "aws", CloudAccount.account_identifier == body.account, CloudAccount.is_active.is_(True))).scalar_one_or_none()
        if account is None:
            raise HTTPException(status_code=404, detail="account is not enrolled")
        account_id = account.id
        session.execute(
            update(CloudMutationEvent)
            .where(
                CloudMutationEvent.account_id == account_id,
                CloudMutationEvent.reconcile_status == "pending",
                CloudMutationEvent.region.in_(regions),
            )
            .values(reconcile_status="queued")
        )
    for region in regions:
        background_tasks.add_task(_run_reconciliation, account_id, region)
    logger.info("queued realtime reconciliation account=%s regions=%s", body.account, regions)
    return {"status": "queued", "account": body.account, "account_id": account_id, "regions": regions}


def _run_reconciliation(account_id: int, region: str) -> None:
    from odineyes.api.inventory_routes import _run_account_scan

    succeeded = False
    try:
        result = _run_account_scan(account_id, region)
        succeeded = result is not None and result.status == "completed"
    except Exception:  # noqa: BLE001 - retry state is persisted below
        logger.exception("real-time reconciliation failed account=%s", account_id)
    with session_scope() as session:
        values: dict[str, Any] = {
            "reconcile_status": "reconciled" if succeeded else "pending",
        }
        if succeeded:
            values["reconciled_at"] = datetime.now(timezone.utc)
        session.execute(
            update(CloudMutationEvent)
            .where(
                CloudMutationEvent.account_id == account_id,
                CloudMutationEvent.reconcile_status == "queued",
                CloudMutationEvent.region == region,
            )
            .values(**values)
        )
        account = session.get(CloudAccount, account_id)
        account_identifier = account.account_identifier if account else None
        if succeeded:
            rows = session.execute(
                select(CloudMutationEvent).where(
                    CloudMutationEvent.account_id == account_id,
                    CloudMutationEvent.reconcile_status == "reconciled",
                    CloudMutationEvent.region == region,
                    CloudMutationEvent.alert.is_not(None),
                )
            ).scalars().all()
            for row in rows:
                row.alert = {**(row.alert or {}), "verification": "reconciled"}
    _notify_reconciliation(account_identifier, region, succeeded)


def _notify_reconciliation(account: str | None, region: str, succeeded: bool) -> None:
    if not account:
        return
    import urllib.request

    url = os.environ.get(
        "ODINEYES_REALTIME_CALLBACK_URL",
        "http://odineyes-realtime:8090/broadcast",
    )
    payload = json.dumps({
        "type": "reconciliation_complete" if succeeded else "reconciliation_failed",
        "account": account,
        "region": region,
        "at": datetime.now(timezone.utc).isoformat(),
    }).encode()
    try:
        request = urllib.request.Request(url, data=payload, method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=3):
            pass
    except Exception:  # noqa: BLE001 - persistence succeeded; UI push is best effort
        logger.warning("could not publish reconciliation completion account=%s", account)
