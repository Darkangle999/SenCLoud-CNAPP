"""FastAPI router for the product customization layer.

CRUD over the three config tables (control overrides, custom frameworks, custom
policies) plus a policy-evaluation endpoint that runs the user's policies against
the current inventory. Mounted by ``server.py``. Same thin-shell style as
``inventory_routes`` — pydantic bodies, ``config_store`` does the DB work.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from odineyes.core import config_store
from odineyes.db.base import get_sessionmaker

router = APIRouter(prefix="/api/config", tags=["config"])

_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_RULE_TYPES = {"tag_required", "encryption_required", "no_public", "network_max"}
_FRAMEWORK_ID_RE = re.compile(r"^[A-Za-z0-9_.\- ]{1,64}$")


# ── control overrides ─────────────────────────────────────────────────────────

class OverrideIn(BaseModel):
    framework: str
    control_id: str
    enabled: Optional[bool] = None
    severity: Optional[str] = None
    note: Optional[str] = None
    waived_until: Optional[datetime] = None


@router.get("/overrides")
def get_overrides() -> dict[str, Any]:
    return {"items": config_store.list_overrides()}


@router.put("/overrides")
def put_override(body: OverrideIn) -> dict[str, Any]:
    if body.severity is not None and body.severity not in _SEVERITIES:
        raise HTTPException(400, f"severity must be one of {sorted(_SEVERITIES)}")
    data = body.model_dump(exclude_unset=True)
    framework = data.pop("framework")
    control_id = data.pop("control_id")
    return config_store.upsert_override(framework, control_id, **data)


@router.delete("/overrides/{framework}/{control_id}")
def remove_override(framework: str, control_id: str) -> dict[str, Any]:
    if not config_store.delete_override(framework, control_id):
        raise HTTPException(404, "no such override")
    return {"deleted": True}


# ── custom frameworks ─────────────────────────────────────────────────────────

class FrameworkIn(BaseModel):
    framework_id: str = Field(min_length=1, max_length=64)
    name: str
    version: Optional[str] = None
    # {control_id: {"title", "section", "checks": [check_id, ...]}}
    controls: dict[str, Any] = Field(default_factory=dict)
    enabled: Optional[bool] = None


@router.get("/frameworks")
def get_frameworks() -> dict[str, Any]:
    return {"items": config_store.list_frameworks()}


@router.put("/frameworks")
def put_framework(body: FrameworkIn) -> dict[str, Any]:
    from odineyes.core.compliance_mapper import FRAMEWORKS
    if body.framework_id in FRAMEWORKS:
        raise HTTPException(400, f"'{body.framework_id}' is a built-in framework id")
    data = body.model_dump(exclude_unset=True)
    framework_id = data.pop("framework_id")
    return config_store.upsert_framework(framework_id, **data)


@router.delete("/frameworks/{framework_id}")
def remove_framework(framework_id: str) -> dict[str, Any]:
    if not config_store.delete_framework(framework_id):
        raise HTTPException(404, "no such framework")
    return {"deleted": True}


@router.post("/frameworks/import")
async def import_framework(
    request: Request,
    framework_id: str = Query(..., min_length=1, max_length=64),
    name: Optional[str] = None,
    version: Optional[str] = None,
    sheet: int = 0,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Import a compliance framework from an uploaded .xlsx control matrix.

    The raw file is the request body (application/octet-stream) — no multipart
    dependency. ``dry_run`` (default) parses + maps and returns a preview without
    saving; ``dry_run=false`` persists it as a custom framework. Controls with no
    explicit check column get a best-practice suggestion from the check registry.
    """
    from odineyes.core.compliance_mapper import FRAMEWORKS
    from odineyes.core.framework_import import (
        FrameworkImportError, MAX_FILE_BYTES, import_workbook,
    )

    if not _FRAMEWORK_ID_RE.match(framework_id):
        raise HTTPException(400, "framework_id must be ≤64 chars of [A-Za-z0-9 _.-]")
    if framework_id in FRAMEWORKS:
        raise HTTPException(400, f"'{framework_id}' is a built-in framework id")

    # Guard memory before reading the body fully (defense in depth; the ASGI
    # server enforces its own limit too).
    clen = request.headers.get("content-length")
    if clen and clen.isdigit() and int(clen) > MAX_FILE_BYTES:
        raise HTTPException(413, "file too large")

    data = await request.body()
    if not data:
        raise HTTPException(400, "empty upload")
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(413, "file too large")

    try:
        fw = import_workbook(data, framework_id=framework_id, name=name, version=version, sheet=sheet)
    except FrameworkImportError as e:
        raise HTTPException(400, str(e))

    if dry_run:
        return {"preview": True, "control_count": len(fw["controls"]), **fw}

    saved = config_store.upsert_framework(
        fw["framework_id"], name=fw["name"], version=fw["version"],
        controls=fw["controls"], enabled=True)
    return {"preview": False, "control_count": len(saved["controls"]), **saved}


# ── custom policies ───────────────────────────────────────────────────────────

class PolicyIn(BaseModel):
    policy_id: str = Field(min_length=1, max_length=64)
    name: str
    description: Optional[str] = None
    severity: str = "medium"
    resource_type: Optional[str] = None
    rule: dict[str, Any]                 # {type, params}
    frameworks: dict[str, Any] = Field(default_factory=dict)  # {framework_id: [control_id]}
    enabled: Optional[bool] = None


@router.get("/policies")
def get_policies() -> dict[str, Any]:
    return {"items": config_store.list_policies()}


@router.put("/policies")
def put_policy(body: PolicyIn) -> dict[str, Any]:
    if body.severity not in _SEVERITIES:
        raise HTTPException(400, f"severity must be one of {sorted(_SEVERITIES)}")
    rtype = (body.rule or {}).get("type")
    if rtype not in _RULE_TYPES:
        raise HTTPException(400, f"rule.type must be one of {sorted(_RULE_TYPES)}")
    data = body.model_dump(exclude_unset=True)
    policy_id = data.pop("policy_id")
    return config_store.upsert_policy(policy_id, **data)


@router.delete("/policies/{policy_id}")
def remove_policy(policy_id: str) -> dict[str, Any]:
    if not config_store.delete_policy(policy_id):
        raise HTTPException(404, "no such policy")
    return {"deleted": True}


@router.post("/policies/evaluate")
def evaluate_policies() -> dict[str, Any]:
    """Run all enabled custom policies against the current inventory assets."""
    from odineyes.core.policy_engine import evaluate
    from odineyes.inventory import queries

    cfg = config_store.load_config()
    if not cfg.custom_policies:
        return {"findings": [], "total": 0, "evaluated_policies": 0,
                "by_status": {"pass": 0, "fail": 0}}

    # ponytail: 500-asset cap; paginate the eval the day an account exceeds it.
    with get_sessionmaker()() as session:
        assets = queries.list_assets(session, page_size=500)["items"]

    findings = evaluate(cfg.custom_policies, assets)
    fails = sum(1 for f in findings if f["status"] == "fail")
    return {"findings": findings, "total": len(findings),
            "evaluated_policies": len(cfg.custom_policies),
            "by_status": {"pass": len(findings) - fails, "fail": fails}}


# ── framework catalog (built-in + custom) for the settings UI ─────────────────

@router.get("/available-frameworks")
def available_frameworks() -> dict[str, Any]:
    from odineyes.core.compliance_mapper import FRAMEWORKS
    builtin = [{"id": k, "name": v.get("name", k), "builtin": True} for k, v in FRAMEWORKS.items()]
    custom = [{"id": f["framework_id"], "name": f["name"], "builtin": False}
              for f in config_store.list_frameworks()]
    return {"items": builtin + custom}


@router.get("/frameworks/{framework_id}/controls")
def framework_controls(framework_id: str) -> dict[str, Any]:
    """The static control list for a framework (built-in or custom), so the
    settings UI can render a toggle/override per control without a live scan."""
    from odineyes.core.compliance_mapper import FRAMEWORKS

    def _controls(src: dict[str, Any]) -> list[dict[str, Any]]:
        return [{"id": cid, "title": m.get("title", cid), "section": m.get("section", "")}
                for cid, m in (src.get("controls", {}) or {}).items()]

    fw = FRAMEWORKS.get(framework_id)
    if fw:
        return {"framework": framework_id, "name": fw.get("name"), "controls": _controls(fw)}
    for f in config_store.list_frameworks():
        if f["framework_id"] == framework_id:
            return {"framework": framework_id, "name": f["name"],
                    "controls": _controls({"controls": f["controls"]})}
    raise HTTPException(404, "no such framework")


# ── Statement of Applicability (ISO 27001 SoA, works for any framework) ────────

def _latest_status(framework_id: str) -> dict[str, str]:
    """Best-effort: per-control state from the most recent compliance snapshot."""
    try:
        from odineyes.db.models import ComplianceSnapshot
        with get_sessionmaker()() as s:
            row = (s.query(ComplianceSnapshot)
                   .filter_by(framework=framework_id)
                   .order_by(ComplianceSnapshot.captured_at.desc())
                   .first())
            return dict(row.controls) if row and row.controls else {}
    except Exception:  # noqa: BLE001 — SoA is useful without a snapshot
        return {}


@router.get("/soa/{framework}")
def get_soa(framework: str) -> dict[str, Any]:
    from odineyes.core.soa import build_soa
    try:
        return build_soa(framework, status_by_control=_latest_status(framework))
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.get("/soa/{framework}/export")
def export_soa(framework: str) -> Response:
    from odineyes.core.soa import build_soa, soa_to_xlsx
    try:
        soa = build_soa(framework, status_by_control=_latest_status(framework))
    except ValueError as e:
        raise HTTPException(404, str(e))
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", framework)
    return Response(
        content=soa_to_xlsx(soa),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{safe}-SoA.xlsx"'},
    )
