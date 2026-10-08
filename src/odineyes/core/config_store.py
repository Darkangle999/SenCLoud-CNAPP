"""Product customization config: control overrides, custom frameworks, custom
policies. Thin layer over the three config tables.

The read path (``load_config``) is best-effort: any failure (no DB, table not
created yet) returns an empty config so scoring falls back to stock behaviour —
the same no-op pattern as the inventory enrichment join. The write helpers are
used by ``api.config_routes`` and raise normally (the caller wants the error).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from odineyes.db.base import get_sessionmaker, session_scope
from odineyes.db.models import ControlOverride, CustomFramework, CustomPolicy

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """A snapshot of all customization, in the shape the mapper/engine consume."""
    # {framework: {control_id: {"enabled", "severity", "note", "waived_until"}}}
    overrides: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    # {framework_id: {"name", "version", "controls", "enabled"}}  (enabled only)
    custom_frameworks: dict[str, dict[str, Any]] = field(default_factory=dict)
    # enabled policies only: [{"policy_id", "name", "severity", "resource_type",
    #                          "rule", "frameworks"}]
    custom_policies: list[dict[str, Any]] = field(default_factory=list)


def load_config() -> Config:
    """Best-effort snapshot. Empty Config on any failure → stock scoring."""
    try:
        cfg = Config()
        with get_sessionmaker()() as session:
            for o in session.query(ControlOverride).all():
                cfg.overrides.setdefault(o.framework, {})[o.control_id] = {
                    "enabled": o.enabled,
                    "severity": o.severity,
                    "note": o.note,
                    "waived_until": o.waived_until.isoformat() if o.waived_until else None,
                }
            for f in session.query(CustomFramework).filter_by(enabled=True).all():
                cfg.custom_frameworks[f.framework_id] = {
                    "name": f.name, "version": f.version,
                    "controls": f.controls or {}, "enabled": f.enabled,
                }
            for p in session.query(CustomPolicy).filter_by(enabled=True).all():
                cfg.custom_policies.append({
                    "policy_id": p.policy_id, "name": p.name, "severity": p.severity,
                    "resource_type": p.resource_type, "rule": p.rule or {},
                    "frameworks": p.frameworks or {},
                })
        return cfg
    except Exception as e:  # noqa: BLE001 — config is optional; never sink a scan
        logger.warning("config load failed (%s) — using stock defaults", e)
        return Config()


def available_frameworks() -> list[str]:
    """Built-in framework ids ∪ enabled custom framework ids."""
    from odineyes.core.compliance_mapper import FRAMEWORKS
    return list(FRAMEWORKS) + list(load_config().custom_frameworks)


# ── serialization ─────────────────────────────────────────────────────────────

def _override_dict(o: ControlOverride) -> dict[str, Any]:
    return {"framework": o.framework, "control_id": o.control_id, "enabled": o.enabled,
            "severity": o.severity, "note": o.note,
            "waived_until": o.waived_until.isoformat() if o.waived_until else None,
            "updated_at": o.updated_at.isoformat() if o.updated_at else None}


def _framework_dict(f: CustomFramework) -> dict[str, Any]:
    return {"framework_id": f.framework_id, "name": f.name, "version": f.version,
            "controls": f.controls or {}, "enabled": f.enabled}


def _policy_dict(p: CustomPolicy) -> dict[str, Any]:
    return {"policy_id": p.policy_id, "name": p.name, "description": p.description,
            "severity": p.severity, "resource_type": p.resource_type,
            "rule": p.rule or {}, "frameworks": p.frameworks or {}, "enabled": p.enabled}


# ── control overrides ─────────────────────────────────────────────────────────

def list_overrides() -> list[dict[str, Any]]:
    with get_sessionmaker()() as s:
        return [_override_dict(o) for o in s.query(ControlOverride).all()]


def upsert_override(framework: str, control_id: str, **fields: Any) -> dict[str, Any]:
    """Set one or more of enabled/severity/note/waived_until for a control."""
    with session_scope() as s:
        o = s.query(ControlOverride).filter_by(framework=framework, control_id=control_id).one_or_none()
        if o is None:
            o = ControlOverride(framework=framework, control_id=control_id)
            s.add(o)
        for k in ("enabled", "severity", "note", "waived_until"):
            if k in fields:
                setattr(o, k, fields[k])
        s.flush()
        return _override_dict(o)


def delete_override(framework: str, control_id: str) -> bool:
    with session_scope() as s:
        o = s.query(ControlOverride).filter_by(framework=framework, control_id=control_id).one_or_none()
        if o is None:
            return False
        s.delete(o)
        return True


# ── custom frameworks ─────────────────────────────────────────────────────────

def list_frameworks() -> list[dict[str, Any]]:
    with get_sessionmaker()() as s:
        return [_framework_dict(f) for f in s.query(CustomFramework).all()]


def upsert_framework(framework_id: str, **fields: Any) -> dict[str, Any]:
    with session_scope() as s:
        f = s.query(CustomFramework).filter_by(framework_id=framework_id).one_or_none()
        if f is None:
            f = CustomFramework(framework_id=framework_id, name=fields.get("name", framework_id))
            s.add(f)
        for k in ("name", "version", "controls", "enabled"):
            if k in fields:
                setattr(f, k, fields[k])
        s.flush()
        return _framework_dict(f)


def delete_framework(framework_id: str) -> bool:
    with session_scope() as s:
        f = s.query(CustomFramework).filter_by(framework_id=framework_id).one_or_none()
        if f is None:
            return False
        s.delete(f)
        return True


# ── custom policies ───────────────────────────────────────────────────────────

def list_policies() -> list[dict[str, Any]]:
    with get_sessionmaker()() as s:
        return [_policy_dict(p) for p in s.query(CustomPolicy).all()]


def upsert_policy(policy_id: str, **fields: Any) -> dict[str, Any]:
    with session_scope() as s:
        p = s.query(CustomPolicy).filter_by(policy_id=policy_id).one_or_none()
        if p is None:
            p = CustomPolicy(policy_id=policy_id, name=fields.get("name", policy_id))
            s.add(p)
        for k in ("name", "description", "severity", "resource_type", "rule", "frameworks", "enabled"):
            if k in fields:
                setattr(p, k, fields[k])
        s.flush()
        return _policy_dict(p)


def delete_policy(policy_id: str) -> bool:
    with session_scope() as s:
        p = s.query(CustomPolicy).filter_by(policy_id=policy_id).one_or_none()
        if p is None:
            return False
        s.delete(p)
        return True
