"""Session-based one-click onboarding endpoints.

The per-account flow in ``inventory_routes`` needs a 12-digit account id before
it can issue anything. These endpoints do not: a launch link is minted blind and
the account is discovered from the stack's callback. Both flows coexist — the
callback in ``autoconnect`` routes to whichever one issued the token.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from odineyes.api.security import require_operator
from odineyes.core import onboarding_session as sessions
from odineyes.core.onboarding_hosting import (
    OnboardingHostingConfigurationError,
    check_hosting,
    hosting_is_ready,
    publish_shared_template,
)
from odineyes.db.base import session_scope

router = APIRouter(prefix="/api/inventory/onboarding", tags=["onboarding"])
logger = logging.getLogger(__name__)

_REGION_PATTERN = r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$"


@router.get("/hosting-status", dependencies=[Depends(require_operator)])
def hosting_status() -> dict[str, Any]:
    """Preflight the one-click path before a link is sent to a customer.

    Every failure reported here is one the customer would otherwise meet as a
    dead launch link or a CREATE_FAILED stack, so the UI keeps link generation
    disabled until this comes back ready.
    """
    checks = check_hosting()
    return {
        "ready": hosting_is_ready(checks),
        "checks": [{"name": c.name, "status": c.status, "detail": c.detail} for c in checks],
    }


@router.post("/publish", dependencies=[Depends(require_operator)])
def publish_template() -> dict[str, Any]:
    """Upload (or reuse) the shared, secret-free onboarding template."""
    from odineyes.core.iac_templates import cloudformation_parameterized_template

    try:
        published = publish_shared_template(cloudformation_parameterized_template("managed"))
    except OnboardingHostingConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "bucket": published.bucket,
        "key": published.key,
        "checksum": published.checksum,
        "reused": published.reused,
    }


class LinkIn(BaseModel):
    label: Optional[str] = Field(default=None, max_length=256)
    ttl_seconds: int = Field(default=3600, ge=60, le=86_400)
    console_region: Optional[str] = Field(default=None, pattern=_REGION_PATTERN)
    # Off unless the platform has a publicly reachable callback endpoint: a
    # stack that cannot reach its callback fails the custom resource and rolls
    # itself back, taking the created role with it.
    with_callback: bool = True
    policy_mode: str = Field(default="managed", pattern="^(managed|least-privilege)$")


@router.post("/link", dependencies=[Depends(require_operator)])
def create_link(body: LinkIn) -> dict[str, Any]:
    """Mint a launch link. No account id required, nothing for the customer to copy.

    The returned URL carries a single-use onboarding token in its query string.
    Deliver it over an authenticated channel, never in a shared ticket.
    """
    try:
        with session_scope() as session:
            link = sessions.create_link(
                session,
                label=(body.label or "").strip() or None,
                ttl_seconds=body.ttl_seconds,
                console_region=body.console_region,
                with_callback=body.with_callback,
                policy_mode=body.policy_mode,
            )
    except OnboardingHostingConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except sessions.tokens.OnboardingTokenError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return link.to_dict()


@router.get("/sessions", dependencies=[Depends(require_operator)])
def list_sessions(limit: int = Query(default=50, ge=1, le=200)) -> dict[str, Any]:
    with session_scope() as session:
        return {"sessions": sessions.list_sessions(session, limit)}


class RegisterManualIn(BaseModel):
    session_id: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    role_arn: str = Field(min_length=20, max_length=512)


@router.post("/register-manual", dependencies=[Depends(require_operator)])
def register_manual(body: RegisterManualIn, background_tasks: BackgroundTasks) -> dict[str, Any]:
    """Complete an onboarding from the stack's RoleArn output.

    Needed whenever the stack could not call back — no public endpoint yet, or a
    customer network that blocks the Lambda.
    """
    import os

    try:
        with session_scope() as session:
            result = sessions.register_manual(
                session, session_id=body.session_id, role_arn=body.role_arn,
            )
    except sessions.OnboardingSessionError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail) from exc

    from odineyes.api.inventory_routes import _auto_scan

    background_tasks.add_task(
        _auto_scan, result["account_id"], os.environ.get("ODINEYES_SCAN_REGION", "us-east-1"),
    )
    return result
