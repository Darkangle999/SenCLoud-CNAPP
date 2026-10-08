"""FastAPI router for the Phase 1 inventory store.

Thin shell over ``odineyes.inventory`` — registration, a manual scan-ingest
trigger (the live cloud collector will call the same service path), and the read
endpoints the asset browser + dashboard consume. Mounted by ``server.py``.
"""

from __future__ import annotations

import csv
import datetime
import io
import json
import logging
import os
import re
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query, Response
from pydantic import BaseModel, Field, model_validator

from odineyes.db.base import get_sessionmaker, session_scope
from odineyes.db.models import Asset, CloudAccount, RealtimeRegion, ScanJob
from odineyes.api.inventory_models import InventoryResourcePage
from odineyes.api.security_models import (
    DataStorePage,
    IdentityPrincipal,
    IdentityPrincipalPage,
    ModeledFindingPage,
)
from odineyes.api.security import require_operator as _shared_require_operator
from odineyes.inventory import queries
from odineyes.inventory.repository import AccountRepository
from odineyes.inventory.service import InventoryService

router = APIRouter(prefix="/api/inventory", tags=["inventory"])
logger = logging.getLogger(__name__)
_REGION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"


def require_operator(authorization: Optional[str] = Header(default=None)) -> None:
    """Operator gate for secret-minting / privileged endpoints. When
    ODINEYES_ADMIN_TOKEN is set, require `Authorization: Bearer <token>`
    (constant-time). When unset (local dev) the gate is open — set the token in
    any shared/prod deployment. Paired with the secret-once behaviour on
    onboarding-template so an unauthenticated mint still can't be replayed."""
    _shared_require_operator(authorization)


def _onboarding_event_bus_arn() -> str:
    """Best-effort regional ingress prefill for a one-click launch link.

    Local development can create an inventory-only onboarding link before the
    regional data plane exists. In that case realtime remains disabled instead
    of accidentally targeting a queue in a different Region.
    """
    from odineyes.core.realtime_policy import event_bus_for_region

    region = os.environ.get("ODINEYES_SCAN_REGION", "us-east-1").strip() or "us-east-1"
    try:
        return event_bus_for_region(region).event_bus_arn
    except (RuntimeError, ValueError):
        return ""

# Stateless service bound to the process-wide engine (DB is initialised at app
# startup); never re-initialises the schema per request.
_service = InventoryService(auto_init=False)


class AccountIn(BaseModel):
    provider: str = Field(pattern="^(aws|azure|gcp)$")
    account_identifier: str = Field(min_length=1, max_length=128)
    name: Optional[str] = None
    role_arn: Optional[str] = None

    @model_validator(mode="after")
    def _check(self) -> "AccountIn":
        # Validate at the trust boundary: an AWS account id is 12 digits and the
        # role ARN (the only credential we store) must be a well-formed IAM role.
        if self.provider == "aws":
            if not re.fullmatch(r"\d{12}", self.account_identifier):
                raise ValueError("aws account_identifier must be 12 digits")
            # role_arn is mandatory: onboarding is uniform cross-account assume-role.
            # No ambient/root-credential scanning path exists anymore.
            if not self.role_arn:
                raise ValueError(
                    "role_arn is required — deploy the onboarding template and paste "
                    "the resulting Odineyes role ARN"
                )
            if not re.fullmatch(
                r"arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]+", self.role_arn
            ):
                raise ValueError("role_arn must be a valid IAM role ARN")
        return self


class ScanResourceIn(BaseModel):
    source_type: str
    raw: dict[str, Any]


class RealtimeRegionIn(BaseModel):
    region: str = Field(pattern=_REGION_PATTERN, max_length=64)
    delivery_role_arn: str = Field(min_length=20, max_length=512)

    @model_validator(mode="after")
    def _valid_role(self) -> "RealtimeRegionIn":
        if not re.fullmatch(r"arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]+", self.delivery_role_arn):
            raise ValueError("delivery_role_arn must be a valid IAM role ARN")
        return self


class ScanIn(BaseModel):
    provider: str = Field(pattern="^(aws|azure|gcp)$")
    account_identifier: str
    resources: list[ScanResourceIn] = Field(default_factory=list, max_length=20_000)
    account_name: Optional[str] = None
    role_arn: Optional[str] = None


def _run_account_scan(account_id: int, region: str):
    """Assume the account's role and run one full scan. Returns the
    AccountScanResult, or None if the account vanished/was disabled. Shared by
    the manual scan endpoint and the auto-scan-on-register background task."""
    from odineyes.inventory.orchestrator import AccountRef, MultiAccountOrchestrator

    with session_scope() as session:
        acct = session.get(CloudAccount, account_id)
        if acct is None or not acct.is_active:
            return None
        ref = AccountRef(acct.account_identifier, acct.name, acct.role_arn,
                         acct.provider, acct.external_id,
                         excluded_regions=tuple(json.loads(acct.excluded_regions or "[]")))
    return MultiAccountOrchestrator(_service, region=region).scan_account(ref)


def _auto_scan(account_id: int, region: str) -> None:
    """Background auto-scan fired right after an account is connected. Best-effort
    — a credential/assume-role failure is logged, never raised (the 201 already
    went out)."""
    try:
        result = _run_account_scan(account_id, region)
        if result is not None:
            logger.info("auto-scan account %s: %s", account_id, result.status)
    except Exception as e:  # noqa: BLE001 — background task must not crash the loop
        logger.warning("auto-scan failed for account %s: %s", account_id, e)


@router.post("/accounts", status_code=201, dependencies=[Depends(require_operator)])
def register_account(body: AccountIn, background_tasks: BackgroundTasks) -> dict[str, Any]:
    with session_scope() as session:
        account = AccountRepository.get_or_create(
            session, body.provider, body.account_identifier, body.name, body.role_arn,
        )
        if body.name:
            account.name = body.name
        account.is_active = True  # re-POSTing a disabled account re-enables it
        account.onboarding_status = "connected"
        session.flush()
        data = queries.account_to_dict(account)
        has_role = bool(account.role_arn)

    # Auto-scan the freshly connected account so the user doesn't have to click
    # Scan. Runs in the background: the 201 returns immediately, the scan (assume
    # role -> collect -> rules -> paths) populates its data a moment later. Only
    # for accounts with a role to assume (all AWS accounts, per onboarding).
    if has_role:
        background_tasks.add_task(_auto_scan, data["id"], "us-east-1")
    return data


@router.put("/accounts/{account_id}/realtime-regions", dependencies=[Depends(require_operator)])
def register_realtime_region(account_id: int, body: RealtimeRegionIn) -> dict[str, Any]:
    """Register the exact EventBridge delivery role from a regional stack.

    This is intentionally operator-gated. The customer stack output is not a
    credential; nevertheless, binding it to the wrong tenant would create an
    unwanted cross-account event sender.
    """
    from odineyes.core.realtime_policy import event_bus_for_region, register_delivery_role

    with session_scope() as session:
        account = session.get(CloudAccount, account_id)
        if account is None or account.provider != "aws" or not account.is_active:
            raise HTTPException(status_code=404, detail="active AWS account not found")
        match = re.fullmatch(r"arn:aws[a-z-]*:iam::(\d{12}):role/[\w+=,.@/-]+", body.delivery_role_arn)
        if match is None or match.group(1) != account.account_identifier:
            raise HTTPException(status_code=422, detail="delivery_role_arn must belong to this customer account")
        try:
            plane = event_bus_for_region(body.region)
            register_delivery_role(body.delivery_role_arn, body.region)
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        row = session.query(RealtimeRegion).filter(
            RealtimeRegion.account_id == account_id,
            RealtimeRegion.region == body.region,
        ).one_or_none()
        if row is None:
            row = RealtimeRegion(
                account_id=account_id,
                region=body.region,
                delivery_role_arn=body.delivery_role_arn,
                queue_arn=plane.arn,
            )
            session.add(row)
        else:
            row.delivery_role_arn = body.delivery_role_arn
            row.queue_arn = plane.arn
        session.flush()
        return {
            "account_id": account_id,
            "region": row.region,
            "delivery_role_arn": row.delivery_role_arn,
            "queue_arn": row.queue_arn,
            "event_bus_arn": plane.event_bus_arn,
            "registered_at": row.registered_at.isoformat(),
        }


@router.get("/accounts/{account_id}/regions", dependencies=[Depends(require_operator)])
def list_account_regions(account_id: int) -> dict[str, Any]:
    """Region Management data: every region the account has assets in, with
    per-region active-resource counts, plus the operator's opt-out list.

    Activity counts power the dormancy view — a region the customer never
    operates in but that suddenly shows resources is exactly the tripwire the
    global sweep exists to catch, so the default exclusion set is empty.
    """
    from sqlalchemy import func

    with session_scope() as session:
        account = session.get(CloudAccount, account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="account not found")
        excluded = sorted(set(json.loads(account.excluded_regions or "[]")))
        rows = (
            session.query(Asset.region, func.count(Asset.id))
            .filter(
                Asset.account_id == account_id,
                Asset.cloud_provider == "aws",
                Asset.is_active.is_(True),
            )
            .group_by(Asset.region)
            .all()
        )
    activity = {region: count for region, count in rows if region}
    regions = sorted(set(activity) | set(excluded))
    return {
        "account_id": account_id,
        "regions": [
            {
                "region": region,
                "active_resources": activity.get(region, 0),
                "excluded": region in excluded,
            }
            for region in regions
        ],
        "excluded_regions": excluded,
    }


class RegionExclusionIn(BaseModel):
    excluded_regions: list[str] = Field(default_factory=list)


@router.put("/accounts/{account_id}/regions", dependencies=[Depends(require_operator)])
def update_account_regions(account_id: int, body: RegionExclusionIn) -> dict[str, Any]:
    """Set the regions excluded from the discovery sweep.

    Opt-out exists for mature environments that physically block regions with
    SCPs — scanning those only burns API budget on guaranteed AccessDenied.
    Every entry is validated as a region-shaped name; an empty list (the
    default) restores the full global sweep.
    """
    cleaned = sorted({r.strip() for r in body.excluded_regions if r and r.strip()})
    for region in cleaned:
        if re.fullmatch(_REGION_PATTERN, region) is None:
            raise HTTPException(status_code=422, detail=f"invalid region name: {region!r}")
    with session_scope() as session:
        account = session.get(CloudAccount, account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="account not found")
        account.excluded_regions = json.dumps(cleaned)
        session.flush()
    return {"account_id": account_id, "excluded_regions": cleaned}


@router.get("/accounts/{account_id}/realtime-regions/template", dependencies=[Depends(require_operator)])
def regional_realtime_template(account_id: int, region: str = Query(..., pattern=_REGION_PATTERN)) -> dict[str, Any]:
    """Return the customer stack and exact same-Region ingress bus to deploy."""
    from odineyes.core.iac_templates import cloudformation_regional_telemetry_template
    from odineyes.core.realtime_policy import event_bus_for_region

    with session_scope() as session:
        account = session.get(CloudAccount, account_id)
        if account is None or account.provider != "aws" or not account.is_active:
            raise HTTPException(status_code=404, detail="active AWS account not found")
    try:
        plane = event_bus_for_region(region)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "account_id": account_id,
        "region": region,
        "parameters": {
            "RealtimeEventBusArn": plane.event_bus_arn,
            "EnableRealtimeCloudTrail": "false",
            "RealtimeTrailRetentionDays": 90,
        },
        "cloudformation_template": cloudformation_regional_telemetry_template(),
    }


class OnboardingIn(BaseModel):
    provider: str = Field(pattern="^(aws|azure|gcp)$")
    account_identifier: str = Field(min_length=1, max_length=128)
    name: Optional[str] = None
    policy_mode: str = Field(default="managed", pattern="^(managed|least-privilege)$")

    @model_validator(mode="after")
    def _check(self) -> "OnboardingIn":
        if self.provider == "aws" and not re.fullmatch(r"\d{12}", self.account_identifier):
            raise ValueError("aws account_identifier must be 12 digits")
        return self


@router.post("/accounts/onboarding-template", dependencies=[Depends(require_operator)])
def generate_onboarding_template(body: OnboardingIn) -> dict[str, Any]:
    """Create-or-reuse the account row (generating its ExternalId server-side —
    see CloudAccount.external_id), then return CloudFormation + Terraform
    artifacts the client runs themselves. Replaces the hand-edit-this-JSON
    onboarding step; the client still pastes the resulting role ARN into
    POST /accounts once the stack/module has run."""
    if body.provider != "aws":
        raise HTTPException(status_code=400, detail="onboarding templates are AWS-only for now")

    from odineyes.core.iac_templates import (
        ConfigurationError,
        cloudformation_parameterized_template,
        cloudformation_template,
        odineyes_account_id,
        odineyes_scanner_principal_arn,
        terraform_autoconnect_snippet,
        terraform_snippet,
    )

    import secrets
    from hashlib import sha256

    # The HMAC api_secret is returned exactly ONCE — at the moment it's minted.
    # This endpoint is unauthenticated, so if a re-POST re-returned the persisted
    # secret, anyone who can guess a 12-digit account id could harvest that
    # account's autoconnect credentials by replaying the request. On reuse we
    # return api_secret=None; recovering it requires an explicit rotate.
    minted_secret = False
    onboarding_token = secrets.token_urlsafe(32)
    onboarding_token_expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    with session_scope() as session:
        account = AccountRepository.get_or_create(
            session, body.provider, body.account_identifier, body.name,
        )
        if not account.api_key:
            account.api_key = secrets.token_urlsafe(32)
        if not account.api_secret:
            account.api_secret = secrets.token_urlsafe(64)
            minted_secret = True

        # Generating setup artefacts creates a draft, never a scan target. A
        # stale browser tab cannot accidentally make an account look connected
        # before CloudFormation has created and submitted the role.
        if not account.role_arn:
            account.is_active = False
            account.onboarding_status = "awaiting_stack"

        account.onboarding_token_hash = sha256(onboarding_token.encode("utf-8")).hexdigest()
        account.onboarding_token_expires_at = onboarding_token_expires_at
        account.onboarding_token_used_at = None

        external_id = account.external_id
        account_row_id = account.id
        api_key = account.api_key
        # api_key is an identifier (safe to echo); the secret is the sensitive half.
        api_secret = account.api_secret if minted_secret else None

    try:
        trust_account_id = odineyes_account_id()
        cfn = cloudformation_template(external_id, body.policy_mode)
        parameterized_cfn = cloudformation_parameterized_template(body.policy_mode)
        tf = terraform_snippet(external_id, body.policy_mode)
        # Auto-connect variant needs the api_secret embedded, so it only exists
        # on the mint call (api_secret is None on reuse — see secret-once note
        # below). On reuse, the client falls back to the manual `tf` snippet.
        tf_auto = (
            terraform_autoconnect_snippet(external_id, api_key, api_secret, body.policy_mode)
            if api_secret else None
        )
    except ConfigurationError as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

    # Publishing is intentionally best-effort. A local deployment has no
    # public HTTPS endpoint or central S3 bucket, but can still use the manual
    # CloudFormation/Terraform artefacts. Production enables this by setting
    # ODINEYES_PUBLIC_API_URL and ODINEYES_ONBOARDING_TEMPLATE_BUCKET.
    quick_create_url: Optional[str] = None
    hosted_template_url: Optional[str] = None
    hosted_template_expires_at: Optional[str] = None
    hosted_template_s3_uri: Optional[str] = None
    hosted_template_version_id: Optional[str] = None
    hosted_template_reused: Optional[bool] = None
    one_click_error: Optional[str] = None
    scanner_principal_arn: Optional[str] = None
    try:
        from odineyes.core.onboarding_hosting import (
            OnboardingHostingConfigurationError,
            public_api_url,
            publish_cloudformation_template,
        )

        scanner_principal_arn = odineyes_scanner_principal_arn()
        if scanner_principal_arn.endswith(":root"):
            raise OnboardingHostingConfigurationError(
                "ODINEYES_SCANNER_PRINCIPAL_ARN must name the specific IAM scanner user or role; "
                "account root cannot be trusted for one-click onboarding"
            )
        hosted = publish_cloudformation_template(
            account_identifier=body.account_identifier,
            template=parameterized_cfn,
            quick_create_parameters={
                "CSPMPlatformAccountId": trust_account_id,
                "CSPMPlatformPrincipalArn": scanner_principal_arn,
                "ExternalId": external_id,
                "OnboardingToken": onboarding_token,
                "CallbackUrl": (
                    public_api_url()
                    + "/api/inventory/accounts/onboarding-callback"
                ),
                "RoleName": "OdineyesReadOnly",
                "RealtimeEventBusArn": _onboarding_event_bus_arn(),
            },
        )
        quick_create_url = hosted.quick_create_url
        hosted_template_url = hosted.template_url
        hosted_template_expires_at = hosted.expires_at.isoformat()
        hosted_template_s3_uri = f"s3://{hosted.bucket}/{hosted.key}"
        hosted_template_version_id = hosted.version_id
        hosted_template_reused = hosted.reused
    except OnboardingHostingConfigurationError as e:
        one_click_error = str(e)

    return {
        "account_id": account_row_id,
        "external_id": external_id,
        "api_key": api_key,
        # Present only on the first generation for this account; None thereafter.
        "api_secret": api_secret,
        "secret_already_issued": not minted_secret,
        "onboarding_token_expires_at": onboarding_token_expires_at.isoformat(),
        "trust_account_id": trust_account_id,
        "scanner_principal_arn": scanner_principal_arn,
        "terraform_autoconnect_snippet": tf_auto,
        "policy_mode": body.policy_mode,
        "cloudformation_quick_create_url": quick_create_url,
        "cloudformation_template_url": hosted_template_url,
        "cloudformation_template_expires_at": hosted_template_expires_at,
        "cloudformation_template_s3_uri": hosted_template_s3_uri,
        "cloudformation_template_version_id": hosted_template_version_id,
        "cloudformation_template_reused": hosted_template_reused,
        "one_click_setup_error": one_click_error,
        "cloudformation_template": cfn,
        "terraform_snippet": tf,
    }


@router.get("/accounts")
def get_accounts() -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return {"items": queries.list_accounts(session)}


@router.delete("/accounts/{account_id}", dependencies=[Depends(require_operator)])
def deactivate_account(
    account_id: int, purge: bool = Query(default=False),
) -> dict[str, Any]:
    """Remove an account.

    Default (purge=false): soft-disable — stop scanning but keep history;
    re-POST to re-enable.

    purge=true: hard delete — the account row AND all of its data (assets,
    findings, issues, vulnerabilities, runtime events, graph edges, DSPM,
    compliance snapshots/drift). Irreversible. This is what "remove the account"
    means from the UI, so nothing lingers after deletion."""
    from sqlalchemy import delete

    from odineyes.db.models import ComplianceDrift, ComplianceSnapshot

    with session_scope() as session:
        account = session.get(CloudAccount, account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="account not found")

        if not purge:
            account.is_active = False
            session.flush()
            return queries.account_to_dict(account)

        ident = account.account_identifier
        # Every account_id-keyed table cascades with the account row (ORM
        # relationships on CloudAccount + ON DELETE CASCADE FKs): assets(+events),
        # scan_jobs(+errors), findings, issues, vulnerabilities, runtime_events,
        # graph_edges, dspm_findings. Only compliance keys on the identifier
        # STRING (snapshots outlive account identity by design), so delete it here.
        session.execute(delete(ComplianceSnapshot).where(ComplianceSnapshot.account == ident))
        session.execute(delete(ComplianceDrift).where(ComplianceDrift.account == ident))
        session.delete(account)
        session.flush()
        return {"deleted": True, "purged": True, "account_id": account_id}


@router.post("/scan", dependencies=[Depends(require_operator)])
def trigger_scan(body: ScanIn) -> dict[str, Any]:
    """Run a scan from a supplied resource set. The live AWS collector will call
    the same ``persist_scan`` path; for now resources are provided in the body so
    the pipeline (normalize → upsert → delta → soft-delete) is exercisable."""
    result = _service.persist_scan(
        body.provider,
        body.account_identifier,
        [(r.source_type, r.raw) for r in body.resources],
        account_name=body.account_name,
        role_arn=body.role_arn,
    )
    return {
        "scan_job_id": result.scan_job_id,
        "status": result.status,
        "found": result.found,
        "new": result.new,
        "changed": result.changed,
        "deleted": result.deleted,
        "reactivated": result.reactivated,
        "errors": result.errors,
        "partial": result.partial,
    }


@router.get("/summary")
def get_summary(account_id: Optional[int] = None) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.summary(session, account_id=account_id)


@router.get("/coverage")
def get_coverage(account_id: Optional[int] = None) -> dict[str, Any]:
    """Per-pillar source coverage (inventory/vuln/runtime/compliance): is each
    pillar producing data, and is it fresh. Surfaces the honest 'no data' state
    (e.g. runtime=absent, vuln=degraded) as a queryable signal."""
    from odineyes.inventory.coverage import compute_coverage

    with get_sessionmaker()() as session:
        return compute_coverage(session, account_id=account_id)


@router.get("/resources", response_model=InventoryResourcePage)
def get_inventory_resources(
    provider: Optional[str] = None,
    account_id: Optional[int] = None,
    q: Optional[str] = Query(default=None, max_length=512),
    category: Optional[str] = Query(default=None, pattern="^(identity|compute|network|data|security|management|other)$"),
    service: Optional[str] = Query(default=None, max_length=64),
    asset_type: Optional[str] = Query(default=None, alias="type", max_length=128),
    region: Optional[str] = Query(default=None, max_length=64),
    exposure: Optional[str] = Query(default=None, pattern="^(private|vpc|public)$"),
    min_risk: Optional[float] = Query(default=None, ge=0, le=100),
    is_active: Optional[bool] = True,
    sort: str = Query(default="risk", pattern="^(name|type|region|risk|last_scanned)$"),
    direction: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    """Modeled inventory explorer contract.

    Separates identity, scope, posture, lifecycle, and metadata; includes stable
    facets and pagination metadata. The legacy root endpoint remains available
    for integrations that still consume storage-shaped asset rows.
    """
    with get_sessionmaker()() as session:
        return queries.list_inventory_resources(
            session,
            provider=provider,
            account_id=account_id,
            query=q,
            category=category,
            service=service,
            asset_type=asset_type,
            region=region,
            exposure=exposure,
            min_risk=min_risk,
            is_active=is_active,
            sort=sort,
            direction=direction,
            page=page,
            page_size=page_size,
        )


@router.get("/identity/resources", response_model=IdentityPrincipalPage)
def get_identity_resources(
    provider: Optional[str] = None,
    account_id: Optional[int] = None,
    q: Optional[str] = Query(default=None, max_length=512),
    principal_type: Optional[str] = Query(default=None, max_length=64),
    trust: Optional[str] = Query(default=None, pattern="^(public|external|verified|account|none)$"),
    min_risk: Optional[float] = Query(default=None, ge=0, le=100),
    sort: str = Query(default="risk", pattern="^(risk|name|last_scanned|findings)$"),
    direction: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.list_identity_principals(
            session, provider=provider, account_id=account_id, query=q,
            principal_type=principal_type, trust_level=trust, min_risk=min_risk,
            sort=sort, direction=direction, page=page, page_size=page_size,
        )


@router.get("/identity/resources/{asset_id}", response_model=IdentityPrincipal)
def get_identity_resource(asset_id: int) -> dict[str, Any]:
    """Return the modeled CIEM view for one identity asset.

    The list endpoint remains optimized for browsing and filtering. This exact
    lookup gives the identity investigation page a refresh-safe URL without
    asking the frontend to reconstruct trust and authorization semantics from
    raw AWS payloads.
    """
    with get_sessionmaker()() as session:
        asset = session.get(Asset, asset_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="Identity principal not found")

        page = queries.list_identity_principals(
            session,
            account_id=asset.account_id,
            query=asset.resource_id,
            page=1,
            page_size=200,
        )
        principal = next(
            (item for item in page["items"] if item["id"] == asset_id),
            None,
        )
        if principal is None:
            raise HTTPException(status_code=404, detail="Asset is not an identity principal")
        return principal


@router.get("/data-security/resources", response_model=DataStorePage)
def get_data_security_resources(
    provider: Optional[str] = None,
    account_id: Optional[int] = None,
    q: Optional[str] = Query(default=None, max_length=512),
    service: Optional[str] = Query(default=None, max_length=64),
    store_type: Optional[str] = Query(default=None, max_length=64),
    label: Optional[str] = Query(default=None, max_length=64),
    region: Optional[str] = Query(default=None, max_length=64),
    exposure: Optional[str] = Query(default=None, pattern="^(private|vpc|public)$"),
    min_risk: Optional[float] = Query(default=None, ge=0, le=100),
    sort: str = Query(default="risk", pattern="^(risk|name|sensitivity|last_seen)$"),
    direction: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.list_data_security_resources(
            session, provider=provider, account_id=account_id, query=q,
            service=service, store_type=store_type, label=label, region=region,
            exposure=exposure, min_risk=min_risk, sort=sort,
            direction=direction, page=page, page_size=page_size,
        )


@router.get("")
def get_inventory(
    provider: Optional[str] = None,
    account_id: Optional[int] = None,
    asset_type: Optional[str] = Query(default=None, alias="type"),
    region: Optional[str] = None,
    is_public: Optional[bool] = None,
    is_active: Optional[bool] = True,
    tag_key: Optional[str] = Query(default=None, max_length=256),
    tag_value: Optional[str] = Query(default=None, max_length=1024),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.list_assets(
            session,
            provider=provider,
            account_id=account_id,
            asset_type=asset_type,
            region=region,
            is_public=is_public,
            is_active=is_active,
            tag_key=tag_key,
            tag_value=tag_value,
            page=page,
            page_size=page_size,
        )


@router.get("/assets/{asset_id}")
def get_asset_detail(asset_id: int) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        asset = queries.get_asset(session, asset_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        return asset


@router.get("/scan-jobs/{job_id}")
def get_scan_job(job_id: int) -> dict[str, Any]:
    from odineyes.db.models import ScanJob

    with get_sessionmaker()() as session:
        job = session.get(ScanJob, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Scan job not found")
        return queries.scan_job_to_dict(job, include_error=True)


class EvaluateIn(BaseModel):
    provider: str = Field(pattern="^(aws|azure|gcp)$")
    account_identifier: str


@router.get("/policy-catalog")
def get_builtin_policy_catalog(
    service: Optional[str] = Query(default=None, max_length=64),
    category: Optional[str] = Query(
        default=None,
        pattern="^(identity|compute|network|data|security|management|other)$",
    ),
    evaluation_mode: Optional[str] = Query(
        default=None,
        pattern="^(resource|relationship)$",
    ),
) -> dict[str, Any]:
    """Built-in persisted-policy coverage, independent of scan results."""
    from odineyes.inventory.rules import builtin_policy_catalog

    all_items = builtin_policy_catalog()
    items = [
        item for item in all_items
        if (service is None or item["service"] == service)
        and (category is None or item["category"] == category)
        and (evaluation_mode is None or item["evaluation_mode"] == evaluation_mode)
    ]

    def counts(field: str) -> dict[str, int]:
        result: dict[str, int] = {}
        for item in all_items:
            value = str(item[field])
            result[value] = result.get(value, 0) + 1
        return dict(sorted(result.items()))

    return {
        "summary": {
            "total": len(all_items),
            "resource_policies": sum(
                item["evaluation_mode"] == "resource" for item in all_items
            ),
            "relationship_policies": sum(
                item["evaluation_mode"] == "relationship" for item in all_items
            ),
            "evidence_gated": sum(item["evidence_gated"] for item in all_items),
            "by_service": counts("service"),
            "by_category": counts("category"),
        },
        "filtered_total": len(items),
        "items": items,
    }


@router.post("/findings/evaluate", dependencies=[Depends(require_operator)])
def evaluate_findings(body: EvaluateIn) -> dict[str, Any]:
    """Run the rules engine over the account's persisted assets and reconcile the
    findings table (open/resolve/reopen). Idempotent on an unchanged inventory."""
    stats = _service.evaluate_findings(body.provider, body.account_identifier)
    return {
        "total": stats.total, "new": stats.new,
        "reopened": stats.reopened, "resolved": stats.resolved,
        "suppressed": stats.suppressed,
    }


@router.get("/findings/resources", response_model=ModeledFindingPage)
def get_modeled_findings(
    account_id: Optional[int] = None,
    q: Optional[str] = Query(default=None, max_length=512),
    severity: Optional[str] = Query(default=None, pattern="^(critical|high|medium|low|info)$"),
    status: Optional[str] = Query(default="open", pattern="^(open|suppressed|resolved)$"),
    rule: Optional[str] = Query(default=None, max_length=128),
    category: Optional[str] = Query(default=None, pattern="^(identity|compute|network|data|security|management|other)$"),
    service: Optional[str] = Query(default=None, max_length=64),
    signal: Optional[str] = Query(default=None, pattern="^(active_threat|network_hygiene)$"),
    sort: str = Query(default="risk", pattern="^(risk|severity|last_seen|title)$"),
    direction: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.list_modeled_findings(
            session, account_id=account_id, query=q, severity=severity,
            status=status, rule_id=rule, category=category, service=service, signal=signal,
            sort=sort, direction=direction, page=page, page_size=page_size,
        )


@router.get("/findings")
def get_findings(
    account_id: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = "open",
    rule_id: Optional[str] = Query(default=None, alias="rule"),
    signal: Optional[str] = Query(default=None, pattern="^(active_threat|network_hygiene)$"),
) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.list_findings(
            session, account_id=account_id, severity=severity, status=status,
            rule_id=rule_id, signal=signal,
        )


@router.get("/findings/summary")
def get_findings_summary(account_id: Optional[int] = None) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.findings_summary(session, account_id=account_id)


# Auditor/ticketing evidence export. Same filters as GET /findings; CSV is the
# default (opens in Excel/Sheets, one row per finding with the fix command), JSON
# mirrors the API payload. Honours the active severity/status/rule filters so the
# operator exports exactly what's on screen.
_EXPORT_COLS = [
    "severity", "status", "signal", "rule_id", "title", "resource_id", "asset_type",
    "why", "remediation", "remediation_cli", "compliance",
    "suppressed_by", "suppressed_why",
    "first_seen_at", "last_seen_at", "resolved_at",
]


@router.get("/findings/export")
def export_findings(
    account_id: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = "open",
    rule_id: Optional[str] = Query(default=None, alias="rule"),
    signal: Optional[str] = Query(default=None, pattern="^(active_threat|network_hygiene)$"),
    fmt: str = Query(default="csv", alias="format", pattern="^(csv|json)$"),
) -> Response:
    with get_sessionmaker()() as session:
        data = queries.list_findings(
            session, account_id=account_id, severity=severity, status=status,
            rule_id=rule_id, signal=signal,
        )
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    if fmt == "json":
        return Response(
            json.dumps(data, indent=2), media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="findings-{ts}.json"'},
        )
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_EXPORT_COLS, extrasaction="ignore")
    writer.writeheader()
    for item in data["items"]:
        row = dict(item)
        # Flatten compliance {FW: [ctrl, ...]} into one auditor-readable cell.
        row["compliance"] = "; ".join(
            f"{fw}:{' '.join(ctrls)}" for fw, ctrls in (item.get("compliance") or {}).items()
        )
        writer.writerow(row)
    return Response(
        buf.getvalue(), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="findings-{ts}.csv"'},
    )


@router.post("/issues/evaluate", dependencies=[Depends(require_operator)])
def evaluate_issues(body: EvaluateIn) -> dict[str, Any]:
    """Run the attack-path engine over the account's persisted assets, reconcile
    the issues table (open/resolve/reopen), and refresh per-asset risk scores."""
    stats = _service.evaluate_issues(body.provider, body.account_identifier)
    return {
        "total": stats.total, "new": stats.new,
        "reopened": stats.reopened, "resolved": stats.resolved,
    }


@router.get("/issues")
def get_issues(
    account_id: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = "open",
    issue_type: Optional[str] = Query(default=None, alias="type"),
) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.list_issues(
            session, account_id=account_id, severity=severity, status=status, issue_type=issue_type,
        )


@router.get("/issues/summary")
def get_issues_summary(account_id: Optional[int] = None) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.issues_summary(session, account_id=account_id)


@router.get("/graph")
def get_graph(
    provider: str = "aws",
    account: Optional[str] = Query(default=None, description="account_identifier, 'all' for fleet, or omit for first"),
) -> dict[str, Any]:
    """Security graph (nodes + edges) with open attack-path issues overlaid as
    finding nodes and every reachable attacker route under ``paths`` — feeds the
    Wiz-style graph canvas. ``account=all`` merges every account into one
    fleet-wide graph; omitting it defaults to the first registered account."""
    with get_sessionmaker()() as session:
        accts = queries.list_accounts(session)
    roster = [
        {"provider": a["provider"], "account_identifier": a["account_identifier"], "name": a["name"]}
        for a in accts
    ]
    if account == "all":
        data = _service.build_graph(provider, None)
    elif account is None:
        if not accts:
            data = _service.build_graph(provider, None)
            data["account"] = None
            data["accounts"] = []
            return data
        data = _service.build_graph(accts[0]["provider"], accts[0]["account_identifier"])
    else:
        data = _service.build_graph(provider, account)
    data["accounts"] = roster
    return data


# ── vulnerabilities (CWPP) ─────────────────────────────────────

class VulnScanIn(BaseModel):
    provider: str = Field(default="aws", pattern="^(aws|azure|gcp)$")
    account_identifier: str
    region: str = Field(default="us-east-1", pattern=_REGION_PATTERN, max_length=64)


@router.post("/vulnerabilities/scan", dependencies=[Depends(require_operator)])
def scan_vulnerabilities(body: VulnScanIn) -> dict[str, Any]:
    """Package-inventory the account's EC2 via SSM and match against OSV, then
    persist the CVEs. Needs live AWS credentials with ssm + read access."""
    try:
        stats = _service.scan_vulnerabilities(body.provider, body.account_identifier, region=body.region)
    except Exception as e:  # noqa: BLE001 — surface a clean message, log detail
        import logging
        logging.getLogger(__name__).error("vuln scan failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="vulnerability scan failed (check AWS credentials / SSM access)")
    return {
        "total": stats.total, "new": stats.new, "reopened": stats.reopened,
        "resolved": stats.resolved, "instances_scanned": stats.instances_scanned,
        "ssm_managed": stats.ssm_managed,
    }


class ImageScanIn(BaseModel):
    provider: str = Field(default="aws", pattern="^(aws|azure|gcp)$")
    account_identifier: str
    region: str = Field(default="us-east-1", pattern=_REGION_PATTERN, max_length=64)
    # Optional explicit image refs; when empty, ECR is auto-discovered.
    image_refs: list[str] = Field(default_factory=list, max_length=500)


class EbsSnapshotScanIn(BaseModel):
    provider: str = Field(default="aws", pattern="^(aws)$")
    account_identifier: str
    region: str = Field(default="us-east-1", pattern=_REGION_PATTERN, max_length=64)
    snapshot_id: str = Field(pattern=r"^snap-[0-9a-fA-F]{8,32}$", max_length=40)


class EbsInstanceScanIn(BaseModel):
    provider: str = Field(default="aws", pattern="^(aws)$")
    account_identifier: str
    region: str = Field(default="us-east-1", pattern=_REGION_PATTERN, max_length=64)
    instance_id: str = Field(pattern=r"^i-[0-9a-fA-F]{8,32}$", max_length=40)


@router.post("/vulnerabilities/scan-images", dependencies=[Depends(require_operator)])
def scan_container_vulnerabilities(body: ImageScanIn) -> dict[str, Any]:
    """Scan container images (auto-discovered from ECR, or explicit refs) with
    Trivy and persist the CVEs. Needs the trivy binary + AWS ECR read access;
    images that can't be scanned are reported skipped, never faked."""
    try:
        stats = _service.scan_container_vulnerabilities(
            body.provider, body.account_identifier, region=body.region,
            image_refs=body.image_refs or None,
        )
    except Exception as e:  # noqa: BLE001 — surface a clean message, log detail
        import logging
        logging.getLogger(__name__).error("image scan failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="container image scan failed (check trivy install / ECR access)")
    return {
        "total": stats.total, "new": stats.new, "reopened": stats.reopened,
        "resolved": stats.resolved, "images_discovered": stats.instances_scanned,
        "images_scanned": stats.ssm_managed,
    }


@router.post("/vulnerabilities/scan-ebs-snapshot", dependencies=[Depends(require_operator)])
def scan_ebs_snapshot_vulnerabilities(body: EbsSnapshotScanIn) -> dict[str, Any]:
    """Read-only EBS Direct vulnerability scan for an existing private snapshot.

    Requires the account's separately onboarded disk-scan role. The endpoint
    never creates a snapshot or persists file contents or secret values.
    """
    try:
        result = _service.scan_ebs_snapshot_vulnerabilities(
            body.provider, body.account_identifier, snapshot_id=body.snapshot_id, region=body.region,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("EBS snapshot vulnerability scan failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="EBS snapshot scan failed")
    sync = result.sync
    return {
        "snapshot_id": result.snapshot_id,
        "scanned": result.scanned,
        "component_count": result.component_count,
        "findings_count": result.findings_count,
        "skipped_reason": result.skipped_reason,
        "total": sync.total if sync else 0,
        "new": sync.new if sync else 0,
        "reopened": sync.reopened if sync else 0,
        "resolved": sync.resolved if sync else 0,
    }


@router.post(
    "/vulnerabilities/scan-ec2-instance", status_code=202,
    dependencies=[Depends(require_operator)],
)
def scan_ec2_instance_vulnerabilities(
    body: EbsInstanceScanIn, background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    """Queue one root-volume agentless scan using Aqua Trivy.

    Background execution avoids CloudFront's request timeout. The lifecycle
    assumes the account's opt-in disk role, applies cooldown and size guards,
    creates a tagged incremental snapshot, invokes ``trivy vm``, persists CVEs
    against the EC2 asset, and deletes the temporary snapshot in ``finally``.
    """
    background_tasks.add_task(
        _service.scan_ec2_instance_vulnerabilities,
        body.provider,
        body.account_identifier,
        instance_id=body.instance_id,
        region=body.region,
    )
    return {
        "status": "queued",
        "provider": body.provider,
        "account_identifier": body.account_identifier,
        "region": body.region,
        "instance_id": body.instance_id,
        "scanner": "aquasecurity-trivy",
        "scan_kind": "ebs_instance",
    }


class SbomIn(BaseModel):
    image_ref: str
    region: str = Field(default="us-east-1", pattern=_REGION_PATTERN, max_length=64)
    profile: Optional[str] = None


@router.post("/vulnerabilities/sbom", dependencies=[Depends(require_operator)])
def generate_image_sbom(body: SbomIn) -> dict[str, Any]:
    """CycloneDX SBOM for one container image via Trivy. Read-only; if trivy
    isn't installed the response is generated=false with a reason, never faked."""
    ref = body.image_ref.strip()
    if not ref or ref.startswith("-"):
        raise HTTPException(status_code=400, detail="invalid image_ref")
    from odineyes.cloud.trivy_scanner import TrivyScanner
    try:
        res = TrivyScanner(region=body.region, profile=body.profile).sbom_image(ref)
    except Exception as e:  # noqa: BLE001 — surface clean message, log detail
        import logging
        logging.getLogger(__name__).error("SBOM generation failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="SBOM generation failed")
    return {
        "image_ref": res.image_ref, "generated": res.generated, "format": "cyclonedx",
        "component_count": res.component_count, "skipped_reason": res.skipped_reason,
        "sbom": res.sbom,
    }


@router.get("/vulnerabilities")
def get_vulnerabilities(
    account_id: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = "open",
    resource_id: Optional[str] = None,
) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.list_vulnerabilities(
            session, account_id=account_id, severity=severity, status=status, resource_id=resource_id,
        )


@router.get("/vulnerabilities/summary")
def get_vulnerabilities_summary(account_id: Optional[int] = None) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.vulnerabilities_summary(session, account_id=account_id)


# ── NVD CVE catalog (browse the full CVE dictionary) ───────────

@router.get("/cve-catalog")
def get_cve_catalog(
    severity: Optional[str] = None,
    keyword: Optional[str] = Query(default=None, alias="q"),
    since: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    """Paginated browse over the full NVD CVE catalog. Server-side filter
    (severity / keyword / modified-since) + LIMIT/OFFSET keep the tab snappy
    regardless of catalog size."""
    since_dt = None
    if since:
        try:
            since_dt = datetime.datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="since must be ISO8601")
    with get_sessionmaker()() as session:
        return queries.list_cve_catalog(
            session, severity=severity, keyword=keyword, since=since_dt,
            page=page, page_size=page_size,
        )


@router.get("/cve-catalog/summary")
def get_cve_catalog_summary() -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.cve_catalog_summary(session)


@router.get("/cve-catalog/{cve_id}")
def get_cve_detail(cve_id: str) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        cve = queries.get_cve(session, cve_id)
        if cve is None:
            raise HTTPException(status_code=404, detail="CVE not in catalog")
        return cve


class CveIngestIn(BaseModel):
    directory: Optional[str] = None  # dir of NVD-2.0 *.json/*.json.gz feed files
    incremental: bool = False        # API delta of CVEs modified in the last N days
    days: int = Field(default=7, ge=1, le=120)


@router.post("/cve-catalog/ingest", dependencies=[Depends(require_operator)])
def ingest_cve_catalog(body: CveIngestIn) -> dict[str, Any]:
    """Bulk-load the catalog. From a directory of NVD feed files (fastest, no
    rate limit) or an incremental API delta. Synchronous — a full load takes a
    while; prefer the directory source for the initial import."""
    from odineyes.scanner import nvd_catalog

    with session_scope() as session:
        if body.directory:
            try:
                count = nvd_catalog.ingest_dir(session, body.directory)
            except FileNotFoundError as e:
                raise HTTPException(status_code=400, detail=str(e))
            return {"source": "directory", "ingested": count}
        if body.incremental:
            since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=body.days)
            count = nvd_catalog.ingest_api(session, last_modified_since=since)
            return {"source": "api-delta", "days": body.days, "ingested": count}
    raise HTTPException(status_code=400, detail="provide 'directory' or set 'incremental'")


# ── persisted graph edges (attack-path backbone) ───────────────

@router.get("/graph-edges")
def get_graph_edges(
    account_id: Optional[int] = None,
    edge_type: Optional[str] = Query(default=None, alias="type"),
    src_id: Optional[str] = Query(default=None, alias="src"),
    is_active: Optional[bool] = True,
) -> dict[str, Any]:
    """Persisted security-graph edges (relationships) with history. Synced on
    every issues evaluation; filter by type/src/active."""
    with get_sessionmaker()() as session:
        return queries.list_graph_edges(
            session, account_id=account_id, edge_type=edge_type, src_id=src_id, is_active=is_active,
        )


# ── persisted DSPM findings (data sensitivity per store) ───────

@router.get("/dspm")
def get_dspm(
    account_id: Optional[int] = None,
    label: Optional[str] = None,
    store_type: Optional[str] = Query(default=None, alias="type"),
) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.list_dspm(session, account_id=account_id, label=label, store_type=store_type)


@router.get("/dspm/summary")
def get_dspm_summary(account_id: Optional[int] = None) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.dspm_summary(session, account_id=account_id)


# ── runtime / threat events ────────────────────────────────────

@router.get("/runtime-events")
def get_runtime_events(
    account_id: Optional[int] = None,
    event_type: Optional[str] = Query(default=None, alias="type"),
    severity: Optional[str] = None,
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.list_runtime_events(
            session, account_id=account_id, event_type=event_type, severity=severity, limit=limit,
        )


@router.get("/runtime-events/summary")
def get_runtime_events_summary(account_id: Optional[int] = None) -> dict[str, Any]:
    with get_sessionmaker()() as session:
        return queries.runtime_events_summary(session, account_id=account_id)


@router.get("/runtime/agents")
def get_runtime_agents(account_id: Optional[int] = None) -> dict[str, Any]:
    """eBPF sensor agents grouped by OS platform with deployment/liveness status
    (online/stale/no_sensor/unsupported). Derived from EC2 inventory + runtime
    events — Windows/other hosts surface as 'unsupported' (eBPF is Linux-only)."""
    with get_sessionmaker()() as session:
        return queries.runtime_agents(session, account_id=account_id)


@router.get("/exploitation")
def get_exploitation(account_id: Optional[int] = None) -> dict[str, Any]:
    """Open attack paths currently being actively walked (Step-4 correlation:
    runtime eBPF events landed on a hop in the path). Stale 'live' flags decay
    first so this reflects current state, not history."""
    from odineyes.inventory.exploitation import reconcile
    with session_scope() as session:
        reconcile(session)
        return queries.exploitation_summary(session, account_id=account_id)


@router.get("/runtime/findings")
def get_runtime_findings(
    account_id: Optional[int] = None,
    host_id: Optional[str] = None,
    severity: Optional[str] = None,
    rule_id: Optional[str] = Query(default=None, alias="rule"),
    since: Optional[str] = None,
    limit: int = Query(default=500, ge=1, le=2000),
) -> dict[str, Any]:
    """Runtime detection findings (events carrying a sensor.detection rule_id)
    across all hosts. Filter by host_id, severity, rule, and since (ISO8601)."""
    since_dt = None
    if since:
        try:
            since_dt = datetime.datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="since must be ISO8601")
    with get_sessionmaker()() as session:
        return queries.list_runtime_findings(
            session, account_id=account_id, host_id=host_id, severity=severity,
            rule_id=rule_id, since=since_dt, limit=limit,
        )


# ── continuous compliance (persisted snapshots + drift) ────────

@router.get("/compliance/current")
def get_compliance_current(account_id: Optional[int] = None) -> dict[str, Any]:
    """Latest persisted compliance snapshot per framework (continuous score).
    ``account_id`` scopes to one account's snapshots (snapshots store the
    account_identifier they were captured against)."""
    with get_sessionmaker()() as session:
        account = None
        if account_id is not None:
            row = session.get(CloudAccount, account_id)
            account = row.account_identifier if row else "__none__"  # unknown id -> empty, never all
        return queries.compliance_current(session, account=account)


@router.get("/compliance/report")
def get_compliance_report(account_id: Optional[int] = None, frameworks: str = "CIS,SOC2,NIST,PCI-DSS") -> dict[str, Any]:
    """Generates the detailed compliance control breakdown dynamically from the current DB findings.

    Findings in the DB come from the rules engine and carry rule_ids like
    WORLD_OPEN_SENSITIVE_PORT / PUBLIC_BUCKET, NOT CheckRegistry check_ids like
    iam_aws_001.  Each Finding also stores its own compliance JSON that maps it
    to framework controls (e.g. {"CIS": ["5.2"], "SOC2": ["CC6.1"]}).

    We feed BOTH sources into the ComplianceMapper:
      1. Real DB findings  → drive fail/pass verdicts on controls they map to.
      2. CheckRegistry checks (all marked 'pass' by default) → ensure every
         known check shows up so the mapper's universe of controls stays
         complete.  If the DB has no findings at all these show 'not_assessed'.
    """
    from odineyes.core.compliance_mapper import ComplianceMapper
    from odineyes.db.models import Finding, CloudAccount
    from odineyes.core.check_registry import CheckRegistry
    from sqlalchemy import select

    with get_sessionmaker()() as session:
        stmt = select(Finding)
        acct = None
        if account_id is not None:
            acct = session.get(CloudAccount, account_id)
            stmt = stmt.where(Finding.account_id == account_id)

        db_findings = session.execute(stmt).scalars().all()

        # ── 1. Build mapped_findings from REAL DB findings ──────────
        #
        # A single rule_id may fire on many resources.  The mapper collapses by
        # check_id — a check_id is "fail" if ANY finding with that rule_id is
        # open.  We deduplicate here so the mapper sees one entry per rule_id
        # with the worst-case status.
        rule_status: dict[str, str] = {}
        rule_compliance: dict[str, dict] = {}
        for f in db_findings:
            rid = f.rule_id
            # open → fail, anything else → pass
            status = "fail" if f.status == "open" else "pass"
            prev = rule_status.get(rid)
            if prev is None or status == "fail":
                rule_status[rid] = status
            # keep the richest compliance mapping we've seen
            if rid not in rule_compliance and f.compliance:
                rule_compliance[rid] = f.compliance

        mapped_findings = [
            {
                "check_id": rid,
                "status": rule_status[rid],
                "compliance_mappings": rule_compliance.get(rid, {}),
            }
            for rid in rule_status
        ]

        # ── 2. Also include CheckRegistry checks for control-coverage ──
        #
        # The CheckRegistry holds compliance mappings for controls that may not
        # have any DB findings yet (either because no resources trigger them, or
        # because no scan has run).  If a DB finding already covers a
        # check_id we skip it so the DB verdict wins.
        has_findings = len(db_findings) > 0
        providers = [acct.provider] if acct else ["aws", "gcp", "azure"]
        registry = CheckRegistry()
        all_checks = registry.resolve_checks(providers, ["all"], [], [])
        seen_ids = set(rule_status.keys())

        for check in all_checks:
            if check.check_id in seen_ids:
                continue
            # If there ARE findings for this account, the check simply didn't fire
            # → the check implicitly passed.  If there are NO findings at all
            # (no scan has run), everything is not_assessed.
            mapped_findings.append({
                "check_id": check.check_id,
                "status": "pass" if has_findings else "not_assessed",
                "compliance_mappings": check.compliance or {},
            })

        mapper = ComplianceMapper()
        fws = [f.strip() for f in frameworks.split(",") if f.strip()]
        comp = mapper.score(mapped_findings, fws)

        return {"compliance": comp}


@router.get("/compliance/history")
def get_compliance_history(
    framework: str,
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    """Score time-series for one framework (trend)."""
    with get_sessionmaker()() as session:
        return queries.compliance_history(session, framework=framework, limit=limit)


@router.get("/compliance/drift")
def get_compliance_drift(
    framework: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    """Recent control state transitions (pass↔fail) — dynamic drift."""
    with get_sessionmaker()() as session:
        return queries.compliance_drift(session, framework=framework, limit=limit)


# ── IaC pre-deploy scan ────────────────────────────────────────

class IacScanIn(BaseModel):
    content: str
    filename: Optional[str] = None
    engine: str = Field(default="builtin", pattern="^(builtin|checkov|trivy)$")


@router.post("/iac/scan", dependencies=[Depends(require_operator)])
def scan_iac(body: IacScanIn) -> dict[str, Any]:
    """Stateless pre-deploy misconfig scan of a Terraform plan JSON or
    CloudFormation template (JSON/YAML). No persistence.

    engine=builtin (default) runs the in-tree scanner; engine=checkov runs
    Checkov when installed (broad policy set); engine=trivy runs
    `trivy config` when installed. Either external engine falls back to
    builtin when its binary is absent."""
    if len(body.content) > 2_000_000:
        raise HTTPException(status_code=413, detail="template too large (2MB limit)")

    if body.engine in ("checkov", "trivy"):
        runner = {"checkov": "checkov_runner", "trivy": "trivy_runner"}[body.engine]
        module = __import__(f"odineyes.iac.{runner}", fromlist=[runner])
        if module.available():
            try:
                return module.scan_content(body.content, body.filename)
            except Exception as e:  # noqa: BLE001 — fall back to the in-tree scanner
                logger.warning("%s scan failed, falling back to builtin: %s", body.engine, e)
        else:
            logger.info("%s requested but not installed; using builtin scanner", body.engine)

    from odineyes.iac.scanner import scan
    return scan(body.content)


class ScanOneIn(BaseModel):
    region: str = Field(default="us-east-1", pattern=_REGION_PATTERN, max_length=64)


class MisconfigScanIn(BaseModel):
    region: Optional[str] = Field(default=None, pattern=_REGION_PATTERN, max_length=64)
    services: Optional[list[str]] = Field(default=None, max_length=32)


def _misconfig_scan_task(account_id: int, identifier: str,
                         role_arn: Optional[str], external_id: Optional[str],
                         region: Optional[str], services: Optional[list[str]]) -> None:
    """Background Trivy misconfig scan for one account. Assumes the account's
    role (like the collector does), runs ``trivy aws`` with the temporary
    credentials via child env only, and merges findings into the shared
    findings table. Never raises into the request loop."""
    try:
        from odineyes.cloud.trivy_scanner import TrivyScanner

        session: Any = None
        if role_arn:
            session = TrivyScanner.assume_role_session(
                role_arn=role_arn, external_id=external_id,
                region=region or "us-east-1",
                session_name="odineyes-misconfig-scan",
            )
        result = _service.scan_trivy_misconfig(
            "aws", identifier, region=region, session=session, services=services,
        )
        logger.info("trivy misconfig scan account %s: %s", identifier, result)
    except Exception:  # noqa: BLE001 - background task must not crash the loop
        logger.warning("trivy misconfig scan failed for account %s",
                       identifier, exc_info=True)


@router.post("/accounts/{account_id}/misconfig-scan", status_code=202,
             dependencies=[Depends(require_operator)])
def scan_account_misconfig(
    account_id: int, body: MisconfigScanIn, background_tasks: BackgroundTasks
) -> dict[str, Any]:
    """Run Trivy's AWS misconfiguration engine (AVD-AWS-*) against one account
    and merge its findings into the shared findings table.

    Fire-and-forget like /scan: the scan fans out across every enabled region
    and dozens of services, which no HTTP origin should wait on. Poll the
    findings endpoints for the AVD-AWS-* results. ``ODINEYES_TRIVY_MISCONFIG``
    gates the engine (auto|on|off)."""
    with session_scope() as session:
        account = session.get(CloudAccount, account_id)
        if account is None or not account.is_active:
            raise HTTPException(status_code=404, detail="account not found or inactive")
        if account.provider != "aws":
            raise HTTPException(status_code=400, detail="trivy misconfig scanning is AWS-only")
        identifier = account.account_identifier
        role_arn = account.role_arn
        external_id = account.external_id

    background_tasks.add_task(
        _misconfig_scan_task, account_id, identifier, role_arn, external_id,
        body.region, body.services,
    )
    return {
        "status": "started",
        "engine": "trivy-aws",
        "account_id": account_id,
        "account_identifier": identifier,
    }


def _run_one_account_scan(account_id: int, region: str) -> None:
    """Background wrapper for a single-account scan. ``scan_account`` already
    records failure on the ScanJob row, so there is nothing to raise into."""
    try:
        result = _run_account_scan(account_id, region)
        logger.info("scan account %s: %s", account_id,
                    result.status if result else "account not found or inactive")
    except Exception as exc:  # noqa: BLE001 — a background task must not crash the loop
        logger.warning("scan failed for account %s: %s", account_id, exc)


@router.post("/accounts/{account_id}/scan", status_code=202,
             dependencies=[Depends(require_operator)])
def scan_one_account(
    account_id: int, body: ScanOneIn, background_tasks: BackgroundTasks
) -> dict[str, Any]:
    """Start a scan of ONE registered account and return immediately.

    Assumes the account's role (with its ExternalId), then
    collect → persist → rules → attack-path, all tagged to this account's id so
    its data stays isolated from every other account.

    This used to run inside the request, which meant the same 504 that /scan-all
    had: a live multi-region scan takes minutes and CloudFront gives the origin
    30 seconds. Failure is still visible — ``scan_account`` opens the ScanJob
    row *before* AssumeRole, so a credential error lands on that row with its
    message rather than vanishing. Poll ``GET /scan-all/status`` and read the
    row for this account_id.
    """
    from sqlalchemy import func

    with session_scope() as session:
        account = session.get(CloudAccount, account_id)
        if account is None or not account.is_active:
            raise HTTPException(status_code=404, detail="account not found or inactive")
        # Starting a rival scan of the same account would race the same rows and
        # double the collector's memory on a 1 GB host.
        running = session.query(ScanJob).filter(
            ScanJob.account_id == account_id,
            ScanJob.status.in_(("queued", "running")),
        ).count()
        # The job row is opened by the background task, so for a moment after
        # this returns the newest job is still the *previous* one. Hand back its
        # id: a poller that ignores everything up to this watermark cannot read
        # the last scan's result as this one's.
        last_job_id = session.query(func.max(ScanJob.id)).filter(
            ScanJob.account_id == account_id
        ).scalar() or 0
        identifier = account.account_identifier

    if running:
        raise HTTPException(status_code=409, detail="scan already running for this account")

    background_tasks.add_task(_run_one_account_scan, account_id, body.region)
    return {
        "status": "started",
        "account_id": account_id,
        "account_identifier": identifier,
        "last_job_id": last_job_id,
        "poll": "/api/inventory/scan-all/status",
    }


class VerifyIn(BaseModel):
    region: str = Field(default="us-east-1", pattern=_REGION_PATTERN, max_length=64)


def _onboarding_role_arn(account: CloudAccount) -> str:
    """Return generated role ARN without accepting a caller-supplied ARN.

    Quick Create always creates ``OdineyesReadOnly`` in the entered account.
    Keeping this derivation server-side prevents a pending connection from being
    pointed at a role in another customer account.
    """
    if account.provider != "aws" or not re.fullmatch(r"\d{12}", account.account_identifier):
        raise HTTPException(status_code=400, detail="automatic verification is AWS-only")
    return account.role_arn or f"arn:aws:iam::{account.account_identifier}:role/OdineyesReadOnly"


@router.post("/accounts/{account_id}/verify", dependencies=[Depends(require_operator)])
def verify_account_access(account_id: int, body: VerifyIn) -> dict[str, Any]:
    """Automated onboarding diagnosis: assume the account's role, then make one
    real read call, and report each stage separately. Replaces the manual
    "aws sts assume-role ... then aws ec2 describe-instances" dance a client
    would otherwise run by hand — click Verify, get a structured answer instead
    of a raw AWS error to interpret.

    Also probes one representative action per collection domain, so an
    out-of-date onboarding stack or an SCP is reported as a named coverage gap
    instead of surfacing later as findings that silently never appear."""
    from odineyes.inventory.orchestrator import AccountRef, MultiAccountOrchestrator

    with session_scope() as session:
        acct = session.get(CloudAccount, account_id)
        if acct is None:
            raise HTTPException(status_code=404, detail="account not found")
        ref = AccountRef(acct.account_identifier, acct.name, acct.role_arn,
                         acct.provider, acct.external_id,
                         excluded_regions=tuple(json.loads(acct.excluded_regions or "[]")))

    result = MultiAccountOrchestrator(_service, region=body.region).verify_access(ref, deep=True)

    # Persist the outcome so the accounts table shows standing health rather
    # than only whatever the operator last clicked.
    if not result["assume"]["ok"]:
        status = "unreachable"
    elif not result["read"]["ok"]:
        status = "no_read"
    elif result.get("permissions", {}).get("healthy", True):
        status = "healthy"
    else:
        status = "degraded"
    with session_scope() as session:
        acct = session.get(CloudAccount, account_id)
        if acct is not None:
            acct.last_verify_status = status
            acct.last_verified_at = datetime.datetime.now(datetime.timezone.utc)
    result["verify_status"] = status
    return result


@router.post("/accounts/{account_id}/verify-onboarding", dependencies=[Depends(require_operator)])
def verify_one_click_onboarding(
    account_id: int, body: VerifyIn, background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    """Verify a pending Quick Create stack and connect it when STS succeeds.

    No callback credential is stored in customer CloudFormation.  When the
    browser returns from AWS, this endpoint derives the only valid role ARN,
    calls AssumeRole with the stored account-specific ExternalId, and only then
    activates scanning.
    """
    from odineyes.inventory.orchestrator import AccountRef, MultiAccountOrchestrator

    with session_scope() as session:
        account = session.get(CloudAccount, account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="account not found")
        role_arn = _onboarding_role_arn(account)
        ref = AccountRef(
            account.account_identifier, account.name, role_arn, account.provider, account.external_id,
        )

    verification = MultiAccountOrchestrator(_service, region=body.region).verify_access(ref)
    ready = bool(verification.get("assume", {}).get("ok") and verification.get("read", {}).get("ok"))
    if not ready:
        return {"status": "awaiting_stack", "connected": False, "verification": verification}

    with session_scope() as session:
        account = session.get(CloudAccount, account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="account not found")
        account.role_arn = role_arn
        account.is_active = True
        account.onboarding_status = "connected"
        session.flush()

    background_tasks.add_task(_auto_scan, account_id, body.region)
    return {"status": "connected", "connected": True, "verification": verification}


class ScanAllIn(BaseModel):
    provider: str = Field(default="aws", pattern="^(aws|azure|gcp)$")
    region: str = Field(default="us-east-1", pattern=_REGION_PATTERN, max_length=64)
    max_workers: int = Field(default=4, ge=1, le=16)


def _run_fleet_scan(provider: str, region: str, max_workers: int) -> None:
    """Background fleet scan. Best-effort: the 202 has already gone out, so a
    failure is logged and the per-account ScanJob rows carry the detail."""
    from odineyes.inventory.orchestrator import MultiAccountOrchestrator

    try:
        results = MultiAccountOrchestrator(
            _service, region=region, max_workers=max_workers,
        ).scan_all(provider)
        logger.info(
            "fleet scan finished: %d account(s), %d completed, %d failed",
            len(results),
            sum(1 for r in results if r.status == "completed"),
            sum(1 for r in results if r.status == "failed"),
        )
    except Exception as exc:  # noqa: BLE001 — a background task must not crash the loop
        logger.warning("fleet scan failed: %s", exc)


@router.post("/scan-all", status_code=202, dependencies=[Depends(require_operator)])
def scan_all_accounts(body: ScanAllIn, background_tasks: BackgroundTasks) -> dict[str, Any]:
    """Start a fleet scan and return immediately.

    Every active registered account is scanned in parallel — STS assume-role
    per account where a role_arn is registered, then the full
    collect → persist → rules → attack-path pipeline.

    This used to run inside the request. A live multi-region sweep takes
    minutes and CloudFront gives the origin 30 seconds, so the caller always
    got a 504 while the scan carried on invisibly on the box: no result, no
    error, and no way to tell a slow scan from a broken one. The work is the
    same, it just no longer happens inside a response the network will not wait
    for. Progress is the per-account ScanJob rows, which the pipeline already
    writes — poll ``GET /scan-all/status``.
    """
    with session_scope() as session:
        accounts = session.query(CloudAccount).filter(
            CloudAccount.provider == body.provider,
            CloudAccount.is_active.is_(True),
        ).all()
        account_ids = [a.id for a in accounts]
        # A second click while the first sweep is still going would double the
        # collector's memory on a 1 GB host and race the same rows. Report the
        # scan already in flight instead of starting a rival one.
        running = session.query(ScanJob).filter(
            ScanJob.account_id.in_(account_ids or [0]),
            ScanJob.status.in_(("queued", "running")),
        ).count() if account_ids else 0

    if running:
        return {
            "status": "already_running",
            "accounts": len(account_ids),
            "in_flight": running,
            "poll": "/api/inventory/scan-all/status",
        }

    background_tasks.add_task(
        _run_fleet_scan, body.provider, body.region, body.max_workers,
    )
    return {
        "status": "started",
        "accounts": len(account_ids),
        "in_flight": 0,
        "poll": "/api/inventory/scan-all/status",
    }


@router.get("/scan-all/status")
def scan_all_status(provider: str = Query(default="aws", pattern="^(aws|azure|gcp)$")) -> dict[str, Any]:
    """Latest scan job per active account, plus whether a sweep is still going.

    ``running`` is what a poller watches: it stays true until every account's
    most recent job has left queued/running. An account that has never been
    scanned reports a null job rather than being omitted, so the caller can
    tell "not started" from "finished".
    """
    from sqlalchemy import func

    with session_scope() as session:
        accounts = session.query(CloudAccount).filter(
            CloudAccount.provider == provider,
            CloudAccount.is_active.is_(True),
        ).all()
        if not accounts:
            return {"running": False, "accounts": [], "completed": 0, "failed": 0, "pending": 0}

        latest_ids = {
            account_id: job_id
            for account_id, job_id in session.query(
                ScanJob.account_id, func.max(ScanJob.id)
            ).filter(
                ScanJob.account_id.in_([a.id for a in accounts])
            ).group_by(ScanJob.account_id).all()
        }
        jobs = {
            job.account_id: job
            for job in session.query(ScanJob).filter(
                ScanJob.id.in_(list(latest_ids.values()) or [0])
            ).all()
        } if latest_ids else {}

        rows = []
        for account in accounts:
            job = jobs.get(account.id)
            rows.append({
                "account_id": account.id,
                "account_identifier": account.account_identifier,
                "name": account.name,
                "job": queries.scan_job_to_dict(job, include_error=True) if job else None,
            })

        statuses = [r["job"]["status"] if r["job"] else None for r in rows]
        return {
            "running": any(s in ("queued", "running") for s in statuses),
            "completed": sum(1 for s in statuses if s == "completed"),
            "failed": sum(1 for s in statuses if s == "failed"),
            "pending": sum(1 for s in statuses if s is None),
            "accounts": rows,
        }
