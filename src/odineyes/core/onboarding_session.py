"""Session-based one-click onboarding: mint a launch link, redeem its callback.

The shape that matters:

    operator clicks "generate link"
        -> session row (pending) + server-generated ExternalId + signed token
        -> one shared, secret-free template published to S3
        -> quick-create URL with every parameter pre-filled

    customer opens the link while signed into whichever account they want
        -> CloudFormation creates the read-only role
        -> a custom-resource Lambda POSTs the role ARN back, once, on Create

    callback redeemed
        -> account row connected, session burned, first scan queued

The customer never pastes a role ARN and never types their account id. The
account is *discovered* from the ARN CloudFormation produced, which is by
construction the account the stack actually ran in.

Everything the callback asserts is checked against state we already hold, so an
authenticated caller still cannot enrol an account the stack did not run in.
"""

from __future__ import annotations

import hmac
import logging
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from odineyes.core import onboarding_token as tokens
from odineyes.core.onboarding_hosting import (
    OnboardingHostingConfigurationError,
    public_api_url,
    publish_shared_template,
    quick_create_url,
)
from odineyes.db.models import CloudAccount, OnboardingSession
from odineyes.inventory.repository import AccountRepository

logger = logging.getLogger(__name__)

ROLE_ARN_RE = re.compile(r"arn:aws[a-z-]*:iam::(\d{12}):role/[\w+=,.@/-]+")
CALLBACK_PATH = "/api/inventory/accounts/onboarding-callback"
ROLE_NAME = "OdineyesReadOnly"


class OnboardingSessionError(Exception):
    """A request that must be refused. ``status`` is the HTTP code to return."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass(frozen=True)
class LaunchLink:
    session_id: str
    launch_url: str
    template_url: str
    template_checksum: str
    template_reused: bool
    external_id: str
    expires_at: str
    label: Optional[str]
    superseded_links: int
    callback_url: str
    callback_enabled: bool

    def to_dict(self) -> dict[str, Any]:
        return dict(vars(self))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def create_link(
    session: Session,
    *,
    label: Optional[str] = None,
    ttl_seconds: int = tokens.DEFAULT_TTL_SECONDS,
    console_region: Optional[str] = None,
    with_callback: bool = True,
    policy_mode: str = "managed",
) -> LaunchLink:
    """Mint a one-click launch URL. No account id required, nothing to copy.

    With ``with_callback=False`` the link still pre-fills everything else but
    leaves ``OnboardingToken`` and ``CallbackUrl`` empty. The template's
    ``AutoConnect`` condition then goes false and no Lambda is created at all —
    the right shape whenever the platform has no publicly reachable endpoint,
    since a stack that cannot reach its callback rolls itself back and takes the
    created role with it. The session is still recorded, so ``register_manual``
    can complete it from the stack's RoleArn output.
    """
    from odineyes.core.iac_templates import (
        cloudformation_parameterized_template,
        odineyes_account_id,
        odineyes_scanner_principal_arn,
    )

    ttl = max(tokens.MIN_TTL_SECONDS, min(int(ttl_seconds), tokens.MAX_TTL_SECONDS))
    # Only the callback needs a public endpoint; demanding one for a link that
    # has no callback would block the very path that works without it.
    api_base = public_api_url() if with_callback else ""

    scanner_principal = odineyes_scanner_principal_arn()
    if scanner_principal.endswith(":root"):
        raise OnboardingHostingConfigurationError(
            "ODINEYES_SCANNER_PRINCIPAL_ARN must name the specific IAM scanner user or "
            "role; account root cannot be trusted for one-click onboarding"
        )

    # The template URL must outlive the link it is embedded in, or a customer
    # who opens the link late gets a broken stack review.
    published = publish_shared_template(
        cloudformation_parameterized_template(policy_mode), url_ttl_seconds=ttl
    )

    session_id = tokens.new_session_id()
    # Generated per session rather than per tenant — no account is known yet.
    # Long enough to clear the template's 32-character floor.
    external_id = f"odineyes-{secrets.token_urlsafe(24)}"
    token_value = tokens.mint(session_id, ttl).value if with_callback else ""

    superseded = _supersede_pending(session, label) if label else 0
    expires_at = _utcnow() + timedelta(seconds=ttl)
    session.add(OnboardingSession(
        session_id=session_id,
        provider="aws",
        external_id=external_id,
        policy_mode=policy_mode,
        label=label,
        status=OnboardingSession.PENDING,
        expires_at=expires_at,
    ))
    session.flush()

    callback_url = f"{api_base}{CALLBACK_PATH}" if with_callback else ""
    launch_url = quick_create_url(
        template_url=published.template_url,
        parameters={
            "CSPMPlatformAccountId": odineyes_account_id(),
            "CSPMPlatformPrincipalArn": scanner_principal,
            "ExternalId": external_id,
            "OnboardingToken": token_value,
            "CallbackUrl": callback_url,
            "RoleName": ROLE_NAME,
            "RealtimeEventBusArn": _event_bus_for_launch(console_region),
        },
        # Stack names allow only [A-Za-z0-9-]; the session id is URL-safe base64
        # and may contain '_'. Strip rather than risk a rejected stack name.
        stack_name=f"odineyes-onboarding-{re.sub(r'[^A-Za-z0-9]', '', session_id)[:8]}",
        console_region=console_region,
    )

    logger.info(
        "issued onboarding link session=%s label=%s ttl=%ds superseded=%d template=%s callback=%s",
        session_id, label or "-", ttl, superseded,
        "reused" if published.reused else "uploaded",
        "on" if with_callback else "off (manual registration)",
    )
    return LaunchLink(
        session_id=session_id,
        launch_url=launch_url,
        template_url=published.template_url,
        template_checksum=published.checksum,
        template_reused=published.reused,
        external_id=external_id,
        expires_at=expires_at.isoformat(),
        label=label,
        superseded_links=superseded,
        callback_url=callback_url,
        callback_enabled=with_callback,
    )


def _event_bus_for_launch(console_region: Optional[str]) -> str:
    """Return a same-Region EventBridge ingress bus, or disable realtime.

    A one-click link can be generated before the regional data-plane stack is
    deployed. It must never fall back to a different Region's bus or queue.
    """
    from odineyes.core.realtime_policy import event_bus_for_region

    region = console_region or os.environ.get("ODINEYES_SCAN_REGION", "us-east-1")
    try:
        return event_bus_for_region(region).event_bus_arn
    except (RuntimeError, ValueError):
        return ""


def _supersede_pending(session: Session, label: str) -> int:
    """Retire earlier pending links for the same label.

    Regenerating a link for a customer must invalidate the one already sent,
    otherwise two live links exist for one intended connection and whichever
    stack runs last silently wins.
    """
    rows = session.execute(
        select(OnboardingSession).where(
            OnboardingSession.provider == "aws",
            OnboardingSession.label == label,
            OnboardingSession.status == OnboardingSession.PENDING,
        )
    ).scalars().all()
    for row in rows:
        row.status = OnboardingSession.SUPERSEDED
    if rows:
        logger.warning(
            "%d earlier pending link(s) for label %r were retired; those URLs now 409",
            len(rows), label,
        )
    return len(rows)


def redeem_callback(session: Session, payload: dict[str, Any]) -> dict[str, Any]:
    """Redeem a one-click onboarding. Called by the stack's Lambda, once.

    Unauthenticated by design — the token IS the authentication, and it is
    signed, short-lived and single-use. Everything the caller asserts is checked
    against state we already hold:

      * the token must verify and its session must still be pending;
      * the ExternalId must equal the one we generated for that session, so a
        customer who edited the parameter cannot register a trust we do not know;
      * the role ARN's account must match the reported account id, so the
        callback cannot enrol an account the stack did not run in.
    """
    token_value = str(payload.get("token") or "")
    external_id = str(payload.get("external_id") or "")
    role_arn = str(payload.get("role_arn") or "")
    account_identifier = str(payload.get("account_identifier") or "")
    disk_scan_role_arn = str(payload.get("disk_scan_role_arn") or "") or None
    realtime_role_arn = str(payload.get("realtime_role_arn") or "") or None

    if not token_value or not external_id or not role_arn or not account_identifier:
        raise OnboardingSessionError(
            400, "token, external_id, role_arn and account_identifier are required"
        )
    if payload.get("cloud", "aws") != "aws":
        raise OnboardingSessionError(400, "only the aws provider is supported")

    try:
        claims = tokens.verify(token_value)
    except tokens.OnboardingTokenError as exc:
        logger.warning("rejected onboarding callback: %s", exc)
        raise OnboardingSessionError(401, str(exc)) from exc

    discovered = _check_role_arn(role_arn, account_identifier)
    if disk_scan_role_arn:
        _check_role_arn(disk_scan_role_arn, account_identifier)
    if realtime_role_arn:
        _check_role_arn(realtime_role_arn, account_identifier)

    row = session.execute(
        select(OnboardingSession).where(OnboardingSession.session_id == claims.session_id)
    ).scalar_one_or_none()
    if row is None:
        raise OnboardingSessionError(404, "unknown onboarding session")

    # The signature proves authenticity; only stored state proves the token is
    # still spendable. A token stays cryptographically valid for its whole TTL,
    # so nothing but this check can retire it.
    status = row.effective_status()
    if status == OnboardingSession.REDEEMED:
        # CloudFormation retries a custom resource. An identical re-delivery
        # must not roll back a stack whose role was already accepted.
        if row.role_arn == role_arn:
            if realtime_role_arn and row.account_id:
                account = session.get(CloudAccount, row.account_id)
                if account is not None:
                    account.realtime_role_arn = realtime_role_arn
                    session.flush()
            return {
                "status": "connected",
                "account_id": row.account_id,
                "account_identifier": row.account_identifier,
                "idempotent": True,
            }
        raise OnboardingSessionError(409, "onboarding session already redeemed")
    if status == OnboardingSession.SUPERSEDED:
        raise OnboardingSessionError(
            409, "this onboarding link was replaced by a newer one; use the latest link"
        )
    if status != OnboardingSession.PENDING:
        raise OnboardingSessionError(409, f"onboarding session is {status}")
    if not hmac.compare_digest(row.external_id, external_id):
        raise OnboardingSessionError(
            400, "external_id does not match the value issued for this session"
        )

    account = _connect_account(
        session, row, account_identifier=discovered, role_arn=role_arn,
        disk_scan_role_arn=disk_scan_role_arn, realtime_role_arn=realtime_role_arn,
    )
    logger.info(
        "onboarding redeemed session=%s account=%s role=%s",
        row.session_id, discovered, role_arn,
    )
    return {
        "status": "connected",
        "account_id": account.id,
        "account_identifier": discovered,
        "idempotent": False,
    }


def register_manual(session: Session, *, session_id: str, role_arn: str) -> dict[str, Any]:
    """Complete an onboarding by hand, when the stack could not call back.

    Every check the callback performs still applies, except the token: the
    operator is already authenticated to this API, so the token's job — proving
    the caller is the stack — is met by the operator vouching for the ARN. The
    external ID still comes from *our* session row, never from the caller, so a
    mistyped ARN cannot bind a trust we do not know.
    """
    row = session.execute(
        select(OnboardingSession).where(OnboardingSession.session_id == session_id.strip())
    ).scalar_one_or_none()
    if row is None:
        raise OnboardingSessionError(404, f"unknown onboarding session {session_id}")
    status = row.effective_status()
    if status == OnboardingSession.REDEEMED:
        raise OnboardingSessionError(409, "onboarding session already redeemed")
    if status == OnboardingSession.SUPERSEDED:
        raise OnboardingSessionError(409, "this onboarding link was replaced by a newer one")
    # An expired link is still registerable by hand: expiry exists to retire the
    # unauthenticated callback token, and this path does not use one.

    match = ROLE_ARN_RE.fullmatch(role_arn.strip())
    if not match:
        raise OnboardingSessionError(400, "role_arn is not a valid IAM role ARN")

    account = _connect_account(
        session, row, account_identifier=match.group(1), role_arn=role_arn.strip(),
        disk_scan_role_arn=None,
        realtime_role_arn=None,
    )
    logger.info("manually registered session=%s account=%s", row.session_id, match.group(1))
    return {
        "status": "connected",
        "account_id": account.id,
        "account_identifier": match.group(1),
        "registered": "manually",
    }


def _check_role_arn(role_arn: str, account_identifier: str) -> str:
    match = ROLE_ARN_RE.fullmatch(role_arn)
    if not match:
        raise OnboardingSessionError(400, "role_arn is not a valid IAM role ARN")
    if not re.fullmatch(r"\d{12}", account_identifier):
        raise OnboardingSessionError(
            400, "account_identifier must be a 12-digit AWS account id"
        )
    if match.group(1) != account_identifier:
        raise OnboardingSessionError(
            400, "role_arn account does not match the reported account_identifier"
        )
    return match.group(1)


def _connect_account(
    session: Session,
    row: OnboardingSession,
    *,
    account_identifier: str,
    role_arn: str,
    disk_scan_role_arn: Optional[str],
    realtime_role_arn: Optional[str],
) -> CloudAccount:
    """Upsert the discovered account and burn the session, in one transaction."""
    account = AccountRepository.get_or_create(
        session, "aws", account_identifier, row.label, role_arn,
    )
    # The session's ExternalId is authoritative: the role that was just created
    # trusts *that* value, so an ExternalId minted earlier by get_or_create for
    # a different connection attempt would leave us unable to assume it.
    account.external_id = row.external_id
    account.role_arn = role_arn
    if disk_scan_role_arn:
        account.disk_scan_role_arn = disk_scan_role_arn
    if realtime_role_arn:
        account.realtime_role_arn = realtime_role_arn
    account.is_active = True
    account.onboarding_status = "connected"
    session.flush()

    row.status = OnboardingSession.REDEEMED
    row.redeemed_at = _utcnow()
    row.account_identifier = account_identifier
    row.role_arn = role_arn
    row.account_id = account.id
    session.flush()
    return account


def session_to_dict(row: OnboardingSession) -> dict[str, Any]:
    return {
        "session_id": row.session_id,
        "label": row.label,
        # Reported, not stored: a pending link goes stale on the clock.
        "status": row.effective_status(),
        "expires_at": _aware(row.expires_at).isoformat(),
        "created_at": _aware(row.created_at).isoformat(),
        "redeemed_at": _aware(row.redeemed_at).isoformat() if row.redeemed_at else None,
        "account_identifier": row.account_identifier,
        "role_arn": row.role_arn,
    }


def list_sessions(session: Session, limit: int = 50) -> list[dict[str, Any]]:
    rows = session.execute(
        select(OnboardingSession).order_by(OnboardingSession.id.desc()).limit(limit)
    ).scalars().all()
    return [session_to_dict(row) for row in rows]
