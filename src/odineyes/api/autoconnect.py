"""FastAPI router for machine-to-machine AWS account autoconnect."""

from __future__ import annotations

import hmac
import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel, Field

from sqlalchemy import select

from odineyes.db.base import session_scope
from odineyes.db.models import CloudAccount

router = APIRouter(prefix="/api/inventory", tags=["autoconnect"])
logger = logging.getLogger(__name__)


class OnboardingCallbackIn(BaseModel):
    # Two token shapes reach this endpoint. The per-account flow sends a plain
    # url-safe random string whose SHA-256 is stored on the account row; the
    # session flow sends a dot-delimited signed token, because no account row
    # exists when its link is issued. The '.' is what tells them apart.
    token: str = Field(min_length=32, max_length=512, pattern=r"^[A-Za-z0-9_.-]+$")
    external_id: str = Field(min_length=32, max_length=128)
    role_arn: str = Field(min_length=20, max_length=512)
    disk_scan_role_arn: Optional[str] = Field(default=None, min_length=20, max_length=512)
    realtime_role_arn: Optional[str] = Field(default=None, min_length=20, max_length=512)
    realtime_region: Optional[str] = Field(default=None, pattern=r"^[a-z]{2}(?:-gov)?-[a-z0-9-]+-\d$")
    account_identifier: str = Field(pattern=r"^\d{12}$")
    cloud: str = Field(default="aws", pattern=r"^aws$")


def verify_hmac(request: Request, body_bytes: bytes, account: CloudAccount) -> None:
    """Verify the HMAC signature of the incoming request."""
    api_key = request.headers.get("X-API-Key")
    signature = request.headers.get("X-Signature")
    tstmp = request.headers.get("X-Timestamp")

    if not api_key or not signature or not tstmp:
        raise HTTPException(status_code=401, detail="Missing authentication headers")

    if account.api_key != api_key:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    if not account.api_secret:
        raise HTTPException(status_code=401, detail="Account has no API secret configured")

    # Time validation to prevent replay attacks (allow 5 mins drift)
    try:
        req_time = int(tstmp) / 1000.0
        if abs(time.time() - req_time) > 300:
            raise HTTPException(status_code=401, detail="Request timestamp expired or too skewed")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp format")

    method = request.method
    path = request.url.path
    
    # Matching Aqua's trigger-aws.py signature scheme: tstmp + method + path + body
    enc = tstmp + method + path + body_bytes.decode("utf-8")
    expected_sig = hmac.new(
        account.api_secret.encode("utf-8"), 
        enc.encode("utf-8"), 
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        raise HTTPException(status_code=403, detail="Invalid HMAC signature")


@router.post("/accounts/autoconnect")
async def autoconnect(request: Request, background_tasks: BackgroundTasks) -> dict[str, Any]:
    """Auto-connect an AWS account during Terraform apply.
    
    Requires HMAC authentication using the API key/secret generated during the
    initial onboarding-template request.
    """
    body_bytes = await request.body()
    try:
        body = json.loads(body_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    external_id = body.get("external_id")
    role_arn = body.get("role_arn")
    provider = body.get("cloud", "aws")

    if not external_id or not role_arn:
        raise HTTPException(status_code=400, detail="Missing external_id or role_arn")

    with session_scope() as session:
        # Find the account by external_id
        stmt = select(CloudAccount).where(CloudAccount.external_id == external_id, CloudAccount.provider == provider)
        account = session.execute(stmt).scalar_one_or_none()
        
        if not account:
            raise HTTPException(status_code=404, detail="Account not found or invalid external_id")

        # Authenticate the request
        verify_hmac(request, body_bytes, account)

        # Bind the role ARN to THIS account: it must be a well-formed IAM role
        # ARN whose 12-digit account id matches the registered account. Without
        # this an authenticated client could point us at a role in another
        # account (confused-deputy / data mis-filing).
        m = re.fullmatch(r"arn:aws[a-z-]*:iam::(\d{12}):role/[\w+=,.@/-]+", role_arn)
        if not m:
            raise HTTPException(status_code=400, detail="role_arn must be a valid IAM role ARN")
        if account.provider == "aws" and m.group(1) != account.account_identifier:
            raise HTTPException(
                status_code=400,
                detail="role_arn account id does not match the registered account",
            )

        # Update the account with the provisioned role ARN to complete onboarding
        account.role_arn = role_arn
        account.is_active = True
        account.onboarding_status = "connected"
        session.flush()
        
        account_id = account.id

    # A one-click CloudFormation stack should also deliver a useful product
    # outcome, not merely save an ARN. Reuse the same safe background scan used
    # by manual registration: the response remains fast and any AssumeRole
    # diagnostic appears on the account's latest scan instead of failing stack
    # creation after the role was accepted.
    from odineyes.api.inventory_routes import _auto_scan

    background_tasks.add_task(
        _auto_scan,
        account_id,
        os.environ.get("ODINEYES_SCAN_REGION", "us-east-1"),
    )
    logger.info(f"Successfully autoconnected account {account_id} with role {role_arn}")
    return {"status": "connected", "account_id": account_id}


@router.post("/accounts/onboarding-callback")
def onboarding_callback(
    body: OnboardingCallbackIn, background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    """Consume the short-lived token embedded by the one-click launch URL.

    Only a SHA-256 digest is stored. The role ARN must belong to the draft AWS
    account and the ExternalId must identify that exact draft. Re-delivery of
    the same successful callback is idempotent so a Lambda retry cannot roll
    back an otherwise valid CloudFormation stack.
    """
    from odineyes.core import onboarding_session, onboarding_token

    # A session-flow token authorises a connection for an account nobody has
    # declared yet, so it cannot be matched against a draft row. Route it to the
    # session redeemer, which discovers the account from the reported role ARN.
    if onboarding_token.looks_like_session_token(body.token):
        try:
            with session_scope() as session:
                result = onboarding_session.redeem_callback(session, body.model_dump())
        except onboarding_session.OnboardingSessionError as exc:
            raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
        if body.realtime_role_arn:
            from odineyes.core.realtime_policy import register_delivery_role
            register_delivery_role(body.realtime_role_arn, body.realtime_region)
        if not result.get("idempotent"):
            from odineyes.api.inventory_routes import _auto_scan

            background_tasks.add_task(
                _auto_scan,
                result["account_id"],
                os.environ.get("ODINEYES_SCAN_REGION", "us-east-1"),
            )
        return result

    token_digest = hashlib.sha256(body.token.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)

    with session_scope() as session:
        stmt = (
            select(CloudAccount)
            .where(
                CloudAccount.external_id == body.external_id,
                CloudAccount.provider == body.cloud,
                CloudAccount.account_identifier == body.account_identifier,
            )
            .with_for_update()
        )
        account = session.execute(stmt).scalar_one_or_none()
        if account is None or not account.onboarding_token_hash:
            raise HTTPException(status_code=401, detail="Invalid onboarding token")
        if not hmac.compare_digest(account.onboarding_token_hash, token_digest):
            raise HTTPException(status_code=401, detail="Invalid onboarding token")

        role_match = re.fullmatch(
            r"arn:aws[a-z-]*:iam::(\d{12}):role/[\w+=,.@/-]+", body.role_arn
        )
        if not role_match or role_match.group(1) != account.account_identifier:
            raise HTTPException(
                status_code=400,
                detail="role_arn must be an IAM role in the onboarding account",
            )

        if body.disk_scan_role_arn:
            disk_role_match = re.fullmatch(
                r"arn:aws[a-z-]*:iam::(\d{12}):role/[\w+=,.@/-]+",
                body.disk_scan_role_arn,
            )
            if not disk_role_match or disk_role_match.group(1) != account.account_identifier:
                raise HTTPException(
                    status_code=400,
                    detail="disk_scan_role_arn must be an IAM role in the onboarding account",
                )

        if body.realtime_role_arn:
            realtime_match = re.fullmatch(
                r"arn:aws[a-z-]*:iam::(\d{12}):role/[\w+=,.@/-]+",
                body.realtime_role_arn,
            )
            if not realtime_match or realtime_match.group(1) != account.account_identifier:
                raise HTTPException(
                    status_code=400,
                    detail="realtime_role_arn must be an IAM role in the onboarding account",
                )

        if account.onboarding_token_used_at is not None:
            if (
                account.role_arn == body.role_arn
                and account.disk_scan_role_arn == body.disk_scan_role_arn
                and account.realtime_role_arn == body.realtime_role_arn
                and account.onboarding_status == "connected"
            ):
                if body.realtime_role_arn:
                    from odineyes.core.realtime_policy import register_delivery_role
                    register_delivery_role(body.realtime_role_arn, body.realtime_region)
                return {"status": "connected", "account_id": account.id, "idempotent": True}
            raise HTTPException(status_code=409, detail="Onboarding token has already been used")

        expires_at = account.onboarding_token_expires_at
        if expires_at is None:
            raise HTTPException(status_code=401, detail="Onboarding token has no expiry")
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            raise HTTPException(status_code=401, detail="Onboarding token has expired")

        account.role_arn = body.role_arn
        account.disk_scan_role_arn = body.disk_scan_role_arn
        account.realtime_role_arn = body.realtime_role_arn
        account.is_active = True
        account.onboarding_status = "connected"
        account.onboarding_token_used_at = now
        session.flush()
        account_id = account.id

    from odineyes.api.inventory_routes import _auto_scan

    background_tasks.add_task(
        _auto_scan,
        account_id,
        os.environ.get("ODINEYES_SCAN_REGION", "us-east-1"),
    )
    logger.info("CloudFormation connected account %s with role %s", account_id, body.role_arn)
    if body.realtime_role_arn:
        from odineyes.core.realtime_policy import register_delivery_role
        register_delivery_role(body.realtime_role_arn, body.realtime_region)
    return {"status": "connected", "account_id": account_id, "idempotent": False}
