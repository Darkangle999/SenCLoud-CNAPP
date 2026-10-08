"""Shared API authorization dependencies."""

from __future__ import annotations

import hmac
import os
from typing import Optional

from fastapi import Header, HTTPException


def require_operator(authorization: Optional[str] = Header(default=None)) -> None:
    """Require the configured operator bearer token for privileged actions."""
    expected = os.environ.get("ODINEYES_ADMIN_TOKEN")
    if not expected:
        return
    if not authorization or not hmac.compare_digest(authorization, f"Bearer {expected}"):
        raise HTTPException(status_code=401, detail="operator authentication required")
