"""§4.4 CIEM slice: IAM user coverage. Users are collected, normalized, and
risk-ruled (privileged long-lived access key; console without MFA). The role
engine already covered roles — this closes the user-side gap.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from odineyes.inventory.aws_raw_collector import _age_days
from odineyes.inventory.normalizers import NORMALIZERS, normalize_iam_user
from odineyes.inventory.rules import (
    rule_dormant_privileged_identity,
    rule_iam_user_console_no_mfa,
    rule_iam_user_privileged_longlived_key,
)


class _Asset:
    """Minimal AssetLike for rule evaluation."""
    def __init__(self, properties, asset_type="aws.iam.user"):
        self.resource_id = "arn:aws:iam::111122223333:user/testuser"
        self.asset_type = asset_type
        self.is_public = False
        self.encryption_enabled = None
        self.network_exposure = "private"
        self.properties = properties
        self.relationships = []


def test_user_registered_in_normalizers():
    assert NORMALIZERS.get("aws.iam.user") is normalize_iam_user


def test_normalize_iam_user_carries_identity_props():
    a = normalize_iam_user(
        {"UserName": "svc", "has_admin": True, "privesc_actions": ["iam:PassRole"],
         "access_key_active": True, "access_key_max_age_days": 200,
         "console_enabled": True, "mfa_enabled": False},
        "111122223333",
    )
    assert a.asset_type == "aws.iam.user"
    assert a.resource_id == "arn:aws:iam::111122223333:user/svc"
    assert a.properties["has_admin"] is True
    assert a.properties["access_key_max_age_days"] == 200


def test_privileged_longlived_key_fires():
    f = rule_iam_user_privileged_longlived_key(_Asset({
        "has_admin": True, "access_key_active": True, "access_key_max_age_days": 120,
    }))
    assert f is not None and f.severity == "critical"


def test_privesc_only_longlived_key_fires():
    f = rule_iam_user_privileged_longlived_key(_Asset({
        "privesc_actions": ["iam:CreatePolicyVersion"], "access_key_active": True,
        "access_key_max_age_days": 400,
    }))
    assert f is not None


def test_fresh_key_or_unprivileged_does_not_fire():
    # Privileged but the key is within the rotation window.
    assert rule_iam_user_privileged_longlived_key(_Asset({
        "has_admin": True, "access_key_active": True, "access_key_max_age_days": 30,
    })) is None
    # Old key but no privilege.
    assert rule_iam_user_privileged_longlived_key(_Asset({
        "has_admin": False, "privesc_actions": [], "access_key_active": True,
        "access_key_max_age_days": 400,
    })) is None


def test_console_no_mfa_fires_only_with_console_and_no_mfa():
    assert rule_iam_user_console_no_mfa(_Asset({"console_enabled": True, "mfa_enabled": False})) is not None
    assert rule_iam_user_console_no_mfa(_Asset({"console_enabled": True, "mfa_enabled": True})) is None
    assert rule_iam_user_console_no_mfa(_Asset({"console_enabled": False, "mfa_enabled": False})) is None


def test_rules_ignore_non_user_assets():
    role = _Asset({"has_admin": True, "access_key_active": True, "access_key_max_age_days": 999},
                  asset_type="aws.iam.role")
    assert rule_iam_user_privileged_longlived_key(role) is None
    assert rule_iam_user_console_no_mfa(role) is None


def test_age_days():
    assert _age_days(datetime.now(timezone.utc) - timedelta(days=100)) == 100
    # naive datetime is treated as UTC, never negative.
    assert _age_days(datetime.now(timezone.utc) + timedelta(days=5)) == 0


# ── dormant privileged identity (role + user) ──────────────────

def test_dormant_privileged_user_fires():
    f = rule_dormant_privileged_identity(_Asset({
        "has_admin": True, "last_used_days": 200, "age_days": 400,
    }))
    assert f is not None and f.severity == "high"


def test_dormant_never_used_privileged_role_fires():
    f = rule_dormant_privileged_identity(_Asset(
        {"privesc_actions": ["iam:PassRole"], "last_used_days": None, "age_days": 300},
        asset_type="aws.iam.role",
    ))
    assert f is not None and "never used" in f.why


def test_recently_used_privileged_identity_does_not_fire():
    assert rule_dormant_privileged_identity(_Asset({
        "has_admin": True, "last_used_days": 3, "age_days": 400,
    })) is None


def test_new_never_used_identity_does_not_fire():
    # Privileged, never used, but only 10 days old — too new to call dormant.
    assert rule_dormant_privileged_identity(_Asset({
        "has_admin": True, "last_used_days": None, "age_days": 10,
    })) is None


def test_dormant_but_unprivileged_does_not_fire():
    assert rule_dormant_privileged_identity(_Asset({
        "has_admin": False, "privesc_actions": [], "last_used_days": 999, "age_days": 999,
    })) is None


def test_dormant_rule_ignores_non_identity_assets():
    assert rule_dormant_privileged_identity(_Asset(
        {"has_admin": True, "last_used_days": 999}, asset_type="aws.s3.bucket",
    )) is None
