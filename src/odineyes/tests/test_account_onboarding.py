"""External-id-backed onboarding: server-generated ExternalId on the account
row, the onboarding-template API, and the orchestrator actually sending it on
assume_role. Ties together repository.py, iac_templates.py, and
orchestrator.py — the fix for the trust-policy placeholder that was shown in
the UI but never enforced.
"""

from __future__ import annotations

from hashlib import sha256
import os
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from odineyes.db.base import init_db, session_scope
from odineyes.db.models import CloudAccount
from odineyes.inventory.orchestrator import AccountRef, MultiAccountOrchestrator
from odineyes.inventory.repository import AccountRepository


@pytest.fixture()
def db(tmp_path):
    url = f"sqlite:///{tmp_path}/onboarding.db"
    os.environ["ODINEYES_DATABASE_URL"] = url
    init_db(url)
    return url


@pytest.fixture()
def client(db):
    from odineyes.api.inventory_routes import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ── repository: external_id generation ─────────────────────────

def test_aws_account_gets_external_id_on_creation(db):
    with session_scope(db) as s:
        acct = AccountRepository.get_or_create(s, "aws", "111122223333")
        assert acct.external_id
        assert acct.external_id.startswith("cs-")


def test_external_id_stable_across_repeat_calls(db):
    with session_scope(db) as s:
        first = AccountRepository.get_or_create(s, "aws", "111122223333").external_id
    with session_scope(db) as s:
        second = AccountRepository.get_or_create(s, "aws", "111122223333").external_id
    assert first == second


def test_two_accounts_get_different_external_ids(db):
    with session_scope(db) as s:
        a = AccountRepository.get_or_create(s, "aws", "111122223333").external_id
        b = AccountRepository.get_or_create(s, "aws", "444455556666").external_id
    assert a != b


def test_non_aws_account_has_no_external_id(db):
    with session_scope(db) as s:
        acct = AccountRepository.get_or_create(s, "azure", "sub-1")
        assert acct.external_id is None


def test_backfills_external_id_for_preexisting_row(db):
    # Simulates an account row created before this column existed.
    with session_scope(db) as s:
        acct = AccountRepository.get_or_create(s, "aws", "111122223333")
        acct.external_id = None
    with session_scope(db) as s:
        acct = AccountRepository.get_or_create(s, "aws", "111122223333")
        assert acct.external_id is not None


# ── API: onboarding-template endpoint ───────────────────────────

def test_onboarding_endpoint_requires_account_id_config(client, monkeypatch):
    import odineyes.core.iac_templates as tpl
    monkeypatch.delenv("ODINEYES_AWS_ACCOUNT_ID", raising=False)
    monkeypatch.setattr(tpl, "_caller_account_id", lambda: None)  # no STS identity
    r = client.post("/api/inventory/accounts/onboarding-template",
                     json={"provider": "aws", "account_identifier": "111122223333"})
    assert r.status_code == 500


def test_onboarding_endpoint_returns_templates(client, monkeypatch):
    monkeypatch.setenv("ODINEYES_AWS_ACCOUNT_ID", "999999999999")
    r = client.post("/api/inventory/accounts/onboarding-template",
                     json={"provider": "aws", "account_identifier": "111122223333"})
    assert r.status_code == 200
    body = r.json()
    assert body["external_id"].startswith("cs-")
    assert body["trust_account_id"] == "999999999999"
    assert body["external_id"] in body["cloudformation_template"]
    assert body["external_id"] in body["terraform_snippet"]


def test_onboarding_endpoint_uses_configured_principal_when_sts_is_unavailable(client, monkeypatch):
    import odineyes.core.iac_templates as tpl

    monkeypatch.delenv("ODINEYES_AWS_ACCOUNT_ID", raising=False)
    monkeypatch.setenv(
        "ODINEYES_SCANNER_PRINCIPAL_ARN",
        "arn:aws:iam::123456789012:user/CloudSentinelLocalScanner",
    )
    monkeypatch.setattr(tpl, "_caller_account_id", lambda: None)

    response = client.post(
        "/api/inventory/accounts/onboarding-template",
        json={"provider": "aws", "account_identifier": "222233334444"},
    )

    assert response.status_code == 200
    assert response.json()["trust_account_id"] == "123456789012"


def test_onboarding_endpoint_publishes_one_click_cloudformation_template(client, db, monkeypatch):
    """Production configuration returns a Quick Create link; no public bucket."""
    monkeypatch.setenv("ODINEYES_AWS_ACCOUNT_ID", "999999999999")
    monkeypatch.setenv("ODINEYES_SCANNER_PRINCIPAL_ARN", "arn:aws:iam::999999999999:role/OdineyesApi")
    monkeypatch.setenv("ODINEYES_ONBOARDING_TEMPLATE_BUCKET", "odineyes-onboarding-templates")
    monkeypatch.setenv("ODINEYES_PUBLIC_API_URL", "https://api.odineyes.example")
    s3 = MagicMock()
    s3.generate_presigned_url.return_value = "https://s3.example.test/signed-template"
    monkeypatch.setattr("boto3.client", lambda service, region_name=None: s3)

    r = client.post("/api/inventory/accounts/onboarding-template",
                    json={"provider": "aws", "account_identifier": "121212121212"})

    assert r.status_code == 200
    body = r.json()
    launch_query = parse_qs(
        urlsplit(body["cloudformation_quick_create_url"]).fragment.split("?", 1)[1]
    )
    callback_token = launch_query["param_OnboardingToken"][0]
    hosted_yaml = s3.put_object.call_args.kwargs["Body"].decode("utf-8")
    assert "#/stacks/create/review" in body["cloudformation_quick_create_url"]
    assert f"param_ExternalId={body['external_id']}" in body["cloudformation_quick_create_url"]
    assert "param_CSPMPlatformAccountId=999999999999" in body["cloudformation_quick_create_url"]
    assert "param_CSPMPlatformPrincipalArn=" in body["cloudformation_quick_create_url"]
    assert "param_OnboardingToken=" in body["cloudformation_quick_create_url"]
    assert "param_CallbackUrl=https%3A%2F%2Fapi.odineyes.example" in body["cloudformation_quick_create_url"]
    assert body["external_id"] not in hosted_yaml
    assert callback_token not in hosted_yaml
    assert "ODINEYES_API_SECRET" not in hosted_yaml
    assert "CSPMDataGuardPolicy" in hosted_yaml
    assert body["cloudformation_template_url"] == "https://s3.example.test/signed-template"
    assert body["one_click_setup_error"] is None
    assert s3.put_object.call_args.kwargs["ServerSideEncryption"] == "AES256"
    assert s3.put_object.call_args.kwargs["Key"] == (
        "cloudformation-onboarding/aws/121212121212/onboarding.yaml"
    )
    assert body["cloudformation_template_s3_uri"] == (
        "s3://odineyes-onboarding-templates/"
        "cloudformation-onboarding/aws/121212121212/onboarding.yaml"
    )
    with session_scope(db) as session:
        account = AccountRepository.get_or_create(session, "aws", "121212121212")
        assert account.onboarding_status == "awaiting_stack"
        assert account.is_active is False
        assert account.onboarding_token_hash
        assert account.onboarding_token_hash == sha256(callback_token.encode("utf-8")).hexdigest()
        assert account.onboarding_token_expires_at


def test_hosted_yaml_reuses_static_key_and_mints_a_fresh_signed_url(monkeypatch):
    """A retry does not write another YAML or rotate the account ExternalId."""
    from odineyes.core.onboarding_hosting import publish_cloudformation_template

    monkeypatch.setenv("ODINEYES_PUBLIC_API_URL", "https://api.example.com")
    monkeypatch.setenv("ODINEYES_ONBOARDING_TEMPLATE_BUCKET", "odineyes-onboarding-templates")
    monkeypatch.setenv("ODINEYES_ONBOARDING_TEMPLATE_PREFIX", "tenant-onboarding/v1")
    template = "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n"
    s3 = MagicMock()
    s3.head_object.return_value = {
        "Metadata": {"template-sha256": sha256(template.encode("utf-8")).hexdigest()},
        "VersionId": "template-version-7",
    }
    s3.generate_presigned_url.return_value = "https://s3.example.test/fresh-signed-template"
    monkeypatch.setattr("boto3.client", lambda service, region_name=None: s3)

    hosted = publish_cloudformation_template(
        account_identifier="121212121212", template=template,
    )

    assert hosted.reused is True
    assert hosted.key == "tenant-onboarding/v1/aws/121212121212/onboarding.yaml"
    assert hosted.version_id == "template-version-7"
    s3.put_object.assert_not_called()
    assert s3.generate_presigned_url.call_args.kwargs["Params"] == {
        "Bucket": "odineyes-onboarding-templates",
        "Key": "tenant-onboarding/v1/aws/121212121212/onboarding.yaml",
        "VersionId": "template-version-7",
    }


def test_hosted_yaml_overwrites_stable_key_only_when_content_changes(monkeypatch):
    from odineyes.core.onboarding_hosting import publish_cloudformation_template

    monkeypatch.setenv("ODINEYES_PUBLIC_API_URL", "https://api.example.com")
    monkeypatch.setenv("ODINEYES_ONBOARDING_TEMPLATE_BUCKET", "odineyes-onboarding-templates")
    s3 = MagicMock()
    s3.head_object.return_value = {"Metadata": {"template-sha256": "old-checksum"}}
    s3.put_object.return_value = {"VersionId": "template-version-8"}
    s3.generate_presigned_url.return_value = "https://s3.example.test/new-signed-template"
    monkeypatch.setattr("boto3.client", lambda service, region_name=None: s3)

    hosted = publish_cloudformation_template(
        account_identifier="121212121212", template="Resources: {}\n",
    )

    assert hosted.reused is False
    assert hosted.version_id == "template-version-8"
    assert s3.put_object.call_args.kwargs["Key"] == (
        "cloudformation-onboarding/aws/121212121212/onboarding.yaml"
    )
    assert s3.put_object.call_args.kwargs["CacheControl"] == "no-store"
    assert s3.put_object.call_args.kwargs["Metadata"]["template-format"] == "cloudformation-yaml"


def test_onboarding_endpoint_reuses_same_external_id_on_repeat_call(client, monkeypatch):
    monkeypatch.setenv("ODINEYES_AWS_ACCOUNT_ID", "999999999999")
    body = {"provider": "aws", "account_identifier": "111122223333"}
    first = client.post("/api/inventory/accounts/onboarding-template", json=body).json()
    second = client.post("/api/inventory/accounts/onboarding-template", json=body).json()
    assert first["external_id"] == second["external_id"]
    assert first["account_id"] == second["account_id"]


def test_verify_one_click_onboarding_connects_only_after_sts_and_read_check(client, db, monkeypatch):
    monkeypatch.setenv("ODINEYES_AWS_ACCOUNT_ID", "999999999999")
    created = client.post(
        "/api/inventory/accounts/onboarding-template",
        json={"provider": "aws", "account_identifier": "111122223333"},
    ).json()
    expected = {
        "account_identifier": "111122223333",
        "assume": {"ok": True, "error": None},
        "read": {"ok": True, "error": None, "sample": {"ec2_instances_seen": 0}},
    }
    monkeypatch.setattr(
        "odineyes.inventory.orchestrator.MultiAccountOrchestrator.verify_access",
        lambda _self, _account: expected,
    )
    monkeypatch.setattr("odineyes.api.inventory_routes._auto_scan", lambda *_args: None)

    response = client.post(f"/api/inventory/accounts/{created['account_id']}/verify-onboarding", json={})

    assert response.status_code == 200
    assert response.json()["connected"] is True
    with session_scope(db) as session:
        account = session.get(CloudAccount, created["account_id"])
        assert account is not None
        assert account.is_active is True
        assert account.onboarding_status == "connected"
        assert account.role_arn == "arn:aws:iam::111122223333:role/OdineyesReadOnly"


def test_onboarding_returns_api_secret_only_on_first_call(client, monkeypatch):
    # The endpoint is unauthenticated; re-returning the persisted api_secret would
    # let anyone harvest an account's autoconnect creds by replaying the request.
    monkeypatch.setenv("ODINEYES_AWS_ACCOUNT_ID", "999999999999")
    body = {"provider": "aws", "account_identifier": "222233334444"}
    first = client.post("/api/inventory/accounts/onboarding-template", json=body).json()
    second = client.post("/api/inventory/accounts/onboarding-template", json=body).json()
    assert first["api_secret"]                       # minted + returned once
    assert first["secret_already_issued"] is False
    assert second["api_secret"] is None              # never re-returned
    assert second["secret_already_issued"] is True
    assert first["api_key"] == second["api_key"]     # key (identifier) stays stable


def test_onboarding_autoconnect_snippet_only_present_on_first_call(client, monkeypatch):
    # Needs the one-time api_secret embedded, so it follows the same secret-once
    # rule: present on mint, null on reuse (client falls back to terraform_snippet).
    monkeypatch.setenv("ODINEYES_AWS_ACCOUNT_ID", "999999999999")
    body = {"provider": "aws", "account_identifier": "666677778888"}
    first = client.post("/api/inventory/accounts/onboarding-template", json=body).json()
    second = client.post("/api/inventory/accounts/onboarding-template", json=body).json()
    assert first["terraform_autoconnect_snippet"] is not None
    assert 'resource "local_file" "odineyes_trigger"' in first["terraform_autoconnect_snippet"]
    assert first["external_id"] in first["terraform_autoconnect_snippet"]
    assert second["terraform_autoconnect_snippet"] is None
    assert second["terraform_snippet"]   # manual fallback still returned every time


def test_onboarding_requires_operator_token_when_set(client, monkeypatch):
    monkeypatch.setenv("ODINEYES_AWS_ACCOUNT_ID", "999999999999")
    monkeypatch.setenv("ODINEYES_ADMIN_TOKEN", "s3cr3t")
    body = {"provider": "aws", "account_identifier": "333344445555"}
    url = "/api/inventory/accounts/onboarding-template"
    assert client.post(url, json=body).status_code == 401                                  # no header
    assert client.post(url, json=body, headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.post(url, json=body, headers={"Authorization": "Bearer s3cr3t"}).status_code == 200


def test_onboarding_endpoint_rejects_non_aws():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient as TC

    from odineyes.api.inventory_routes import router
    app = FastAPI()
    app.include_router(router)
    c = TC(app)
    r = c.post("/api/inventory/accounts/onboarding-template",
               json={"provider": "azure", "account_identifier": "sub-1"})
    assert r.status_code == 400


def test_onboarding_endpoint_rejects_bad_account_id_format(client, monkeypatch):
    monkeypatch.setenv("ODINEYES_AWS_ACCOUNT_ID", "999999999999")
    r = client.post("/api/inventory/accounts/onboarding-template",
                     json={"provider": "aws", "account_identifier": "not-12-digits"})
    assert r.status_code == 422


# ── orchestrator: ExternalId actually sent to assume_role ──────

def test_assume_role_includes_external_id_when_set():
    orch = MultiAccountOrchestrator()
    account = AccountRef("111122223333", "prod", "arn:aws:iam::111122223333:role/OdineyesReadOnly",
                          "aws", external_id="cs-secret-value")
    fake_sts = MagicMock()
    fake_sts.assume_role.return_value = {"Credentials": {
        "AccessKeyId": "AK", "SecretAccessKey": "SK", "SessionToken": "ST",
    }}
    with patch("boto3.client", return_value=fake_sts):
        orch._default_session(account)
    _, kwargs = fake_sts.assume_role.call_args
    assert kwargs["ExternalId"] == "cs-secret-value"


def test_assume_role_omits_external_id_when_absent():
    orch = MultiAccountOrchestrator()
    account = AccountRef("111122223333", "prod", "arn:aws:iam::111122223333:role/OdineyesReadOnly",
                          "aws", external_id=None)
    fake_sts = MagicMock()
    fake_sts.assume_role.return_value = {"Credentials": {
        "AccessKeyId": "AK", "SecretAccessKey": "SK", "SessionToken": "ST",
    }}
    with patch("boto3.client", return_value=fake_sts):
        orch._default_session(account)
    _, kwargs = fake_sts.assume_role.call_args
    assert "ExternalId" not in kwargs


def test_scan_all_hydrates_external_id_from_db(db):
    with session_scope(db) as s:
        AccountRepository.get_or_create(
            s, "aws", "111122223333", None,
            "arn:aws:iam::111122223333:role/OdineyesReadOnly",
        )

    fake_sts = MagicMock()
    fake_sts.assume_role.return_value = {"Credentials": {
        "AccessKeyId": "AK", "SecretAccessKey": "SK", "SessionToken": "ST",
    }}
    orch = MultiAccountOrchestrator(collector_factory=lambda session, region: MagicMock(collect=lambda: []))
    with patch("boto3.client", return_value=fake_sts):
        orch.scan_all("aws")
    _, kwargs = fake_sts.assume_role.call_args
    assert kwargs["ExternalId"].startswith("cs-")
