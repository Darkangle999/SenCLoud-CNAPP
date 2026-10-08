"""Session-based one-click onboarding: a launch link minted before anyone knows
which AWS account will run the stack, and the callback that discovers it.

The property under test throughout is that the caller asserts nothing we trust:
the ExternalId comes from our session row, the account comes from the role ARN
CloudFormation produced, and the token is signed, expiring and single-use.
"""

from __future__ import annotations

import os
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from odineyes.core import onboarding_session as sessions
from odineyes.core import onboarding_token as tokens
from odineyes.core.onboarding_hosting import SharedOnboardingTemplate
from odineyes.db.base import init_db, session_scope
from odineyes.db.models import CloudAccount, OnboardingSession

ACCOUNT = "111122223333"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/OdineyesReadOnly"


@pytest.fixture(autouse=True)
def platform_env(monkeypatch, tmp_path):
    monkeypatch.setenv("ODINEYES_DATABASE_URL", f"sqlite:///{tmp_path}/onboarding.db")
    monkeypatch.setenv("ODINEYES_AWS_ACCOUNT_ID", "999988887777")
    monkeypatch.setenv(
        "ODINEYES_SCANNER_PRINCIPAL_ARN", "arn:aws:iam::999988887777:role/OdineyesScanner",
    )
    monkeypatch.setenv("ODINEYES_PUBLIC_API_URL", "https://api.example.com")
    monkeypatch.setenv(tokens.SECRET_ENV, "s" * 40)
    monkeypatch.setenv("ODINEYES_ONBOARDING_TEMPLATE_BUCKET", "odineyes-templates")
    # S3 is the only external dependency of link creation; stub the publish so
    # the rest of the flow is exercised offline.
    monkeypatch.setattr(
        sessions, "publish_shared_template",
        lambda template, url_ttl_seconds=3600: SharedOnboardingTemplate(
            bucket="odineyes-templates", key="p/onboarding.yaml",
            template_url="https://odineyes-templates.s3.amazonaws.com/p/onboarding.yaml?sig=x",
            checksum="abc123", reused=False,
        ),
    )
    init_db(os.environ["ODINEYES_DATABASE_URL"])


def _link(**kw):
    with session_scope() as session:
        return sessions.create_link(session, **kw)


def _callback(link, *, role_arn=ROLE_ARN, account=ACCOUNT, external_id=None, token=None):
    payload = {
        "token": token if token is not None else _token_for(link),
        "external_id": external_id if external_id is not None else link.external_id,
        "role_arn": role_arn,
        "account_identifier": account,
        "cloud": "aws",
    }
    with session_scope() as session:
        return sessions.redeem_callback(session, payload)


def _token_for(link) -> str:
    """The token as the stack would present it — read back out of the launch URL,
    not reconstructed, so the URL itself is under test."""
    query = parse_qs(urlsplit(link.launch_url).fragment.split("?", 1)[1])
    return query["param_OnboardingToken"][0]


def test_link_needs_no_account_id_and_prefills_every_parameter():
    link = _link(label="Acme production")

    query = parse_qs(urlsplit(link.launch_url).fragment.split("?", 1)[1])
    assert query["param_ExternalId"] == [link.external_id]
    assert query["param_CSPMPlatformAccountId"] == ["999988887777"]
    assert query["param_CSPMPlatformPrincipalArn"] == [
        "arn:aws:iam::999988887777:role/OdineyesScanner"
    ]
    assert query["param_CallbackUrl"] == [
        "https://api.example.com/api/inventory/accounts/onboarding-callback"
    ]
    assert query["param_RoleName"] == ["OdineyesReadOnly"]
    # Nothing in the link names an account — that is the whole point.
    assert ACCOUNT not in link.launch_url
    assert tokens.verify(_token_for(link)).session_id == link.session_id

    with session_scope() as session:
        row = session.query(OnboardingSession).one()
        assert row.status == OnboardingSession.PENDING
        assert row.account_identifier is None


def test_callback_discovers_the_account_and_connects_it():
    link = _link(label="Acme")
    result = _callback(link)

    assert result["status"] == "connected"
    assert result["account_identifier"] == ACCOUNT
    with session_scope() as session:
        account = session.get(CloudAccount, result["account_id"])
        assert account.role_arn == ROLE_ARN
        assert account.is_active and account.onboarding_status == "connected"
        # The trust the created role carries is the session's, not one minted
        # for some earlier connection attempt.
        assert account.external_id == link.external_id
        assert account.name == "Acme"
        row = session.query(OnboardingSession).one()
        assert row.status == OnboardingSession.REDEEMED
        assert row.account_id == account.id


def test_token_is_single_use_but_an_identical_retry_is_idempotent():
    link = _link()
    _callback(link)

    # CloudFormation retries custom resources; an identical re-delivery must not
    # fail a stack whose role was already accepted.
    again = _callback(link)
    assert again["idempotent"] is True

    other = f"arn:aws:iam::{ACCOUNT}:role/SomethingElse"
    with pytest.raises(sessions.OnboardingSessionError) as exc:
        _callback(link, role_arn=other)
    assert exc.value.status == 409


def test_regenerating_for_a_label_retires_the_link_already_sent():
    first = _link(label="Acme")
    second = _link(label="Acme")
    assert second.superseded_links == 1

    with pytest.raises(sessions.OnboardingSessionError) as exc:
        _callback(first)
    assert exc.value.status == 409
    assert "replaced" in exc.value.detail
    # The current link still works.
    assert _callback(second)["status"] == "connected"


def test_forged_or_expired_token_is_refused(monkeypatch):
    link = _link()
    good = _token_for(link)

    with pytest.raises(sessions.OnboardingSessionError) as exc:
        _callback(link, token=good[:-1] + ("0" if good[-1] != "0" else "1"))
    assert exc.value.status == 401

    # A token signed with a different secret must not verify either.
    monkeypatch.setenv(tokens.SECRET_ENV, "d" * 40)
    other = tokens.mint(link.session_id, 600).value
    monkeypatch.setenv(tokens.SECRET_ENV, "s" * 40)
    with pytest.raises(sessions.OnboardingSessionError) as exc:
        _callback(link, token=other)
    assert exc.value.status == 401


def test_edited_external_id_is_refused():
    """A customer who changes the ExternalId parameter ends up with a role we
    cannot assume — that must surface here, not as a silent trust mismatch."""
    link = _link()
    with pytest.raises(sessions.OnboardingSessionError) as exc:
        _callback(link, external_id="odineyes-" + "z" * 32)
    assert exc.value.status == 400
    assert "external_id" in exc.value.detail


def test_role_arn_must_belong_to_the_reported_account():
    link = _link()
    with pytest.raises(sessions.OnboardingSessionError) as exc:
        _callback(link, role_arn="arn:aws:iam::444455556666:role/OdineyesReadOnly")
    assert exc.value.status == 400
    with session_scope() as session:
        assert session.query(CloudAccount).count() == 0


def test_manual_registration_takes_the_external_id_from_the_session():
    link = _link(label="No callback", with_callback=False)
    assert link.callback_enabled is False
    assert link.callback_url == ""
    query = parse_qs(urlsplit(link.launch_url).fragment.split("?", 1)[1])
    # Empty CallbackUrl + token turns the template's AutoConnect condition off,
    # so no Lambda is created and the stack cannot roll back over an
    # unreachable endpoint.
    assert query.get("param_CallbackUrl", [""])[0] == ""
    assert query.get("param_OnboardingToken", [""])[0] == ""

    with session_scope() as session:
        result = sessions.register_manual(
            session, session_id=link.session_id, role_arn=ROLE_ARN,
        )
    assert result["account_identifier"] == ACCOUNT
    with session_scope() as session:
        account = session.get(CloudAccount, result["account_id"])
        assert account.external_id == link.external_id
        assert session.query(OnboardingSession).one().status == OnboardingSession.REDEEMED


def test_a_link_with_no_callback_needs_no_public_api_url(monkeypatch):
    """The manual path is exactly what a deployment without a public endpoint
    has to use, so requiring one would block it."""
    monkeypatch.delenv("ODINEYES_PUBLIC_API_URL", raising=False)
    assert _link(with_callback=False).callback_enabled is False

    from odineyes.core.onboarding_hosting import OnboardingHostingConfigurationError

    with pytest.raises(OnboardingHostingConfigurationError):
        _link(with_callback=True)


def test_pending_link_reports_itself_expired_on_the_clock():
    import datetime

    _link()
    with session_scope() as session:
        row = session.query(OnboardingSession).one()
        row.expires_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)
    with session_scope() as session:
        assert sessions.list_sessions(session)[0]["status"] == OnboardingSession.EXPIRED


# ---------------------------------------------------------------- HTTP surface
@pytest.fixture()
def client():
    from odineyes.api.autoconnect import router as autoconnect_router
    from odineyes.api.onboarding_routes import router as onboarding_router

    app = FastAPI()
    app.include_router(onboarding_router)
    app.include_router(autoconnect_router)
    return TestClient(app)


def test_link_endpoint_then_callback_endpoint_connects(client):
    link = client.post("/api/inventory/onboarding/link", json={"label": "Acme"}).json()
    assert link["callback_enabled"] is True

    token = parse_qs(urlsplit(link["launch_url"]).fragment.split("?", 1)[1])[
        "param_OnboardingToken"
    ][0]
    response = client.post(
        "/api/inventory/accounts/onboarding-callback",
        json={
            "token": token,
            "external_id": link["external_id"],
            "role_arn": ROLE_ARN,
            "account_identifier": ACCOUNT,
            "cloud": "aws",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["account_identifier"] == ACCOUNT

    listed = client.get("/api/inventory/onboarding/sessions").json()["sessions"]
    assert listed[0]["status"] == "redeemed"
    assert listed[0]["account_identifier"] == ACCOUNT


def test_hosting_status_reports_failures_instead_of_raising(client, monkeypatch):
    monkeypatch.setenv(tokens.SECRET_ENV, "too-short")
    body = client.get("/api/inventory/onboarding/hosting-status").json()

    assert body["ready"] is False
    assert "Token signing secret" in {c["name"] for c in body["checks"] if c["status"] == "fail"}


def test_missing_public_api_url_warns_rather_than_blocking_links(client, monkeypatch):
    """Failing here would block the manual path — the only one a deployment
    without a public endpoint can use."""
    monkeypatch.delenv("ODINEYES_PUBLIC_API_URL", raising=False)
    checks = client.get("/api/inventory/onboarding/hosting-status").json()["checks"]

    url_check = next(c for c in checks if c["name"] == "Public API URL")
    assert url_check["status"] == "warn"
    assert "callback toggle OFF" in url_check["detail"]
    assert "Public API URL" not in {c["name"] for c in checks if c["status"] == "fail"}


# ---------------------------------------------------- bucket reachability check
def _client_error(code: str, message: str):
    from botocore.exceptions import ClientError

    return ClientError({"Error": {"Code": code, "Message": message}}, "HeadBucket")


class _StubS3Client:
    """head_bucket is always denied, head_object behavior is injected."""

    def __init__(self, head_object):
        self._head_object = head_object

    def head_bucket(self, Bucket):
        raise _client_error("403", "Forbidden")

    def head_object(self, Bucket, Key):
        return self._head_object(Bucket, Key)

    def get_bucket_policy_status(self, Bucket):
        raise _client_error("403", "Forbidden")

    def validate_template(self, **kwargs):
        return {}


class _StubSession:
    def __init__(self, s3):
        self._s3 = s3

    def client(self, service, region_name=None):
        return self._s3


def _run_check_hosting(monkeypatch, head_object):
    from odineyes.core import onboarding_hosting as hosting

    # Keep the CloudFormation acceptance check offline; only the bucket probe
    # is under test here.
    monkeypatch.setattr(
        hosting, "publish_shared_template",
        lambda template, url_ttl_seconds=3600: SharedOnboardingTemplate(
            bucket="odineyes-templates", key="p/onboarding.yaml",
            template_url="https://odineyes-templates.s3.amazonaws.com/p/onboarding.yaml?sig=x",
            checksum="abc123", reused=True,
        ),
    )
    return hosting.check_hosting(session=_StubSession(_StubS3Client(head_object)))


def test_bucket_check_survives_a_denied_head_bucket(monkeypatch):
    """The least-privilege publish policy grants object access only, so
    head_bucket 403s. The check must probe the template key instead of
    reporting a false fail that would disable link generation."""
    probes = []

    def head_object(Bucket, Key):
        probes.append(Key)
        raise _client_error("404", "Not Found")

    checks = _run_check_hosting(monkeypatch, head_object)

    reachable = next(c for c in checks if c.name == "Bucket reachable")
    assert reachable.status == "pass"
    assert "s3:ListBucket" in reachable.detail
    # The fallback really probed the shared template key (the "Template
    # published" check probes it again afterwards).
    assert probes[0] == "cloudformation-onboarding/public/onboarding/odineyes-onboarding.yaml"


def test_bucket_check_fails_when_object_access_is_denied_too(monkeypatch):
    def head_object(Bucket, Key):
        raise _client_error("403", "Forbidden")

    checks = _run_check_hosting(monkeypatch, head_object)

    reachable = next(c for c in checks if c.name == "Bucket reachable")
    assert reachable.status == "fail"
    assert "403" in reachable.detail
