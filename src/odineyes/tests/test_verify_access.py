"""Automated onboarding diagnosis (verify_access / POST /accounts/{id}/verify):
replaces the manual "aws sts assume-role ... then aws ec2 describe-instances"
dance with one structured result showing which stage — assume vs read — failed.
"""

from __future__ import annotations

import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from odineyes.db.base import init_db, session_scope
from odineyes.inventory.orchestrator import AccountRef, MultiAccountOrchestrator
from odineyes.inventory.repository import AccountRepository


@pytest.fixture()
def client(tmp_path):
    os.environ["ODINEYES_DATABASE_URL"] = f"sqlite:///{tmp_path}/verify.db"
    init_db(os.environ["ODINEYES_DATABASE_URL"])
    from odineyes.api.inventory_routes import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_verify_reports_assume_failure_without_touching_read(monkeypatch):
    orch = MultiAccountOrchestrator()
    monkeypatch.setattr(orch, "_default_session",
                        lambda ref: (_ for _ in ()).throw(RuntimeError("AssumeRole failed: boom")))
    result = orch.verify_access(AccountRef("111122223333", None,
                                            "arn:aws:iam::111122223333:role/x", "aws"))
    assert result["assume"] == {"ok": False, "error": "AssumeRole failed: boom"}
    assert result["read"]["ok"] is False and result["read"]["error"] is None  # never attempted


def test_verify_reports_read_failure_when_assume_succeeds(monkeypatch):
    import boto3

    class _DeniedClient:
        def describe_instances(self, **kw):
            raise Exception("AccessDenied: not authorized to perform ec2:DescribeInstances")

    orch = MultiAccountOrchestrator()
    monkeypatch.setattr(orch, "_default_session", lambda ref: boto3.Session())
    monkeypatch.setattr(boto3.Session, "client", lambda self, *a, **kw: _DeniedClient())

    result = orch.verify_access(AccountRef("111122223333", None,
                                            "arn:aws:iam::111122223333:role/x", "aws"))
    assert result["assume"]["ok"] is True
    assert result["read"]["ok"] is False
    assert "AccessDenied" in result["read"]["error"]


def test_verify_reports_full_success(monkeypatch):
    import boto3

    class _OkClient:
        def describe_instances(self, **kw):
            return {"Reservations": [{"Instances": [{"InstanceId": "i-1"}, {"InstanceId": "i-2"}]}]}

    orch = MultiAccountOrchestrator()
    monkeypatch.setattr(orch, "_default_session", lambda ref: boto3.Session())
    monkeypatch.setattr(boto3.Session, "client", lambda self, *a, **kw: _OkClient())

    result = orch.verify_access(AccountRef("111122223333", None,
                                            "arn:aws:iam::111122223333:role/x", "aws"))
    assert result["assume"]["ok"] is True
    assert result["read"] == {"ok": True, "error": None, "sample": {"ec2_instances_seen": 2}}


def test_verify_endpoint_404s_on_unknown_account(client):
    r = client.post("/api/inventory/accounts/999/verify", json={})
    assert r.status_code == 404


def test_verify_endpoint_returns_structured_result(client, monkeypatch):
    with session_scope() as s:
        acct = AccountRepository.get_or_create(
            s, "aws", "111122223333", None, "arn:aws:iam::111122223333:role/x",
        )
        aid = acct.id

    seen: dict[str, bool] = {}

    def _fake(self, ref, *, deep=False):
        seen["deep"] = deep
        return {"account_identifier": ref.identifier,
                "assume": {"ok": True, "error": None},
                "read": {"ok": True, "error": None, "sample": {"ec2_instances_seen": 0}}}

    monkeypatch.setattr(MultiAccountOrchestrator, "verify_access", _fake)
    r = client.post(f"/api/inventory/accounts/{aid}/verify", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["assume"]["ok"] is True and body["read"]["ok"] is True
    # The operator-facing Verify button runs the full per-domain probe set;
    # the onboarding poller (verify-onboarding) deliberately does not.
    assert seen["deep"] is True


def test_deep_verify_reports_domain_coverage_and_guard_failures(monkeypatch):
    """The onboarding template attaches read policies AND a Deny guard. Deep
    verification must report both a missing read action and a guard that the
    customer's account failed to enforce."""
    import boto3
    from botocore.exceptions import ClientError

    from odineyes.core import onboarding_validator as ov

    class _Client:
        def __init__(self, service):
            self._service = service

        def describe_instances(self, **kw):
            return {"Reservations": [{"Instances": [{"InstanceId": "i-1"}]}]}

        def list_keys(self, **kw):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListKeys")

        # The guard policy should deny this; the account lets it through.
        def get_authorization_token(self, **kw):
            return {}

    orch = MultiAccountOrchestrator()
    monkeypatch.setattr(orch, "_default_session", lambda ref: boto3.Session())
    monkeypatch.setattr(boto3.Session, "client",
                        lambda self, service, **kw: _Client(service))
    monkeypatch.setattr(ov, "POSITIVE_PROBES", (
        ov.Probe("compute", "ec2", "describe_instances"),
        ov.Probe("security", "kms", "list_keys"),
    ))
    monkeypatch.setattr(ov, "NEGATIVE_PROBES", (
        ov.Probe("guard", "ecr", "get_authorization_token", expect_denied=True),
    ))

    result = orch.verify_access(
        AccountRef("111122223333", None, "arn:aws:iam::111122223333:role/x", "aws"),
        deep=True,
    )
    perms = result["permissions"]
    assert result["read"]["ok"] is True  # the shallow check still passes …
    assert perms["healthy"] is False     # … while collection is demonstrably degraded
    assert [m["action"] for m in perms["missing"]] == ["kms:list_keys"]
    assert [g["action"] for g in perms["guard_failures"]] == ["ecr:get_authorization_token"]
    assert perms["coverage"] == {"compute": {"ok": 1, "total": 1},
                                 "security": {"ok": 0, "total": 1}}


def test_shallow_verify_makes_no_probe_calls(monkeypatch):
    """verify-onboarding polls on window focus — it must stay one read call."""
    import boto3

    from odineyes.core import onboarding_validator as ov

    class _OkClient:
        def describe_instances(self, **kw):
            return {"Reservations": []}

    orch = MultiAccountOrchestrator()
    monkeypatch.setattr(orch, "_default_session", lambda ref: boto3.Session())
    monkeypatch.setattr(boto3.Session, "client", lambda self, *a, **kw: _OkClient())
    monkeypatch.setattr(ov, "validate", lambda *a, **kw: pytest.fail("probed on shallow verify"))

    result = orch.verify_access(AccountRef("111122223333", None,
                                            "arn:aws:iam::111122223333:role/x", "aws"))
    assert "permissions" not in result
