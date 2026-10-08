"""Generic (role-only) onboarding: the ambient/root-credential scan path is
removed, so every AWS account MUST carry a role_arn. Two guards:
  1. POST /accounts rejects an AWS account with no role_arn (422 at the API).
  2. The orchestrator refuses to build a session without a role_arn — it never
     falls back to the runner's ambient identity.
"""

from __future__ import annotations

import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from odineyes.db.base import init_db
from odineyes.inventory.orchestrator import AccountRef, MultiAccountOrchestrator


@pytest.fixture()
def client(tmp_path):
    url = f"sqlite:///{tmp_path}/generic.db"
    os.environ["ODINEYES_DATABASE_URL"] = url
    init_db(url)
    from odineyes.api.inventory_routes import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_register_aws_without_role_arn_is_rejected(client):
    r = client.post("/api/inventory/accounts", json={"provider": "aws", "account_identifier": "111122223333"})
    assert r.status_code == 422
    assert "role_arn is required" in r.text


def test_register_aws_with_role_arn_succeeds(client):
    r = client.post("/api/inventory/accounts", json={
        "provider": "aws", "account_identifier": "111122223333",
        "role_arn": "arn:aws:iam::111122223333:role/OdineyesReadOnly",
    })
    assert r.status_code == 201


def test_register_auto_scans_the_new_account(client, monkeypatch):
    # Connecting an account kicks its scan in the background — no manual Scan
    # click. (Stub the scan so the test doesn't touch AWS.)
    import odineyes.api.inventory_routes as ir
    calls: list = []
    monkeypatch.setattr(ir, "_run_account_scan", lambda aid, region: calls.append((aid, region)))
    r = client.post("/api/inventory/accounts", json={
        "provider": "aws", "account_identifier": "555566667777",
        "role_arn": "arn:aws:iam::555566667777:role/OdineyesReadOnly",
    })
    assert r.status_code == 201
    assert calls and calls[0][0] == r.json()["id"]   # scanned the account just created


def test_orchestrator_refuses_scanning_a_different_account_with_ambient():
    # Ambient creds are only allowed to scan the caller's OWN account. Here the
    # caller identity resolves to a different account (or None), so scanning
    # 111122223333 with ambient creds must be refused, not silently mis-filed.
    orch = MultiAccountOrchestrator()
    orch._caller_account = lambda: "999999999999"  # not the target
    with pytest.raises(RuntimeError, match="cannot scan account 111122223333"):
        orch._default_session(AccountRef("111122223333", None, None, "aws"))


def test_orchestrator_allows_ambient_for_own_account():
    # Caller identity == target → ambient dev scan of your own account is fine.
    orch = MultiAccountOrchestrator()
    orch._caller_account = lambda: "111122223333"
    session = orch._default_session(AccountRef("111122223333", None, None, "aws"))
    assert session is not None
