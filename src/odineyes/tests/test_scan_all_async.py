"""The fleet scan must answer before the network gives up on it.

/scan-all ran the whole multi-region sweep inside the request. CloudFront gives
the origin 30 seconds, a live sweep takes minutes, so the caller got a 504 every
time while the scan carried on invisibly. These tests pin the contract that
replaced it: answer immediately, report progress separately, and refuse to
start a second sweep on top of a running one.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from odineyes.api.server import app
from odineyes.db.base import init_db, session_scope
from odineyes.db.models import CloudAccount, ScanJob


def _client(tmp_path, monkeypatch) -> TestClient:
    init_db(f"sqlite:///{tmp_path}/scanall.db")
    monkeypatch.setenv("ODINEYES_API_KEY", "")
    return TestClient(app)


def _account(identifier: str = "111122223333") -> int:
    with session_scope() as s:
        acct = CloudAccount(provider="aws", account_identifier=identifier,
                            name=f"acct-{identifier}", is_active=True)
        s.add(acct)
        s.flush()
        return acct.id


def test_scan_all_returns_immediately_with_202(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    _account()
    started: list[tuple] = []
    monkeypatch.setattr(
        "odineyes.api.inventory_routes._run_fleet_scan",
        lambda *a, **k: started.append(a),
    )

    response = client.post("/api/inventory/scan-all", json={"provider": "aws"})
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "started"
    assert body["accounts"] == 1
    assert body["poll"] == "/api/inventory/scan-all/status"


def test_a_second_scan_does_not_start_on_top_of_a_running_one(tmp_path, monkeypatch):
    """Two clicks would double the collector's memory on a 1 GB host and race
    the same rows."""
    client = _client(tmp_path, monkeypatch)
    account_id = _account()
    with session_scope() as s:
        s.add(ScanJob(account_id=account_id, scan_type="config", status="running"))

    calls: list[tuple] = []
    monkeypatch.setattr(
        "odineyes.api.inventory_routes._run_fleet_scan",
        lambda *a, **k: calls.append(a),
    )
    body = client.post("/api/inventory/scan-all", json={"provider": "aws"}).json()
    assert body["status"] == "already_running"
    assert body["in_flight"] == 1
    assert calls == [], "no rival sweep may be queued"


def test_status_distinguishes_never_scanned_from_finished(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    scanned = _account("111122223333")
    _account("444455556666")           # never scanned
    with session_scope() as s:
        s.add(ScanJob(account_id=scanned, scan_type="config", status="completed",
                      assets_found=42))

    body = client.get("/api/inventory/scan-all/status").json()
    assert body["running"] is False
    assert body["completed"] == 1
    assert body["pending"] == 1, "an unscanned account is pending, not omitted"
    by_id = {r["account_id"]: r for r in body["accounts"]}
    assert by_id[scanned]["job"]["assets_found"] == 42
    assert by_id[scanned]["job"]["status"] == "completed"
    assert next(r for r in body["accounts"] if r["job"] is None)


def test_status_reports_running_until_every_account_settles(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    a = _account("111122223333")
    b = _account("444455556666")
    with session_scope() as s:
        s.add(ScanJob(account_id=a, scan_type="config", status="completed"))
        s.add(ScanJob(account_id=b, scan_type="config", status="running"))
    assert client.get("/api/inventory/scan-all/status").json()["running"] is True

    with session_scope() as s:
        s.query(ScanJob).filter(ScanJob.account_id == b).update({"status": "failed"})
    body = client.get("/api/inventory/scan-all/status").json()
    assert body["running"] is False
    assert body["failed"] == 1


def test_scanning_one_account_also_answers_immediately(tmp_path, monkeypatch):
    """One account is still a multi-region scan, so it hits the same 30s origin
    timeout /scan-all did."""
    client = _client(tmp_path, monkeypatch)
    account_id = _account()
    queued: list[tuple] = []
    monkeypatch.setattr(
        "odineyes.api.inventory_routes._run_one_account_scan",
        lambda *a, **k: queued.append(a),
    )

    response = client.post(f"/api/inventory/accounts/{account_id}/scan", json={})
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "started"
    assert body["account_id"] == account_id
    assert queued == [(account_id, "us-east-1")]


def test_one_account_scan_hands_back_a_watermark_past_the_previous_job(tmp_path, monkeypatch):
    """The job row opens inside the background task, so for a moment the newest
    job is still the last scan's. Without the watermark a poller reads that
    stale 'completed' as this scan's result."""
    client = _client(tmp_path, monkeypatch)
    account_id = _account()
    with session_scope() as s:
        old = ScanJob(account_id=account_id, scan_type="config", status="completed")
        s.add(old)
        s.flush()
        old_id = old.id

    monkeypatch.setattr(
        "odineyes.api.inventory_routes._run_one_account_scan", lambda *a, **k: None)
    body = client.post(f"/api/inventory/accounts/{account_id}/scan", json={}).json()
    assert body["last_job_id"] == old_id


def test_one_account_scan_refuses_to_race_itself(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    account_id = _account()
    with session_scope() as s:
        s.add(ScanJob(account_id=account_id, scan_type="config", status="running"))

    queued: list[tuple] = []
    monkeypatch.setattr(
        "odineyes.api.inventory_routes._run_one_account_scan",
        lambda *a, **k: queued.append(a),
    )
    response = client.post(f"/api/inventory/accounts/{account_id}/scan", json={})
    assert response.status_code == 409
    assert queued == [], "no rival scan may be queued for the same account"


def test_scanning_a_missing_account_is_still_a_404(tmp_path, monkeypatch):
    """Going async must not turn 'no such account' into an accepted job that
    quietly does nothing."""
    client = _client(tmp_path, monkeypatch)
    assert client.post("/api/inventory/accounts/999/scan", json={}).status_code == 404


def test_status_uses_the_latest_job_not_the_first(tmp_path, monkeypatch):
    """A finished older job must not mask a re-scan that is still in flight."""
    client = _client(tmp_path, monkeypatch)
    account_id = _account()
    with session_scope() as s:
        s.add(ScanJob(account_id=account_id, scan_type="config", status="completed"))
        s.flush()
        s.add(ScanJob(account_id=account_id, scan_type="config", status="running"))

    body = client.get("/api/inventory/scan-all/status").json()
    assert body["running"] is True
    assert body["accounts"][0]["job"]["status"] == "running"
