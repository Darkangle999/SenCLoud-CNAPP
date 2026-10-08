from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from odineyes.api.realtime_routes import router
from odineyes.db.base import init_db, session_scope
from odineyes.db.models import CloudAccount, CloudMutationEvent


def _client(tmp_path):
    url = f"sqlite:///{tmp_path / 'realtime.db'}"
    init_db(url)
    with session_scope(url) as session:
        session.add(CloudAccount(provider="aws", account_identifier="123456789012", name="test"))
    app = FastAPI()
    app.include_router(router)
    return TestClient(app), url


def _event(event_id="evt-1"):
    return {
        "id": event_id,
        "account": "123456789012",
        "region": "us-east-1",
        "source": "aws.ec2",
        "time": "2026-08-11T10:00:00Z",
        "detail": {
            "eventName": "AuthorizeSecurityGroupIngress",
            "eventSource": "ec2.amazonaws.com",
            "requestParameters": {
                "groupId": "sg-123",
                "ipPermissions": [{"fromPort": 22, "toPort": 22, "ipRanges": [{"cidrIp": "0.0.0.0/0"}]}],
                "authorizationToken": "must-not-persist",
            },
        },
    }


def test_mutation_is_idempotent_redacted_and_generates_provisional_alert(tmp_path):
    client, url = _client(tmp_path)
    first = client.post("/internal/realtime/events", json=_event())
    second = client.post("/internal/realtime/events", json=_event())
    assert first.status_code == 200
    assert first.json()["alert"]["severity"] == "high"
    assert second.json()["duplicate"] is True
    with session_scope(url) as session:
        rows = session.execute(select(CloudMutationEvent)).scalars().all()
        assert len(rows) == 1
        assert rows[0].payload["detail"]["requestParameters"]["authorizationToken"] == "[redacted]"


def test_failed_api_call_is_acknowledgeable_without_persistence(tmp_path):
    client, url = _client(tmp_path)
    event = _event("evt-failed")
    event["detail"]["errorCode"] = "AccessDenied"
    response = client.post("/internal/realtime/events", json=event)
    assert response.json()["status"] == "ignored"
    with session_scope(url) as session:
        assert session.execute(select(CloudMutationEvent)).scalars().all() == []


def test_unknown_account_is_rejected_for_dlq_redrive(tmp_path):
    client, _ = _client(tmp_path)
    event = _event()
    event["account"] = "999999999999"
    assert client.post("/internal/realtime/events", json=event).status_code == 403


def test_reconcile_queues_each_dirty_region(tmp_path, monkeypatch):
    client, _ = _client(tmp_path)
    queued: list[tuple[int, str]] = []
    monkeypatch.setattr(
        "odineyes.api.realtime_routes._run_reconciliation",
        lambda account_id, region: queued.append((account_id, region)),
    )

    response = client.post(
        "/internal/realtime/reconcile",
        json={"account": "123456789012", "regions": ["ap-south-1", "us-east-1", "ap-south-1"]},
    )

    assert response.status_code == 202
    assert response.json()["regions"] == ["ap-south-1", "us-east-1"]
    assert [region for _, region in queued] == ["ap-south-1", "us-east-1"]
