import json
import time
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from odineyes.api.server import app
from odineyes.db.base import Base, get_engine, session_scope
from odineyes.db.models import CloudAccount

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.drop_all(get_engine())
    Base.metadata.create_all(get_engine())
    yield

def test_autoconnect_success():
    # Insert account
    with session_scope() as session:
        acc = CloudAccount(
            provider="aws",
            account_identifier="123456789012",
            name="test-acc",
            external_id="ext-123",
            api_key="test-api-key",
            api_secret="test-api-secret",
            is_active=False
        )
        session.add(acc)
        session.flush()

    # Prepare request
    url = "/api/inventory/accounts/autoconnect"
    body = {
        "external_id": "ext-123",
        "role_arn": "arn:aws:iam::123456789012:role/CSPM",
        "cloud": "aws"
    }
    body_bytes = json.dumps(body).encode('utf-8')
    tstmp = str(int(time.time() * 1000))
    enc = tstmp + "POST" + url + body_bytes.decode('utf-8')
    sig = hmac.new("test-api-secret".encode('utf-8'), enc.encode('utf-8'), hashlib.sha256).hexdigest()

    response = client.post(
        url,
        data=body_bytes,
        headers={
            "X-API-Key": "test-api-key",
            "X-Signature": sig,
            "X-Timestamp": tstmp,
            "Content-Type": "application/json"
        }
    )

    assert response.status_code == 200
    assert response.json()["status"] == "connected"

    # Verify db update
    with session_scope() as session:
        acc = session.query(CloudAccount).filter_by(external_id="ext-123").first()
        assert acc.role_arn == "arn:aws:iam::123456789012:role/CSPM"
        assert acc.is_active is True

def test_autoconnect_invalid_hmac():
    with session_scope() as session:
        acc = CloudAccount(
            provider="aws",
            account_identifier="123456789012",
            name="test-acc",
            external_id="ext-123",
            api_key="test-api-key",
            api_secret="test-api-secret"
        )
        session.add(acc)

    url = "/api/inventory/accounts/autoconnect"
    body = {"external_id": "ext-123", "role_arn": "arn"}
    body_bytes = json.dumps(body).encode('utf-8')
    tstmp = str(int(time.time() * 1000))
    # Bad signature
    sig = "bad_signature"

    response = client.post(
        url,
        data=body_bytes,
        headers={
            "X-API-Key": "test-api-key",
            "X-Signature": sig,
            "X-Timestamp": tstmp,
            "Content-Type": "application/json"
        }
    )

    assert response.status_code == 403
    assert "Invalid HMAC signature" in response.json()["detail"]


def test_cloudformation_callback_consumes_bound_token_and_is_idempotent(monkeypatch):
    token = "t" * 43
    external_id = "cs-" + ("a" * 32)
    role_arn = "arn:aws:iam::123456789012:role/OdineyesReadOnly"
    disk_scan_role_arn = "arn:aws:iam::123456789012:role/OdineyesReadOnly-DiskScan"
    monkeypatch.setattr("odineyes.api.inventory_routes._auto_scan", lambda *_args: None)

    with session_scope() as session:
        session.add(CloudAccount(
            provider="aws",
            account_identifier="123456789012",
            name="callback-account",
            external_id=external_id,
            onboarding_status="awaiting_stack",
            is_active=False,
            onboarding_token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            onboarding_token_expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        ))

    payload = {
        "token": token,
        "external_id": external_id,
        "role_arn": role_arn,
        "disk_scan_role_arn": disk_scan_role_arn,
        "account_identifier": "123456789012",
        "cloud": "aws",
    }
    first = client.post("/api/inventory/accounts/onboarding-callback", json=payload)
    second = client.post("/api/inventory/accounts/onboarding-callback", json=payload)

    assert first.status_code == 200
    assert first.json()["idempotent"] is False
    assert second.status_code == 200
    assert second.json()["idempotent"] is True
    with session_scope() as session:
        account = session.query(CloudAccount).filter_by(external_id=external_id).one()
        assert account.role_arn == role_arn
        assert account.disk_scan_role_arn == disk_scan_role_arn
        assert account.is_active is True
        assert account.onboarding_status == "connected"
        assert account.onboarding_token_used_at is not None


def test_cloudformation_callback_rejects_wrong_token(monkeypatch):
    external_id = "cs-" + ("b" * 32)
    monkeypatch.setattr("odineyes.api.inventory_routes._auto_scan", lambda *_args: None)
    with session_scope() as session:
        session.add(CloudAccount(
            provider="aws",
            account_identifier="210987654321",
            external_id=external_id,
            onboarding_status="awaiting_stack",
            is_active=False,
            onboarding_token_hash=hashlib.sha256(("x" * 43).encode("utf-8")).hexdigest(),
            onboarding_token_expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        ))

    response = client.post("/api/inventory/accounts/onboarding-callback", json={
        "token": "y" * 43,
        "external_id": external_id,
        "role_arn": "arn:aws:iam::210987654321:role/OdineyesReadOnly",
        "account_identifier": "210987654321",
        "cloud": "aws",
    })
    assert response.status_code == 401
