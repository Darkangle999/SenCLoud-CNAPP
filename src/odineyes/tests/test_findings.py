"""Finding persistence + API — open/resolve/reopen lifecycle and read endpoints.

Lifecycle runs through InventoryService.evaluate_findings against sqlite; the
API surface (evaluate trigger, list, summary) is driven with TestClient on a
minimal app, same pattern as test_inventory_api.
"""

from __future__ import annotations

import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from odineyes.inventory.schema import NormalizedAsset
from odineyes.inventory.service import InventoryService

ACCOUNT = "123456789012"


def role(admin: bool, name="exposed") -> NormalizedAsset:
    return NormalizedAsset(
        resource_id=f"arn:aws:iam::{ACCOUNT}:role/{name}", cloud_provider="aws",
        account_identifier=ACCOUNT, asset_type="aws.iam.role", name=name,
        is_public=True, properties={"has_admin": admin, "admin_reason": "AdministratorAccess"},
    )


def bucket(public: bool, name="b") -> NormalizedAsset:
    return NormalizedAsset(
        resource_id=f"arn:aws:s3:::{name}", cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type="aws.s3.bucket", is_public=public,
    )


@pytest.fixture()
def svc(tmp_path):
    return InventoryService(database_url=f"sqlite:///{tmp_path}/findings.db")


# ── lifecycle ──────────────────────────────────────────────────

def test_evaluate_opens_findings(svc):
    svc.persist_normalized("aws", ACCOUNT, [role(admin=True), bucket(public=True)])
    stats = svc.evaluate_findings("aws", ACCOUNT)
    assert stats.total == 2 and stats.new == 2 and stats.resolved == 0


def test_re_evaluate_is_idempotent(svc):
    svc.persist_normalized("aws", ACCOUNT, [role(admin=True)])
    svc.evaluate_findings("aws", ACCOUNT)
    stats = svc.evaluate_findings("aws", ACCOUNT)
    assert stats.new == 0 and stats.reopened == 0 and stats.resolved == 0 and stats.total == 1


def test_fixed_resource_resolves_finding(svc):
    svc.persist_normalized("aws", ACCOUNT, [bucket(public=True)])
    svc.evaluate_findings("aws", ACCOUNT)
    # remediate: bucket now private -> rescan -> re-evaluate
    svc.persist_normalized("aws", ACCOUNT, [bucket(public=False)])
    stats = svc.evaluate_findings("aws", ACCOUNT)
    assert stats.total == 0 and stats.resolved == 1


def test_regression_reopens_finding(svc):
    svc.persist_normalized("aws", ACCOUNT, [bucket(public=True)])
    svc.evaluate_findings("aws", ACCOUNT)
    svc.persist_normalized("aws", ACCOUNT, [bucket(public=False)])
    svc.evaluate_findings("aws", ACCOUNT)            # resolved
    svc.persist_normalized("aws", ACCOUNT, [bucket(public=True)])
    stats = svc.evaluate_findings("aws", ACCOUNT)    # regressed
    assert stats.reopened == 1 and stats.new == 0


# ── API ────────────────────────────────────────────────────────

@pytest.fixture()
def client(tmp_path):
    url = f"sqlite:///{tmp_path}/findings_api.db"
    os.environ["ODINEYES_DATABASE_URL"] = url
    from odineyes.db.base import init_db
    init_db(url)
    from odineyes.api.inventory_routes import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _seed_and_evaluate(client):
    client.post("/api/inventory/accounts", json={"provider": "aws", "account_identifier": ACCOUNT})
    client.post("/api/inventory/scan", json={
        "provider": "aws", "account_identifier": ACCOUNT,
        "resources": [
            {"source_type": "aws.iam.role", "raw": {
                "RoleName": "exposed", "Arn": f"arn:aws:iam::{ACCOUNT}:role/exposed",
                "AssumeRolePolicyDocument": {"Statement": [
                    {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]},
                "has_admin": True, "admin_reason": "AdministratorAccess"}},
            {"source_type": "aws.s3.bucket", "raw": {
                "Name": "pub", "Region": "us-east-1", "PolicyStatus": {"IsPublic": True},
                "Encryption": {"enabled": True}, "PublicAccessBlock": {}}},
        ],
    })
    return client.post("/api/inventory/findings/evaluate",
                       json={"provider": "aws", "account_identifier": ACCOUNT}).json()


def test_api_evaluate_then_list(client):
    ev = _seed_and_evaluate(client)
    assert ev["total"] == 3 and ev["new"] == 3

    body = client.get("/api/inventory/findings").json()
    assert body["total"] == 3
    assert body["items"][0]["severity"] == "critical"   # sorted, admin role first
    assert "compliance" in body["items"][0]


def test_api_filter_by_severity(client):
    _seed_and_evaluate(client)
    body = client.get("/api/inventory/findings", params={"severity": "critical"}).json()
    assert body["total"] == 1
    assert body["items"][0]["rule_id"] == "PUBLIC_ADMIN_ROLE"


def test_api_findings_summary(client):
    _seed_and_evaluate(client)
    s = client.get("/api/inventory/findings/summary").json()
    assert s["open"] == 3 and s["suppressed"] == 0 and s["resolved"] == 0
    assert s["by_severity"]["critical"] == 1
    assert s["by_severity"]["high"] == 2
    assert s["active_threats"] == 3
    assert s["network_hygiene"] == 0
    assert s["active_threat_by_severity"] == s["by_severity"]


def test_suppressed_findings_are_auditable_but_absent_from_active_export(client):
    client.post("/api/inventory/accounts", json={
        "provider": "aws", "account_identifier": ACCOUNT,
    })
    client.post("/api/inventory/scan", json={
        "provider": "aws", "account_identifier": ACCOUNT,
        "resources": [
            {"source_type": "aws.ec2.vpc", "raw": {
                "VpcId": "vpc-default", "Region": "eu-north-1", "IsDefault": True,
                "State": "available", "_FlowLogsActive": [],
                "_Evidence": {"flow_logs": "observed"},
            }},
            {"source_type": "aws.ec2.subnet", "raw": {
                "SubnetId": "subnet-empty", "VpcId": "vpc-default",
                "Region": "eu-north-1", "DefaultForAz": True,
                "MapPublicIpOnLaunch": True,
            }},
            {"source_type": "aws.ec2.network_acl", "raw": {
                "NetworkAclId": "acl-default", "VpcId": "vpc-default",
                "Region": "eu-north-1", "IsDefault": True,
                "Associations": [{"SubnetId": "subnet-empty"}],
            }},
        ],
    })
    evaluated = client.post("/api/inventory/findings/evaluate", json={
        "provider": "aws", "account_identifier": ACCOUNT,
    }).json()
    assert evaluated["suppressed"] == 2
    assert evaluated["new"] == 0

    active = client.get("/api/inventory/findings", params={"status": "open"}).json()
    assert active["total"] == 0

    suppressed = client.get(
        "/api/inventory/findings/resources",
        params={"status": "suppressed", "signal": "network_hygiene"},
    ).json()
    assert suppressed["totals"]["suppressed"] == 2
    assert suppressed["pagination"]["total"] == 2
    assert {item["evidence"]["suppressed_by"] for item in suppressed["items"]} == {
        "design", "path",
    }
    assert {item["verdict"]["signal"] for item in suppressed["items"]} == {"network_hygiene"}
    assert suppressed["totals"]["active_threats"] == 0
    assert suppressed["totals"]["network_hygiene"] == 0

    active_csv = client.get("/api/inventory/findings/export", params={"status": "open"})
    assert "VPC_FLOW_LOGS_DISABLED" not in active_csv.text
    assert "SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED" not in active_csv.text

    suppressed_csv = client.get(
        "/api/inventory/findings/export",
        params={"status": "suppressed", "signal": "network_hygiene"},
    )
    assert "signal" in suppressed_csv.text
    assert "network_hygiene" in suppressed_csv.text
    assert "suppressed_by" in suppressed_csv.text
    assert "VPC_FLOW_LOGS_DISABLED" in suppressed_csv.text
    assert "SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED" in suppressed_csv.text
