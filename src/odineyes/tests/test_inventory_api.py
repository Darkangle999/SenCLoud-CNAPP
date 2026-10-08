"""REST read-API over the inventory store.

Mounts the inventory router on a minimal app (avoids server.py's Neo4j imports)
and drives it with TestClient against an isolated sqlite database.
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select


def s3_raw(name: str, *, public: bool = False) -> dict:
    blocked = {
        "BlockPublicAcls": True, "BlockPublicPolicy": True,
        "IgnorePublicAcls": True, "RestrictPublicBuckets": True,
    }
    return {
        "Name": name,
        "Region": "us-east-1",
        "PolicyStatus": {"IsPublic": public},
        "Encryption": {"enabled": True, "algorithm": "AES256"},
        "Versioning": "Enabled",
        "PublicAccessBlock": {} if public else blocked,
        "Tags": {"env": "prod"},
    }


@pytest.fixture()
def client(tmp_path):
    url = f"sqlite:///{tmp_path}/api.db"
    os.environ["ODINEYES_DATABASE_URL"] = url
    from odineyes.db.base import init_db
    init_db(url)  # rebinds the global engine to this isolated db + creates tables

    from odineyes.api.inventory_routes import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _seed(client) -> dict:
    client.post("/api/inventory/accounts", json={"provider": "aws", "account_identifier": "123456789012"})
    return client.post("/api/inventory/scan", json={
        "provider": "aws",
        "account_identifier": "123456789012",
        "resources": [
            {"source_type": "s3:bucket", "raw": s3_raw("alpha", public=False)},
            {"source_type": "s3:bucket", "raw": s3_raw("beta", public=True)},
        ],
    }).json()


def test_register_account(client):
    r = client.post("/api/inventory/accounts", json={
        "provider": "aws", "account_identifier": "999900001111",
        "role_arn": "arn:aws:iam::999900001111:role/OdineyesReadOnly",
    })
    assert r.status_code == 201
    body = r.json()
    assert body["provider"] == "aws"
    assert body["account_identifier"] == "999900001111"
    assert isinstance(body["id"], int)


def test_register_rejects_bad_provider(client):
    r = client.post("/api/inventory/accounts", json={"provider": "digitalocean", "account_identifier": "x"})
    assert r.status_code == 422


def test_ebs_snapshot_scan_endpoint_returns_explicit_skip(client, monkeypatch):
    """The route exposes scan coverage cleanly without making an AWS call."""
    from odineyes.api import inventory_routes
    from odineyes.inventory.service import EbsSnapshotScanStats

    monkeypatch.setattr(
        inventory_routes._service,
        "scan_ebs_snapshot_vulnerabilities",
        lambda *args, **kwargs: EbsSnapshotScanStats(
            snapshot_id="snap-0123456789abcdef0",
            scanned=False,
            skipped_reason="disk scanning is not enabled for this account",
        ),
    )
    response = client.post("/api/inventory/vulnerabilities/scan-ebs-snapshot", json={
        "provider": "aws",
        "account_identifier": "123456789012",
        "region": "us-east-1",
        "snapshot_id": "snap-0123456789abcdef0",
    })

    assert response.status_code == 200
    assert response.json()["scanned"] is False
    assert "not enabled" in response.json()["skipped_reason"]


def test_ec2_agentless_scan_endpoint_queues_off_request_path(client, monkeypatch):
    from odineyes.api import inventory_routes

    captured = {}

    def fake_scan(provider, account_identifier, **kwargs):
        captured.update({
            "provider": provider,
            "account_identifier": account_identifier,
            **kwargs,
        })

    monkeypatch.setattr(
        inventory_routes._service, "scan_ec2_instance_vulnerabilities", fake_scan,
    )
    response = client.post("/api/inventory/vulnerabilities/scan-ec2-instance", json={
        "provider": "aws",
        "account_identifier": "123456789012",
        "region": "us-east-1",
        "instance_id": "i-0123456789abcdef0",
    })

    assert response.status_code == 202
    assert response.json()["scanner"] == "aquasecurity-trivy"
    assert captured["instance_id"] == "i-0123456789abcdef0"


def test_scan_then_list(client):
    scan = _seed(client)
    assert scan["status"] == "completed"
    assert (scan["found"], scan["new"]) == (2, 2)

    r = client.get("/api/inventory")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2
    assert {i["asset_type"] for i in body["items"]} == {"aws.s3.bucket"}


def test_filters(client):
    _seed(client)
    assert client.get("/api/inventory", params={"is_public": "true"}).json()["total"] == 1
    assert client.get("/api/inventory", params={"type": "aws.s3.bucket"}).json()["total"] == 2
    assert client.get("/api/inventory", params={"region": "eu-west-1"}).json()["total"] == 0
    # tag filter (in-memory pass)
    assert client.get("/api/inventory", params={"tag_key": "env", "tag_value": "prod"}).json()["total"] == 2
    assert client.get("/api/inventory", params={"tag_key": "env", "tag_value": "dev"}).json()["total"] == 0


def test_modeled_inventory_resources(client):
    _seed(client)

    response = client.get("/api/inventory/resources")
    assert response.status_code == 200
    body = response.json()

    assert body["schema_version"] == "1.0"
    assert body["totals"] == {
        "assets": 2, "filtered": 2, "public": 1, "elevated_risk": 0,
    }
    assert body["pagination"]["total"] == 2
    assert body["facets"]["categories"] == [
        {"value": "data", "label": "Data", "count": 2},
    ]

    resource = body["items"][0]
    assert resource["identity"]["service"] == "s3"
    assert resource["identity"]["category"] == "data"
    assert resource["scope"] == {"region": "us-east-1", "level": "regional"}
    assert set(resource["posture"]) == {"exposure", "is_public", "encryption", "risk", "findings"}
    assert set(resource["lifecycle"]) == {"status", "first_seen_at", "last_scanned_at", "resource_created_at"}

    searched = client.get("/api/inventory/resources", params={"q": "beta"}).json()
    assert searched["pagination"]["total"] == 1
    assert searched["items"][0]["identity"]["name"] == "beta"

    empty = client.get("/api/inventory/resources", params={"category": "compute"}).json()
    assert empty["pagination"]["total"] == 0


def test_modeled_security_domain_resources(client):
    _seed(client)
    client.post("/api/inventory/findings/evaluate", json={
        "provider": "aws", "account_identifier": "123456789012",
    })

    findings = client.get("/api/inventory/findings/resources").json()
    assert findings["schema_version"] == "1.0"
    assert findings["totals"]["open"] >= 1
    assert findings["pagination"]["total"] >= 1
    assert set(findings["items"][0]) == {
        "id", "verdict", "resource", "posture", "evidence", "remediation", "lifecycle",
    }

    identity = client.get("/api/inventory/identity/resources").json()
    assert identity["schema_version"] == "1.0"
    assert identity["totals"]["principals"] == 0
    assert identity["items"] == []

    data = client.get("/api/inventory/data-security/resources").json()
    assert data["schema_version"] == "1.0"
    assert data["totals"]["stores"] == 2
    assert data["totals"]["classified"] == 0
    assert data["facets"]["services"] == [{"value": "s3", "label": "s3", "count": 2}]
    assert data["items"][0]["classification"]["status"] == "unclassified"


def test_identity_marks_verified_onboarding_role_as_non_external(client, monkeypatch):
    account_id = "123456789012"
    scanner = "arn:aws:iam::123456789012:role/OdineyesBootstrap-Scanner"
    role_arn = f"arn:aws:iam::{account_id}:role/OdineyesReadOnly"
    monkeypatch.setenv("ODINEYES_SCANNER_PRINCIPAL_ARN", scanner)
    created = client.post("/api/inventory/accounts", json={
        "provider": "aws",
        "account_identifier": account_id,
        "role_arn": role_arn,
    }).json()
    from odineyes.db.base import get_sessionmaker
    from odineyes.db.models import CloudAccount
    with get_sessionmaker()() as session:
        external_id = session.execute(
            select(CloudAccount.external_id).where(CloudAccount.id == created["id"])
        ).scalar_one()

    response = client.post("/api/inventory/scan", json={
        "provider": "aws",
        "account_identifier": account_id,
        "resources": [{
            "source_type": "iam:role",
            "raw": {
                "RoleName": "OdineyesReadOnly",
                "Arn": role_arn,
                "trust_external": True,
                "trust_principals": [scanner],
                "AssumeRolePolicyDocument": {
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"AWS": scanner},
                        "Action": "sts:AssumeRole",
                        "Condition": {
                            "StringEquals": {"sts:ExternalId": external_id},
                        },
                    }],
                },
            },
        }],
    })
    assert response.status_code == 200

    identity = client.get("/api/inventory/identity/resources").json()
    principal = identity["items"][0]
    assert principal["trust"]["level"] == "verified"
    assert principal["trust"]["external"] is False
    assert principal["trust"]["onboarding_verified"] is True
    assert identity["totals"]["external_trust"] == 0

    detail = client.get(f"/api/inventory/identity/resources/{principal['id']}")
    assert detail.status_code == 200
    assert detail.json()["identity"]["resource_id"] == role_arn
    assert detail.json()["trust"]["onboarding_verified"] is True


def test_summary(client):
    _seed(client)
    body = client.get("/api/inventory/summary").json()
    assert body["total_assets"] == 2
    assert body["public_assets"] == 1
    assert body["by_type"]["aws.s3.bucket"] == 2
    assert body["by_provider"]["aws"] == 2
    # per-region service breakdown: region -> {asset_type: count}
    assert body["by_region_type"]["us-east-1"]["aws.s3.bucket"] == 2


def test_asset_detail_and_404(client):
    _seed(client)
    asset_id = client.get("/api/inventory").json()["items"][0]["id"]
    detail = client.get(f"/api/inventory/assets/{asset_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert "raw" in body and "normalized" in body
    assert any(e["event_type"] == "created" for e in body["events"])

    assert client.get("/api/inventory/assets/99999").status_code == 404
    assert client.get(f"/api/inventory/identity/resources/{asset_id}").status_code == 404
    assert client.get("/api/inventory/identity/resources/99999").status_code == 404


def test_asset_detail_resolves_related_resources(client):
    # An instance's USES_SECURITY_GROUP relationship stores the short sg-id, while
    # the SG asset's resource_id is the full ARN. The detail must still resolve the
    # two to each other (Wiz-style related-resource view).
    client.post("/api/inventory/accounts", json={"provider": "aws", "account_identifier": "123456789012"})
    client.post("/api/inventory/scan", json={
        "provider": "aws",
        "account_identifier": "123456789012",
        "resources": [
            {"source_type": "ec2:security-group", "raw": {
                "GroupId": "sg-0aa6605d7a911a67e", "GroupName": "web", "Region": "us-east-1", "VpcId": "vpc-1",
                "IpPermissions": [{"FromPort": 443, "ToPort": 443, "IpProtocol": "tcp",
                                   "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
            }},
            {"source_type": "ec2:instance", "raw": {
                "InstanceId": "i-1", "Region": "us-east-1", "VpcId": "vpc-1",
                "SecurityGroups": [{"GroupId": "sg-0aa6605d7a911a67e"}],
                "State": {"Name": "running"}, "Tags": [{"Key": "Name", "Value": "app"}],
            }},
        ],
    })
    items = client.get("/api/inventory").json()["items"]
    instance = next(i for i in items if i["asset_type"] == "aws.ec2.instance")
    body = client.get(f"/api/inventory/assets/{instance['id']}").json()
    sg_rel = next(r for r in body["related_resources"] if r["type"] == "USES_SECURITY_GROUP")
    assert sg_rel["asset"] is not None
    assert sg_rel["asset"]["asset_type"] == "aws.ec2.security_group"
    assert sg_rel["asset"]["resource_id"].endswith("security-group/sg-0aa6605d7a911a67e")


def test_asset_detail_correlates_vulnerabilities_and_scan_coverage(client):
    _seed(client)
    listing = client.get("/api/inventory").json()["items"]
    asset = listing[0]

    from odineyes.db.base import get_sessionmaker
    from odineyes.db.models import CloudAccount
    from odineyes.inventory.repository import SecurityScanRepository, VulnerabilityRepository

    with get_sessionmaker()() as session:
        account = session.get(CloudAccount, asset["account_id"])
        VulnerabilityRepository.sync(session, account, [SimpleNamespace(
            resource_id=asset["resource_id"],
            cve_id="CVE-2026-1000",
            package="openssl",
            installed_version="3.0.1",
            severity="high",
            cvss=8.1,
            summary="test vulnerability",
            fixed_version="3.0.2",
            scanner_source="trivy",
            package_type="debian",
            target="registry.example/app:1.2.3",
            package_path="/usr/lib/libssl.so",
        )])
        SecurityScanRepository.record(
            session,
            account,
            resource_id=asset["resource_id"],
            scanner="trivy",
            scan_kind="container_image",
            status="completed",
            package_count=12,
            findings_count=1,
        )
        session.commit()

    body = client.get(f"/api/inventory/assets/{asset['id']}").json()
    posture = body["vulnerability_posture"]
    assert posture["coverage"]["status"] == "completed"
    assert posture["coverage"]["package_count"] == 12
    assert posture["summary"]["open"] == 1
    assert posture["components"][0]["package"] == "openssl"
    assert posture["components"][0]["paths"] == ["/usr/lib/libssl.so"]
    assert posture["items"][0]["scanner_source"] == "trivy"


def test_scan_job_status(client):
    scan = _seed(client)
    r = client.get(f"/api/inventory/scan-jobs/{scan['scan_job_id']}")
    assert r.status_code == 200
    assert r.json()["status"] == "completed"
    assert r.json()["assets_found"] == 2
    assert client.get("/api/inventory/scan-jobs/99999").status_code == 404


def test_accounts_include_latest_scan_status(client):
    scan = _seed(client)
    accounts = client.get("/api/inventory/accounts")

    assert accounts.status_code == 200
    latest = accounts.json()["items"][0]["latest_scan"]
    assert latest["id"] == scan["scan_job_id"]
    assert latest["status"] == "completed"
    assert latest["error"] is None


def test_pagination(client):
    client.post("/api/inventory/accounts", json={"provider": "aws", "account_identifier": "123456789012"})
    client.post("/api/inventory/scan", json={
        "provider": "aws",
        "account_identifier": "123456789012",
        "resources": [{"source_type": "s3:bucket", "raw": s3_raw(f"bucket-{i}")} for i in range(5)],
    })
    page1 = client.get("/api/inventory", params={"page": 1, "page_size": 2}).json()
    assert page1["total"] == 5
    assert len(page1["items"]) == 2
    page3 = client.get("/api/inventory", params={"page": 3, "page_size": 2}).json()
    assert len(page3["items"]) == 1


def _rds_network_scan(*, world_open: bool) -> dict:
    """A public-endpoint RDS instance plus the network evidence around it."""
    ingress = [{
        "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
        "IpRanges": [{"CidrIp": "0.0.0.0/0" if world_open else "10.0.0.0/8"}],
    }]
    return {
        "provider": "aws",
        "account_identifier": "123456789012",
        "resources": [
            {"source_type": "aws.ec2.security_group", "raw": {
                "GroupId": "sg-db", "GroupName": "db", "VpcId": "vpc-1",
                "Region": "us-east-1", "IpPermissions": ingress,
            }},
            {"source_type": "aws.ec2.route_table", "raw": {
                "RouteTableId": "rtb-pub", "VpcId": "vpc-1", "Region": "us-east-1",
                "Associations": [{"SubnetId": "subnet-a"}],
                "Routes": [{"DestinationCidrBlock": "0.0.0.0/0",
                            "GatewayId": "igw-1", "State": "active"}],
            }},
            {"source_type": "aws.ec2.network_acl", "raw": {
                "NetworkAclId": "acl-1", "VpcId": "vpc-1", "Region": "us-east-1",
                "IsDefault": True, "Associations": [{"SubnetId": "subnet-a"}],
                "Entries": [
                    {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "Egress": False,
                     "CidrBlock": "0.0.0.0/0"},
                    {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "Egress": True,
                     "CidrBlock": "0.0.0.0/0"},
                ],
            }},
            {"source_type": "aws.ec2.internet_gateway", "raw": {
                "InternetGatewayId": "igw-1", "Region": "us-east-1",
                "Attachments": [{"VpcId": "vpc-1", "State": "available"}],
            }},
            {"source_type": "aws.rds.db_instance", "raw": {
                "DBInstanceIdentifier": "prod-db", "Engine": "postgres",
                "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:prod-db",
                "Region": "us-east-1", "PubliclyAccessible": True, "StorageEncrypted": True,
                "Endpoint": {"Address": "prod-db.rds.amazonaws.com", "Port": 5432},
                "DBSubnetGroup": {"VpcId": "vpc-1",
                                  "Subnets": [{"SubnetIdentifier": "subnet-a"}]},
                "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-db", "Status": "active"}],
            }},
        ],
    }


def _db_detail(client, payload: dict) -> dict:
    client.post("/api/inventory/accounts",
                json={"provider": "aws", "account_identifier": "123456789012"})
    client.post("/api/inventory/scan", json=payload)
    items = client.get("/api/inventory").json()["items"]
    db = next(i for i in items if i["asset_type"] == "aws.rds.db_instance")
    return client.get(f"/api/inventory/assets/{db['id']}").json()


def test_asset_detail_exposes_a_proven_reachability_verdict(client):
    body = _db_detail(client, _rds_network_scan(world_open=True))
    reachability = body["internet_reachability"]
    assert reachability["status"] == "reachable"
    assert reachability["missing"] == []
    assert any(e["source"] == "ec2:DescribeNetworkAcls" for e in reachability["evidence"])


def test_asset_detail_distinguishes_blocked_from_unverified(client):
    """A closed security group is proof, not absence of data — the operator has
    to be able to tell the two apart."""
    body = _db_detail(client, _rds_network_scan(world_open=False))
    reachability = body["internet_reachability"]
    assert reachability["status"] == "blocked"
    assert reachability["blockers"]
    assert reachability["missing"] == []


def test_asset_detail_omits_reachability_for_non_public_resources(client):
    _seed(client)
    asset_id = client.get("/api/inventory").json()["items"][0]["id"]
    body = client.get(f"/api/inventory/assets/{asset_id}").json()
    assert body["internet_reachability"] is None


def test_security_group_never_gets_rds_reachability_evidence(client):
    """A security group is a rule set, not an RDS endpoint. Even a world-open one
    scanned alongside a public database must get no reachability verdict of its
    own — otherwise the RDS assessor stamps `rds:DescribeDBInstances` evidence
    onto a non-RDS asset (the cross-asset evidence bleed)."""
    client.post("/api/inventory/accounts",
                json={"provider": "aws", "account_identifier": "123456789012"})
    client.post("/api/inventory/scan", json=_rds_network_scan(world_open=True))
    sg = next(i for i in client.get("/api/inventory").json()["items"]
              if i["asset_type"] == "aws.ec2.security_group")
    body = client.get(f"/api/inventory/assets/{sg['id']}").json()
    assert body["internet_reachability"] is None
