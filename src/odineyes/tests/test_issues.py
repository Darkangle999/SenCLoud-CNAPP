"""Attack-path issue engine — graph building, detectors, risk model,
persistence lifecycle, per-asset risk, and the REST surface.

Same fixture style as test_rules/test_findings: hand-built NormalizedAsset
objects (the engine reads only standard fields, so in-memory and DB rows
behave identically).
"""

from __future__ import annotations

import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from odineyes.inventory.graph import INTERNET_ID, AssetGraph
from odineyes.inventory.issues import _severity_for, analyze
from odineyes.inventory.schema import NormalizedAsset
from odineyes.inventory.service import InventoryService

ACCOUNT = "123456789012"


def ec2(public=True, profile="web-role", sgs=("sg-1",), iid="i-1") -> NormalizedAsset:
    rels = [{"type": "BELONGS_TO", "target_id": ACCOUNT}]
    rels += [{"type": "USES_SECURITY_GROUP", "target_id": s} for s in sgs]
    props = {
        "security_group_ids": list(sgs),
        "public_ip": "203.0.113.10" if public else None,
        "vpc_id": "vpc-db",
        "subnet_id": "subnet-db",
    }
    if profile:
        props["iam_instance_profile"] = f"arn:aws:iam::{ACCOUNT}:instance-profile/{profile}"
        rels.append({"type": "USES_INSTANCE_PROFILE", "target_id": props["iam_instance_profile"]})
    return NormalizedAsset(
        resource_id=f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/{iid}",
        cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type="aws.ec2.instance", name=iid, region="us-east-1",
        is_public=public, network_exposure="public" if public else "vpc",
        properties=props, relationships=rels,
    )


def sg(ports=(22,), gid="sg-1") -> NormalizedAsset:
    labels = {0: "ALL", 22: "SSH", 3389: "RDP", 443: "HTTPS"}
    ingress = [
        {"cidr": "0.0.0.0/0", "protocol": "-1" if port == 0 else "tcp",
         "from_port": None if port == 0 else port, "to_port": None if port == 0 else port}
        for port in ports
    ]
    return NormalizedAsset(
        resource_id=f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/{gid}",
        cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type="aws.ec2.security_group", name=gid, region="us-east-1",
        is_public=False, network_exposure="vpc",
        properties={"open_ports": list(ports),
                    "open_port_labels": [labels.get(p, str(p)) for p in ports],
                    "world_open_ingress": ingress},
    )


def role(admin=True, name="web-role", privesc=(), external=False, wildcard=False,
         federated=()) -> NormalizedAsset:
    return NormalizedAsset(
        resource_id=f"arn:aws:iam::{ACCOUNT}:role/{name}",
        cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type="aws.iam.role", name=name,
        is_public=wildcard, network_exposure="public" if wildcard else "private",
        properties={
            "has_admin": admin, "admin_reason": "AdministratorAccess" if admin else None,
            "privesc_actions": list(privesc),
            "trust_external": external or wildcard, "publicly_assumable": wildcard,
            "trust_principals": ["arn:aws:iam::999999999999:root"] if external else [],
            "trust_federated": list(federated),
        },
    )


_GHA_OIDC = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"


def test_overprivileged_cicd_role_flagged():
    issues = analyze([role(admin=True, name="gha-deploy", federated=[_GHA_OIDC])])
    cicd = [i for i in issues if i.issue_type == "OVERPRIVILEGED_CICD_ROLE"]
    assert len(cicd) == 1
    assert cicd[0].severity == "critical"
    assert "github" in cicd[0].why.lower()
    assert cicd[0].compliance.get("CIS")  # mapped to compliance controls


def test_cicd_role_privesc_only_is_high():
    issues = analyze([role(admin=False, name="gha-iam", privesc=["iam:PutRolePolicy"],
                           federated=[_GHA_OIDC])])
    cicd = [i for i in issues if i.issue_type == "OVERPRIVILEGED_CICD_ROLE"]
    assert len(cicd) == 1 and cicd[0].severity == "high"


def test_cicd_role_least_privilege_not_flagged():
    # Federated to GitHub but no admin and no privesc primitives → not a path.
    issues = analyze([role(admin=False, name="gha-readonly", federated=[_GHA_OIDC])])
    assert not any(i.issue_type == "OVERPRIVILEGED_CICD_ROLE" for i in issues)


def _tagged_bucket(env: str):
    b = bucket(public=True, name="assets")
    b.tags = {"Environment": env}
    return b


def test_prod_tag_outranks_nonprod_same_issue():
    prod = [i for i in analyze([_tagged_bucket("production")]) if i.issue_type == "PUBLIC_S3_EXPOSURE"][0]
    dev = [i for i in analyze([_tagged_bucket("dev")]) if i.issue_type == "PUBLIC_S3_EXPOSURE"][0]
    base = [i for i in analyze([bucket(public=True, name="assets")]) if i.issue_type == "PUBLIC_S3_EXPOSURE"][0]
    # prod escalates, dev de-prioritises, untagged is the baseline in between.
    assert prod.risk_score > base.risk_score > dev.risk_score


def bucket(public=False, name="app-assets", encrypted=True) -> NormalizedAsset:
    return NormalizedAsset(
        resource_id=f"arn:aws:s3:::{name}",
        cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type="aws.s3.bucket", name=name,
        is_public=public, encryption_enabled=encrypted,
        network_exposure="public" if public else "private",
    )


def rds(public=True, encrypted=False, name="db-1", sgs=(), port=5432, subnets=("subnet-db",)) -> NormalizedAsset:
    rels = [{"type": "BELONGS_TO", "target_id": ACCOUNT}]
    rels += [{"type": "USES_SECURITY_GROUP", "target_id": s} for s in sgs]
    return NormalizedAsset(
        resource_id=f"arn:aws:rds:us-east-1:{ACCOUNT}:db:{name}",
        cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type="aws.rds.db_instance", name=name, region="us-east-1",
        is_public=False, encryption_enabled=encrypted, network_exposure="vpc",
        properties={"engine": "postgres", "port": port, "vpc_id": "vpc-db",
                    "publicly_accessible": public, "subnet_ids": list(subnets),
                    "security_group_ids": list(sgs)},
        relationships=rels,
    )


def rds_public_network(subnet="subnet-db", *, inbound=True, outbound=True) -> list[NormalizedAsset]:
    """Minimal collected EC2 evidence for a world-to-RDS proof."""
    entries = [
        {"rule_number": 100, "protocol": "-1", "rule_action": "allow" if inbound else "deny",
         "egress": False, "cidr_block": "0.0.0.0/0", "from_port": None, "to_port": None},
        {"rule_number": 100, "protocol": "-1", "rule_action": "allow" if outbound else "deny",
         "egress": True, "cidr_block": "0.0.0.0/0", "from_port": None, "to_port": None},
    ]
    return [
        NormalizedAsset(
            resource_id=f"arn:aws:ec2:us-east-1:{ACCOUNT}:route-table/rtb-db",
            cloud_provider="aws", account_identifier=ACCOUNT, asset_type="aws.ec2.route_table",
            name="rtb-db", region="us-east-1",
            properties={"vpc_id": "vpc-db", "associations": [{"subnet_id": subnet, "main": False}],
                        "routes": [{"destination_cidr_block": "0.0.0.0/0", "gateway_id": "igw-db", "state": "active"}]},
        ),
        NormalizedAsset(
            resource_id=f"arn:aws:ec2:us-east-1:{ACCOUNT}:network-acl/acl-db",
            cloud_provider="aws", account_identifier=ACCOUNT, asset_type="aws.ec2.network_acl",
            name="acl-db", region="us-east-1",
            properties={"vpc_id": "vpc-db", "is_default": True, "subnet_ids": [subnet], "entries": entries},
        ),
        NormalizedAsset(
            resource_id=f"arn:aws:ec2:us-east-1:{ACCOUNT}:internet-gateway/igw-db",
            cloud_provider="aws", account_identifier=ACCOUNT, asset_type="aws.ec2.internet_gateway",
            name="igw-db", region="us-east-1", properties={"attached_vpc_ids": ["vpc-db"]},
        ),
    ]


# ── graph building ─────────────────────────────────────────────

def test_graph_resolves_sg_and_role_edges():
    g = AssetGraph.build([
        ec2(), sg(ports=(22,)), role(admin=True), *rds_public_network(),
    ])
    inst_id = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-1"
    assert [e.dst for e in g.out_edges(inst_id, "USES_SECURITY_GROUP")] == [
        f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/sg-1"]
    assert [e.dst for e in g.out_edges(inst_id, "CAN_ASSUME")] == [
        f"arn:aws:iam::{ACCOUNT}:role/web-role"]
    exposed = g.out_edges(INTERNET_ID, "EXPOSED_TO")
    inst_edge = next(e for e in exposed if e.dst == inst_id)
    assert inst_edge.properties["port_labels"] == ["SSH"]


def test_graph_admin_role_reaches_all_buckets():
    g = AssetGraph.build([role(admin=True), bucket(name="a"), bucket(name="b")])
    role_id = f"arn:aws:iam::{ACCOUNT}:role/web-role"
    assert len(g.out_edges(role_id, "CAN_ACCESS")) == 2


def test_graph_no_role_edge_without_name_match():
    g = AssetGraph.build([ec2(profile="other-profile"), role(name="web-role")])
    inst_id = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-1"
    assert g.out_edges(inst_id, "CAN_ASSUME") == []


def test_serialize_emits_nodes_and_edges_for_canvas():
    g = AssetGraph.build([
        ec2(), sg(ports=(22,)), role(admin=True), bucket(name="a"),
        *rds_public_network(),
    ])
    data = g.serialize()
    by_id = {n["id"]: n for n in data["nodes"]}
    inst_id = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-1"
    assert by_id[inst_id]["kind"] == "compute"
    assert by_id[inst_id]["is_public"] is True
    # admin role flag surfaces for the crown badge
    role_id = f"arn:aws:iam::{ACCOUNT}:role/web-role"
    assert by_id[role_id]["properties"]["has_admin"] is True
    # the internet→compute exposure carries its open ports
    exposed = next(e for e in data["edges"] if e["type"] == "EXPOSED_TO" and e["target"] == inst_id)
    assert exposed["ports"] == ["SSH"]
    # every edge endpoint is a real node (no dangling references)
    ids = set(by_id)
    assert all(e["source"] in ids and e["target"] in ids for e in data["edges"])


# ── detectors ──────────────────────────────────────────────────

def test_public_compute_to_admin_fires():
    issues = analyze([ec2(), sg(), role(admin=True), *rds_public_network()])
    types = [i.issue_type for i in issues]
    assert "PUBLIC_COMPUTE_TO_ADMIN" in types
    top = next(i for i in issues if i.issue_type == "PUBLIC_COMPUTE_TO_ADMIN")
    assert top.severity == "critical"
    assert [h["kind"] for h in top.path] == ["internet", "compute", "role"]
    assert 0 < top.risk_score <= 100
    # Fully asset-backed, config-derived path → high confidence (never the 0 a
    # naive "is the timestamp set" check would wrongly produce on fixtures).
    assert 0.8 <= top.confidence <= 1.0


def test_private_compute_is_silent():
    issues = analyze([ec2(public=False), sg(), role(admin=True)])
    assert all(i.issue_type != "PUBLIC_COMPUTE_TO_ADMIN" for i in issues)


def test_compute_to_data_aggregates_buckets():
    issues = analyze([ec2(), sg(), role(admin=True),
                      bucket(name="customer-data"), bucket(name="app-assets"),
                      *rds_public_network()],
                     data_labels={"customer-data": "CRITICAL"})
    data = [i for i in issues if i.issue_type == "PUBLIC_COMPUTE_TO_DATA"]
    assert len(data) == 1                       # one issue per (instance, role)
    assert data[0].severity == "critical"       # DSPM-confirmed sensitive bucket present
    assert len(data[0].related) == 2
    assert data[0].path[-1]["name"] == "customer-data"


def test_public_endpoint_without_network_proof_is_not_an_attack_path():
    issues = analyze([bucket(public=True, name="prod-backup", encrypted=False),
                      rds(public=True, encrypted=False)])
    types = {i.issue_type for i in issues}
    assert types == {"PUBLIC_S3_EXPOSURE"}
    b = next(i for i in issues if i.issue_type == "PUBLIC_S3_EXPOSURE")
    # Sensitive-looking names are hints, not content evidence. Without DSPM,
    # this remains high rather than becoming a false critical.
    assert b.severity == "high" and "unencrypted" in b.why
    assert b.evidence[0]["observation"] == "sensitivity = UNCLASSIFIED"


def test_public_db_with_closed_security_group_has_no_attack_path():
    # The user's reported case: endpoint configured but SG closed. This must
    # produce no Internet -> DB edge and no synthetic low-risk attack path.
    issues = analyze([rds(public=True, encrypted=True, name="cust-db", sgs=("sg-db",)),
                      sg(ports=(), gid="sg-db")])           # SG opens nothing to 0.0.0.0/0
    assert not any(issue.issue_type == "PUBLIC_DATABASE_PATH" for issue in issues)
    graph = AssetGraph.build([rds(public=True, encrypted=True, name="cust-db", sgs=("sg-db",)), sg(ports=(), gid="sg-db")])
    db = graph.node(f"arn:aws:rds:us-east-1:{ACCOUNT}:db:cust-db")
    assert db.properties["internet_reachability"]["status"] == "blocked"


def test_db_evidence_cites_the_open_ingress_rule():
    issues = analyze([rds(public=True, encrypted=False, name="d", sgs=("sg-o",)),
                      sg(ports=(5432,), gid="sg-o"), *rds_public_network()])
    db = next(i for i in issues if i.issue_type == "PUBLIC_DATABASE_PATH")
    sg_ev = next(e for e in db.evidence if e["source"] == "ec2:DescribeSecurityGroups")
    assert "sg-o" in sg_ev["observation"] and "0.0.0.0/0" in sg_ev["observation"]
    assert "database port" in sg_ev["effect"]
    assert any(e["source"] == "ec2:DescribeRouteTables" for e in db.evidence)
    assert any(e["source"] == "ec2:DescribeNetworkAcls" for e in db.evidence)


def test_world_open_db_requires_full_network_proof():
    # A world-open security group is necessary but not enough. The complete
    # topology yields a path; a closed SG yields none.
    open_db = analyze([rds(public=True, encrypted=False, name="d", sgs=("sg-o",)),
                       sg(ports=(5432,), gid="sg-o"), *rds_public_network()])
    shut_db = analyze([rds(public=True, encrypted=False, name="d", sgs=("sg-c",)),
                       sg(ports=(), gid="sg-c")])
    o = next(i.risk_score for i in open_db if i.issue_type == "PUBLIC_DATABASE_PATH")
    assert o > 0
    assert not any(i.issue_type == "PUBLIC_DATABASE_PATH" for i in shut_db)


def test_public_db_with_denying_network_acl_has_no_attack_path():
    issues = analyze([rds(public=True, encrypted=False, name="d", sgs=("sg-o",)),
                      sg(ports=(5432,), gid="sg-o"), *rds_public_network(inbound=False)])
    assert not any(issue.issue_type == "PUBLIC_DATABASE_PATH" for issue in issues)


def test_cross_account_and_privesc():
    issues = analyze([role(admin=True, name="ext", wildcard=True),
                      role(admin=False, name="esc", privesc=("iam:PutRolePolicy",))])
    types = {i.issue_type for i in issues}
    assert "CROSS_ACCOUNT_LATERAL" in types and "IAM_PRIVILEGE_ESCALATION" in types
    lateral = next(i for i in issues if i.issue_type == "CROSS_ACCOUNT_LATERAL")
    assert lateral.severity == "critical"       # admin + wildcard trust


def test_verified_odineyes_onboarding_trust_is_not_an_attack_path():
    scanner = "arn:aws:iam::123456789012:role/OdineyesScanner"
    external_id = "cs-account-stable-external-id"
    onboarded = role(admin=False, name="OdineyesReadOnly")
    onboarded.properties.update({
        "trust_external": True,
        "trust_principals": [scanner],
    })
    # Deliberately use raw policy evidence rather than the newly normalized
    # property: inventories already stored before this release must be fixed on
    # their next issue evaluation without needing a fresh cloud scan.
    onboarded.raw = {
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": scanner},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }],
        },
    }
    context = {
        "scanner_principal_arn": scanner,
        "account_external_ids": {ACCOUNT: external_id},
        "account_role_arns": {ACCOUNT: onboarded.resource_id},
    }

    graph = AssetGraph.build([onboarded], **context)
    edge = graph.out_edges(f"external:{scanner}", "CAN_ASSUME")[0]
    assert edge.properties["verified_onboarding"] is True
    assert graph.enumerate_paths() == []
    assert not any(
        issue.issue_type == "CROSS_ACCOUNT_LATERAL"
        for issue in analyze([onboarded], **context)
    )


def test_unregistered_role_or_wrong_external_id_remains_a_cross_account_risk():
    scanner = "arn:aws:iam::123456789012:role/OdineyesScanner"
    registered_external_id = "cs-registered"
    other_role = role(admin=False, name="not-the-registered-role")
    other_role.properties.update({
        "trust_external": True,
        "trust_principals": [scanner],
        "trust_statements": [{"principals": [scanner], "external_ids": [registered_external_id]}],
    })
    registered_role_arn = f"arn:aws:iam::{ACCOUNT}:role/OdineyesReadOnly"
    context = {
        "scanner_principal_arn": scanner,
        "account_external_ids": {ACCOUNT: registered_external_id},
        "account_role_arns": {ACCOUNT: registered_role_arn},
    }

    issue = next(
        item for item in analyze([other_role], **context)
        if item.issue_type == "CROSS_ACCOUNT_LATERAL"
    )
    assert "ExternalId are approved" in issue.remediation


def test_ranked_by_risk_and_deduped():
    issues = analyze([
        ec2(), sg(), role(admin=True), bucket(public=True), rds(),
        *rds_public_network(),
    ])
    risks = [i.risk_score for i in issues]
    assert risks == sorted(risks, reverse=True)
    assert len({i.path_hash for i in issues}) == len(issues)


def test_confirmed_data_sensitivity_raises_path_above_unclassified_name_hint():
    # Classification outranks names. A generic bucket with confirmed sensitive
    # data must rank above a scary-looking but unclassified bucket.
    pii = analyze(
        [bucket(public=True, name="opaque-store")],
        data_labels={"opaque-store": "CRITICAL"},
    )
    generic = analyze([bucket(public=True, name="customer-ssn-data")])
    pii_risk = next(i.risk_score for i in pii if i.issue_type == "PUBLIC_S3_EXPOSURE")
    gen_risk = next(i.risk_score for i in generic if i.issue_type == "PUBLIC_S3_EXPOSURE")
    assert pii_risk > gen_risk
    assert next(i for i in pii if i.issue_type == "PUBLIC_S3_EXPOSURE").severity == "critical"
    assert next(i for i in generic if i.issue_type == "PUBLIC_S3_EXPOSURE").severity == "high"


def test_policy_backed_role_chain_reaches_private_data():
    source = role(admin=False, name="web-role")
    source.properties.update({
        "assume_role_resources": [f"arn:aws:iam::{ACCOUNT}:role/data-role"],
        "policy_analysis_complete": True,
    })
    target = role(admin=False, name="data-role")
    target.properties.update({
        "trust_principals": [f"arn:aws:iam::{ACCOUNT}:root"],
        "s3_read_resources": ["arn:aws:s3:::customer-prod-data/*"],
        "policy_analysis_complete": True,
    })
    data = bucket(public=False, name="customer-prod-data")

    graph = AssetGraph.build([
        ec2(), sg(), source, target, data, *rds_public_network(),
    ])
    assert [edge.dst for edge in graph.out_edges(source.resource_id, "CAN_ASSUME")] == [target.resource_id]
    assert [edge.dst for edge in graph.out_edges(target.resource_id, "CAN_ACCESS")] == [data.resource_id]

    paths = graph.enumerate_paths()
    assert any(path["nodes"] == [
        INTERNET_ID, ec2().resource_id, source.resource_id, target.resource_id, data.resource_id,
    ] for path in paths)

    issue = next(item for item in analyze([
        ec2(), sg(), source, target, data, *rds_public_network(),
    ])
                 if item.issue_type == "PUBLIC_COMPUTE_TO_DATA")
    assert [hop["kind"] for hop in issue.path] == ["internet", "compute", "role", "role", "bucket"]
    assert "web-role -> data-role" in issue.why


def test_graph_analysis_explains_clean_vs_incomplete_evidence():
    complete_role = role(admin=False, name="read-role")
    complete_role.properties["policy_analysis_complete"] = True
    graph = AssetGraph.build([complete_role, bucket(public=False)])
    summary = graph.analysis_summary(total_assets=2, paths=graph.enumerate_paths())
    assert summary["status"] == "ready"
    assert summary["conclusion"] == "no_entry_points_observed"

    legacy_role = role(admin=False, name="legacy")
    partial = AssetGraph.build([legacy_role, bucket(public=False)])
    summary = partial.analysis_summary(total_assets=2, paths=partial.enumerate_paths())
    assert summary["status"] == "partial"
    assert summary["conclusion"] == "insufficient_identity_evidence"


# ── persistence lifecycle ──────────────────────────────────────

@pytest.fixture()
def svc(tmp_path):
    return InventoryService(database_url=f"sqlite:///{tmp_path}/issues.db")


def test_evaluate_issues_opens_then_idempotent(svc):
    svc.persist_normalized(
        "aws", ACCOUNT, [ec2(), sg(), role(admin=True), *rds_public_network()]
    )
    stats = svc.evaluate_issues("aws", ACCOUNT)
    assert stats.new == stats.total and stats.total >= 1
    again = svc.evaluate_issues("aws", ACCOUNT)
    assert again.new == 0 and again.reopened == 0 and again.resolved == 0
    assert again.total == stats.total


def test_closed_path_resolves_then_reopens(svc):
    svc.persist_normalized(
        "aws", ACCOUNT, [ec2(), sg(), role(admin=True), *rds_public_network()]
    )
    svc.evaluate_issues("aws", ACCOUNT)
    # remediate: instance loses its public IP -> path closes
    svc.persist_normalized(
        "aws", ACCOUNT, [ec2(public=False), sg(), role(admin=True), *rds_public_network()]
    )
    stats = svc.evaluate_issues("aws", ACCOUNT)
    assert stats.resolved >= 1 and stats.total == 0
    # regression
    svc.persist_normalized(
        "aws", ACCOUNT, [ec2(), sg(), role(admin=True), *rds_public_network()]
    )
    stats = svc.evaluate_issues("aws", ACCOUNT)
    assert stats.reopened >= 1 and stats.new == 0


def test_asset_risk_score_updated(svc):
    svc.persist_normalized(
        "aws", ACCOUNT, [ec2(), sg(), role(admin=True), *rds_public_network()]
    )
    svc.evaluate_issues("aws", ACCOUNT)
    from odineyes.db.base import session_scope
    from odineyes.db.models import Asset
    with session_scope(svc._url) as session:
        inst = session.query(Asset).filter(
            Asset.resource_id.like("%instance/i-1")).one()
        the_role = session.query(Asset).filter(
            Asset.resource_id.like("%role/web-role")).one()
        assert inst.risk_score > 0
        assert the_role.risk_score > 0   # role is on the path


def test_collateral_risk_is_decayed_below_entry_point(svc):
    """A private bucket reachable only because an admin role can read it must
    score below the role itself — blast radius without flattened ranking."""
    svc.persist_normalized("aws", ACCOUNT, [
        role(admin=True, name="ext", wildcard=True),
        bucket(public=False, name="innocent-private"),
    ])
    svc.evaluate_issues("aws", ACCOUNT)
    from odineyes.db.base import session_scope
    from odineyes.db.models import Asset
    with session_scope(svc._url) as session:
        the_role = session.query(Asset).filter(Asset.resource_id.like("%role/ext")).one()
        b = session.query(Asset).filter(Asset.resource_id.like("%innocent-private")).one()
        assert the_role.risk_score >= 90        # entry point of CROSS_ACCOUNT_LATERAL, full
        assert 0 < b.risk_score < the_role.risk_score   # collateral, decayed
        assert b.risk_score == round(the_role.risk_score * 0.5, 1)


# ── API ────────────────────────────────────────────────────────

@pytest.fixture()
def client(tmp_path):
    url = f"sqlite:///{tmp_path}/issues_api.db"
    os.environ["ODINEYES_DATABASE_URL"] = url
    from odineyes.db.base import init_db
    init_db(url)
    from odineyes.api.inventory_routes import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _seed(client):
    client.post("/api/inventory/scan", json={
        "provider": "aws", "account_identifier": ACCOUNT,
        "resources": [
            {"source_type": "aws.ec2.instance", "raw": {
                "InstanceId": "i-1", "Region": "us-east-1", "PublicIpAddress": "3.3.3.3",
                "VpcId": "vpc-db", "SubnetId": "subnet-db",
                "SecurityGroups": [{"GroupId": "sg-1"}],
                "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/web-role"}}},
            {"source_type": "aws.ec2.security_group", "raw": {
                "GroupId": "sg-1", "GroupName": "open", "Region": "us-east-1",
                "IpPermissions": [{"FromPort": 22, "ToPort": 22,
                                   "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}},
            {"source_type": "aws.iam.role", "raw": {
                "RoleName": "web-role", "Arn": f"arn:aws:iam::{ACCOUNT}:role/web-role",
                "AssumeRolePolicyDocument": {"Statement": []},
                "has_admin": True, "admin_reason": "AdministratorAccess"}},
            {"source_type": "aws.ec2.route_table", "raw": {
                "RouteTableId": "rtb-db", "Region": "us-east-1", "VpcId": "vpc-db",
                "Associations": [{"SubnetId": "subnet-db", "Main": False}],
                "Routes": [{"DestinationCidrBlock": "0.0.0.0/0",
                            "GatewayId": "igw-db", "State": "active"}]}},
            {"source_type": "aws.ec2.internet_gateway", "raw": {
                "InternetGatewayId": "igw-db", "Region": "us-east-1",
                "Attachments": [{"VpcId": "vpc-db", "State": "available"}]}},
            {"source_type": "aws.ec2.network_acl", "raw": {
                "NetworkAclId": "acl-db", "Region": "us-east-1", "VpcId": "vpc-db",
                "IsDefault": True, "Associations": [{"SubnetId": "subnet-db"}],
                "Entries": [
                    {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow",
                     "Egress": False, "CidrBlock": "0.0.0.0/0"},
                    {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow",
                     "Egress": True, "CidrBlock": "0.0.0.0/0"},
                ]}},
        ],
    })
    return client.post("/api/inventory/issues/evaluate",
                       json={"provider": "aws", "account_identifier": ACCOUNT}).json()


def test_api_evaluate_then_list_issues(client):
    ev = _seed(client)
    assert ev["new"] >= 1

    body = client.get("/api/inventory/issues").json()
    assert body["total"] >= 1
    top = body["items"][0]
    assert top["issue_type"] == "PUBLIC_COMPUTE_TO_ADMIN"
    assert top["risk_score"] > 0 and top["status"] == "open"
    assert [h["kind"] for h in top["path"]] == ["internet", "compute", "role"]


def test_api_issues_summary_and_asset_risk(client):
    _seed(client)
    s = client.get("/api/inventory/issues/summary").json()
    assert s["open"] >= 1 and s["max_risk"] > 0
    assert "PUBLIC_COMPUTE_TO_ADMIN" in s["by_type"]

    assets = client.get("/api/inventory").json()["items"]
    inst = next(a for a in assets if a["asset_type"] == "aws.ec2.instance")
    assert inst["risk_score"] > 0
