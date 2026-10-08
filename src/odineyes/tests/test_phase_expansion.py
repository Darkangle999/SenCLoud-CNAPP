"""Expansion slice — 9 new AWS normalizers, Azure/GCP spine readiness, the two
new rules, Lambda in the security graph, multi-account orchestration, and the
optional Neo4j projection. All offline: fakes stand in for boto3 and the
neo4j driver.
"""

from __future__ import annotations

import pytest

from odineyes.inventory.graph import AssetGraph
from odineyes.inventory.graph_store import Neo4jGraphStore
from odineyes.inventory.issues import analyze
from odineyes.inventory.normalizers import NORMALIZERS, get_normalizer
from odineyes.inventory.orchestrator import AccountRef, MultiAccountOrchestrator
from odineyes.inventory.rules import evaluate
from odineyes.inventory.schema import NormalizedAsset
from odineyes.inventory.service import InventoryService

ACCOUNT = "123456789012"


# ── new normalizers ────────────────────────────────────────────

def test_lambda_public_url():
    fn = get_normalizer("aws.lambda.function")
    a = fn({"FunctionName": "f", "FunctionArn": f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:f",
            "FunctionUrlAuthType": "NONE", "Role": f"arn:aws:iam::{ACCOUNT}:role/x"}, ACCOUNT)
    assert a.asset_type == "aws.lambda.function"
    assert a.is_public and a.network_exposure == "public"
    assert a.region == "eu-west-1"
    assert {"type": "EXECUTES_AS", "target_id": f"arn:aws:iam::{ACCOUNT}:role/x"} in a.relationships


def test_lambda_private_in_vpc():
    fn = get_normalizer("aws.lambda.function")
    a = fn({"FunctionName": "f", "Region": "us-east-1",
            "VpcConfig": {"VpcId": "vpc-1"}, "PublicPolicy": False}, ACCOUNT)
    assert not a.is_public and a.network_exposure == "vpc"


def test_ecs_cluster_shape():
    fn = get_normalizer("aws.ecs.cluster")
    a = fn({"clusterName": "prod", "clusterArn": f"arn:aws:ecs:us-east-1:{ACCOUNT}:cluster/prod",
            "status": "ACTIVE", "runningTasksCount": 7,
            "settings": [{"name": "containerInsights", "value": "enabled"}]}, ACCOUNT)
    assert a.asset_type == "aws.ecs.cluster" and a.region == "us-east-1"
    assert a.properties["running_tasks"] == 7
    assert a.properties["container_insights"] == "enabled"


def test_container_workload_and_registry_shapes():
    task = get_normalizer("aws.ecs.task_definition")({
        "taskDefinitionArn": f"arn:aws:ecs:us-east-1:{ACCOUNT}:task-definition/api:7",
        "family": "api", "revision": 7, "networkMode": "host",
        "taskRoleArn": f"arn:aws:iam::{ACCOUNT}:role/api-task",
        "containerDefinitions": [{"name": "api", "linuxParameters": {"privileged": True}}],
    }, ACCOUNT)
    eks = get_normalizer("aws.eks.cluster")({
        "name": "prod", "arn": f"arn:aws:eks:us-east-1:{ACCOUNT}:cluster/prod",
        "resourcesVpcConfig": {"endpointPublicAccess": True, "publicAccessCidrs": ["0.0.0.0/0"]},
    }, ACCOUNT)
    ecr = get_normalizer("aws.ecr.repository")({
        "repositoryName": "api", "repositoryArn": f"arn:aws:ecr:us-east-1:{ACCOUNT}:repository/api",
        "imageScanningConfiguration": {"scanOnPush": False},
        "_Evidence": {"resource_policy": "observed", "lifecycle_policy": "absent"},
    }, ACCOUNT)
    assert task.properties["privileged_containers"] == ["api"]
    assert task.properties["host_network"] is True
    assert {"type": "EXECUTES_AS", "target_id": f"arn:aws:iam::{ACCOUNT}:role/api-task"} in task.relationships
    assert eks.is_public and eks.properties["public_access_cidrs"] == ["0.0.0.0/0"]
    assert ecr.encryption_enabled and ecr.properties["image_scan_on_push"] is False


def test_secret_always_encrypted_public_flag():
    fn = get_normalizer("aws.secretsmanager.secret")
    a = fn({"Name": "db-pass", "ARN": f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:db-pass",
            "PublicPolicy": True, "RotationEnabled": True}, ACCOUNT)
    assert a.encryption_enabled is True
    assert a.is_public and a.properties["rotation_enabled"]


def test_db_cluster_family_shares_shape():
    raws = {
        "aws.rds.db_cluster": {"DBClusterIdentifier": "aurora-1", "Engine": "aurora-postgresql",
                               "StorageEncrypted": True},
        "aws.neptune.cluster": {"DBClusterIdentifier": "nep-1", "Engine": "neptune",
                                "StorageEncrypted": False},
        "aws.docdb.cluster": {"DBClusterIdentifier": "doc-1", "Engine": "docdb",
                              "StorageEncrypted": True},
    }
    for asset_type, raw in raws.items():
        a = get_normalizer(asset_type)(raw, ACCOUNT)
        assert a.asset_type == asset_type
        assert a.is_public is False                       # cluster-level default
        assert a.encryption_enabled is bool(raw["StorageEncrypted"])


def test_rds_proxy_is_vpc_only():
    a = get_normalizer("aws.rds.db_proxy")({"DBProxyName": "p", "RequireTLS": True}, ACCOUNT)
    assert not a.is_public and a.network_exposure == "vpc"
    assert a.properties["require_tls"] is True


def test_redshift_public_unencrypted():
    a = get_normalizer("aws.redshift.cluster")(
        {"ClusterIdentifier": "wh", "Region": "us-east-1",
         "PubliclyAccessible": True, "Encrypted": False,
         "Endpoint": {"Address": "wh.x.redshift.amazonaws.com", "Port": 5439}}, ACCOUNT)
    assert a.is_public and a.encryption_enabled is False
    assert a.resource_id.startswith("arn:aws:redshift:us-east-1:")


def test_elbv2_scheme_drives_exposure():
    fn = get_normalizer("aws.elbv2.load_balancer")
    pub = fn({"LoadBalancerName": "edge", "Scheme": "internet-facing",
              "SecurityGroups": ["sg-9"], "Type": "application"}, ACCOUNT)
    internal = fn({"LoadBalancerName": "internal", "Scheme": "internal"}, ACCOUNT)
    assert pub.is_public and not internal.is_public
    assert {"type": "USES_SECURITY_GROUP", "target_id": "sg-9"} in pub.relationships


def test_azure_and_gcp_normalizers():
    az = get_normalizer("azure.storage.account")(
        {"name": "stor1", "location": "westeurope",
         "properties": {"allowBlobPublicAccess": True}}, "sub-1")
    assert az.cloud_provider == "azure" and az.is_public

    gcp = get_normalizer("gcp.storage.bucket")(
        {"name": "bkt", "location": "EU", "PublicBinding": True}, "proj-1")
    assert gcp.cloud_provider == "gcp" and gcp.is_public
    assert gcp.encryption_enabled is True


def test_registry_covers_all_new_types():
    for t in ["aws.lambda.function", "aws.ecs.cluster", "aws.secretsmanager.secret",
              "aws.ecs.task_definition", "aws.eks.cluster", "aws.ecr.repository",
              "aws.rds.db_cluster", "aws.neptune.cluster", "aws.docdb.cluster",
              "aws.rds.db_proxy", "aws.redshift.cluster", "aws.elbv2.load_balancer",
              "azure.storage.account", "gcp.storage.bucket"]:
        assert t in NORMALIZERS, t


# ── new rules ──────────────────────────────────────────────────

def _lambda_asset(public: bool) -> NormalizedAsset:
    return NormalizedAsset(
        resource_id=f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:f", cloud_provider="aws",
        account_identifier=ACCOUNT, asset_type="aws.lambda.function", name="f",
        is_public=public, properties={"function_url_auth": "NONE" if public else None},
    )


def _warehouse(public: bool, encrypted: bool) -> NormalizedAsset:
    return NormalizedAsset(
        resource_id=f"arn:aws:redshift:us-east-1:{ACCOUNT}:cluster:wh", cloud_provider="aws",
        account_identifier=ACCOUNT, asset_type="aws.redshift.cluster", name="wh",
        is_public=public, encryption_enabled=encrypted,
    )


def test_rule_public_lambda():
    fired = evaluate([_lambda_asset(public=True)])
    assert [f.rule_id for f in fired] == ["PUBLIC_LAMBDA_URL"]
    assert evaluate([_lambda_asset(public=False)]) == []


def test_rule_public_warehouse_severity():
    crit = evaluate([_warehouse(public=True, encrypted=False)])
    high = evaluate([_warehouse(public=True, encrypted=True)])
    assert crit[0].rule_id == "PUBLIC_WAREHOUSE" and crit[0].severity == "critical"
    assert high[0].severity == "high"
    assert evaluate([_warehouse(public=False, encrypted=True)]) == []


# ── graph: lambda joins the compute tier ───────────────────────

def _admin_role(name="exec-role") -> NormalizedAsset:
    return NormalizedAsset(
        resource_id=f"arn:aws:iam::{ACCOUNT}:role/{name}", cloud_provider="aws",
        account_identifier=ACCOUNT, asset_type="aws.iam.role", name=name,
        properties={"has_admin": True, "admin_reason": "AdministratorAccess"},
    )


def test_public_lambda_with_admin_role_is_attack_path():
    lam = NormalizedAsset(
        resource_id=f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:f", cloud_provider="aws",
        account_identifier=ACCOUNT, asset_type="aws.lambda.function", name="f",
        is_public=True, network_exposure="public",
        relationships=[{"type": "EXECUTES_AS", "target_id": f"arn:aws:iam::{ACCOUNT}:role/exec-role"}],
    )
    g = AssetGraph.build([lam, _admin_role()])
    assert [e.dst for e in g.out_edges(lam.resource_id, "CAN_ASSUME")] == [
        f"arn:aws:iam::{ACCOUNT}:role/exec-role"]

    issues = analyze([lam, _admin_role()])
    assert any(i.issue_type == "PUBLIC_COMPUTE_TO_ADMIN" for i in issues)


# ── multi-account orchestration ────────────────────────────────

class _FakeCollector:
    def __init__(self, resources):
        self._resources = resources

    def collect(self):
        return self._resources


def test_orchestrator_scans_all_accounts_in_isolation(tmp_path):
    svc = InventoryService(database_url=f"sqlite:///{tmp_path}/fleet.db")
    svc.persist_normalized("aws", "111111111111", [])   # register two accounts
    svc.persist_normalized("aws", "222222222222", [])

    captured_refs: list[AccountRef] = []

    def session_factory(ref: AccountRef):
        captured_refs.append(ref)
        return ref   # handed through to the collector factory below

    def collector_factory(session, region):
        # Bucket names are globally unique in real AWS — mirror that here, or
        # the (resource_id, cloud_provider) natural key rightly collides.
        return _FakeCollector([
            ("aws.s3.bucket", {"Name": f"pub-{session.identifier}", "Region": region,
                               "PolicyStatus": {"IsPublic": True},
                               "Encryption": {"enabled": True}, "PublicAccessBlock": {}}),
        ])

    orch = MultiAccountOrchestrator(
        svc, region="us-east-1", max_workers=2,
        session_factory=session_factory, collector_factory=collector_factory,
    )
    results = orch.scan_all("aws")

    assert len(results) == 2
    assert all(r.status == "completed" for r in results)
    assert {r.account_identifier for r in results} == {"111111111111", "222222222222"}
    assert all(r.scan.found == 1 for r in results)
    assert all(r.findings.total == 1 for r in results)          # PUBLIC_BUCKET fires per account
    assert {ref.identifier for ref in captured_refs} == {"111111111111", "222222222222"}


def test_orchestrator_isolates_account_failure(tmp_path):
    svc = InventoryService(database_url=f"sqlite:///{tmp_path}/fleet2.db")
    svc.persist_normalized("aws", "111111111111", [])
    svc.persist_normalized("aws", "222222222222", [])

    def session_factory(ref: AccountRef):
        if ref.identifier == "111111111111":
            raise RuntimeError("AccessDenied: cannot assume role")
        return object()

    orch = MultiAccountOrchestrator(
        svc, session_factory=session_factory,
        collector_factory=lambda s, r: _FakeCollector([]),
    )
    results = {r.account_identifier: r for r in orch.scan_all("aws")}

    assert results["111111111111"].status == "failed"
    assert "AccessDenied" in results["111111111111"].error
    assert results["222222222222"].status == "completed"


# ── Neo4j projection (fake driver) ─────────────────────────────

class _FakeNeoSession:
    def __init__(self, log):
        self._log = log

    def run(self, query, **params):
        self._log.append((query, params))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeNeoDriver:
    def __init__(self):
        self.queries: list[tuple] = []
        self.closed = False

    def session(self):
        return _FakeNeoSession(self.queries)

    def close(self):
        self.closed = True


def test_neo4j_projection_writes_nodes_edges_and_prunes():
    lam = NormalizedAsset(
        resource_id=f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:f", cloud_provider="aws",
        account_identifier=ACCOUNT, asset_type="aws.lambda.function", name="f",
        is_public=True, network_exposure="public",
        relationships=[{"type": "EXECUTES_AS", "target_id": f"arn:aws:iam::{ACCOUNT}:role/exec-role"}],
    )
    graph = AssetGraph.build([lam, _admin_role()])
    driver = _FakeNeoDriver()
    store = Neo4jGraphStore(driver)

    counts = store.sync_account(ACCOUNT, graph)
    store.close()

    assert counts["nodes"] == 3          # internet + lambda + role
    assert counts["edges"] >= 2          # EXPOSED_TO + CAN_ASSUME
    joined = " ".join(q for q, _ in driver.queries)
    assert "MERGE (a:Asset" in joined and "DETACH DELETE" in joined
    assert "CAN_ASSUME" in joined and "EXPOSED_TO" in joined
    assert driver.closed


def test_neo4j_store_off_without_env(monkeypatch):
    monkeypatch.delenv("ODINEYES_NEO4J_URI", raising=False)
    assert Neo4jGraphStore.from_env() is None
