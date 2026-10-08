"""Parity between the Python and Go attack-path engines.

The Go engine is a reimplementation of security detection logic. The only thing
that makes that safe is proof that it reaches the same verdicts, so these tests
run both engines over the same fixtures and compare every field an operator
acts on — not just which paths were found, but their severity, score,
confidence, hop order and remediation text.

The tests skip when the Go binary is absent so the suite still runs on a
machine without a Go toolchain. ``test_go_engine_binary_is_available`` is the
guard against that skip becoming permanent and silent: set
ODINEYES_REQUIRE_GO_GRAPH=1 in CI and a missing binary is a failure.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone

import pytest

from odineyes.inventory import graph_engine
from odineyes.inventory.issues import analyze as analyze_python
from odineyes.inventory.schema import NormalizedAsset

ACCOUNT = "123456789012"
NOW = datetime(2026, 8, 7, 12, 0, 0, tzinfo=timezone.utc)


def _binary() -> str | None:
    configured = (os.environ.get(graph_engine.ENV_BINARY) or "").strip()
    if configured and os.path.isfile(configured):
        return configured
    for candidate in (
        "scanner-go/bin/odineyes-graph.exe",
        "scanner-go/bin/odineyes-graph",
    ):
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    return shutil.which(graph_engine.DEFAULT_BINARY)


@pytest.fixture()
def go_binary(monkeypatch):
    path = _binary()
    if not path:
        pytest.skip("Go graph engine binary not built")
    monkeypatch.setenv(graph_engine.ENV_BINARY, path)
    return path


def test_go_engine_binary_is_available():
    """CI must not silently skip the whole parity suite."""
    if not os.environ.get("ODINEYES_REQUIRE_GO_GRAPH"):
        pytest.skip("set ODINEYES_REQUIRE_GO_GRAPH=1 to require the Go engine")
    assert _binary(), "ODINEYES_REQUIRE_GO_GRAPH is set but the Go engine is not built"


def _asset(asset_type, resource_id, properties=None, **kwargs) -> NormalizedAsset:
    return NormalizedAsset(
        resource_id=resource_id, cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type=asset_type, properties=properties or {}, **kwargs,
    )


def _public_instance(name="i-web", role_name="app-role"):
    """An EC2 instance with a wide-open group but no proven network path.

    Deliberately *not* the exposure fixture: is_public on an EC2 is a
    configuration flag, and both engines require route-table/IGW/NACL evidence
    before it becomes an attacker edge. Kept so the parity tests cover the case
    where that evidence is absent.
    """
    return _asset(
        "aws.ec2.instance", f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/{name}",
        {"iam_instance_profile": f"arn:aws:iam::{ACCOUNT}:instance-profile/{role_name}",
         "vpc_id": "vpc-1", "subnet_id": "subnet-a"},
        name=name, is_public=True,
        relationships=[{"type": "USES_SECURITY_GROUP", "target_id": "sg-open"}],
    )


def _public_lambda(name="public-fn", role_name="app-role"):
    """A Lambda with a function URL. Unlike EC2 this is a service endpoint whose
    path does not depend on customer VPC routing, so is_public *is* the proof."""
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/{role_name}"
    return _asset(
        "aws.lambda.function", f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{name}",
        {"url_config": {"AuthType": "NONE"}},
        name=name, is_public=True,
        relationships=[{"type": "EXECUTES_AS", "target_id": role_arn}],
    )


def _open_sg():
    return _asset(
        "aws.ec2.security_group", f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/sg-open",
        {"open_ports": [22], "open_port_labels": ["SSH"],
         "world_open_ingress": [{"cidr": "0.0.0.0/0", "protocol": "tcp",
                                 "from_port": 22, "to_port": 22}]},
        name="sg-open",
    )


def _admin_role(name="app-role"):
    return _asset(
        "aws.iam.role", f"arn:aws:iam::{ACCOUNT}:role/{name}",
        {"has_admin": True, "admin_reason": "AdministratorAccess",
         "policy_analysis_complete": True,
         "trust_principals": [f"arn:aws:iam::{ACCOUNT}:root"]},
        name=name,
    )


def _bucket(name, **kwargs):
    return _asset("aws.s3.bucket", f"arn:aws:s3:::{name}", {}, name=name, **kwargs)


def _both(assets, **kwargs):
    """Run both engines over the same assets and return (python, go)."""
    python_issues = analyze_python(assets, **kwargs)
    snapshot = graph_engine.build_snapshot(assets, now=NOW, **kwargs)
    result = graph_engine.run_go_engine(snapshot)
    go_issues = [graph_engine._issue_from_dict(item) for item in result["issues"]]
    return python_issues, go_issues


def _assert_parity(assets, **kwargs):
    python_issues, go_issues = _both(assets, **kwargs)
    report = graph_engine.compare(python_issues, go_issues)
    assert report["match"], (
        f"engines disagree\n  only python: {report['only_python']}\n"
        f"  only go: {report['only_go']}"
    )
    return python_issues, go_issues


# ── the detectors, one fixture each ────────────────────────────

def test_public_compute_to_admin_parity(go_binary):
    python_issues, _ = _assert_parity(
        [_public_lambda(), _admin_role()])
    assert any(i.issue_type == "PUBLIC_COMPUTE_TO_ADMIN" for i in python_issues)


def test_unproven_ec2_exposure_stays_unproven_in_both(go_binary):
    """is_public on an EC2 with no routing evidence must not become a path in
    either engine. This is the failure mode that would make the Go port look
    'better' by inventing findings."""
    python_issues, go_issues = _both([_open_sg(), _public_instance(), _admin_role()])
    assert not any(i.issue_type == "PUBLIC_COMPUTE_TO_ADMIN" for i in python_issues)
    assert not any(i.issue_type == "PUBLIC_COMPUTE_TO_ADMIN" for i in go_issues)


def test_public_bucket_exposure_parity(go_binary):
    python_issues, _ = _assert_parity([
        _bucket("customer-data-prod", is_public=True, encryption_enabled=False),
        _bucket("scratch", is_public=True, encryption_enabled=True),
    ])
    kinds = {i.issue_type for i in python_issues}
    assert kinds == {"PUBLIC_S3_EXPOSURE"}
    # The sensitive-name path must outrank the generic one in both engines.
    scores = {i.resource_id: i.risk_score for i in python_issues}
    assert scores["arn:aws:s3:::customer-data-prod"] > scores["arn:aws:s3:::scratch"]


def test_dspm_classification_controls_critical_promotion_in_both_engines(go_binary):
    classified = _bucket("opaque-store", is_public=True, encryption_enabled=True)
    unclassified = _bucket("customer-prod-secrets", is_public=True, encryption_enabled=True)
    labels = {"opaque-store": "CRITICAL"}

    python_issues, go_issues = _assert_parity(
        [classified, unclassified], data_labels=labels,
    )
    for issues in (python_issues, go_issues):
        by_resource = {issue.resource_id: issue for issue in issues}
        assert by_resource[classified.resource_id].severity == "critical"
        assert by_resource[unclassified.resource_id].severity == "high"
        assert by_resource[classified.resource_id].evidence_status == "confirmed"
        assert by_resource[classified.resource_id].evidence[0]["observation"] == (
            "sensitivity = CRITICAL"
        )


def test_role_chaining_to_data_parity(go_binary):
    """The bounded role-chain walk is the subtlest port — shared `visited`,
    shortest-path-per-bucket, depth cap. Give it a chain to walk."""
    first = _asset(
        "aws.iam.role", f"arn:aws:iam::{ACCOUNT}:role/app-role",
        {"policy_analysis_complete": True,
         "assume_role_resources": [f"arn:aws:iam::{ACCOUNT}:role/data-role"],
         "trust_principals": [f"arn:aws:iam::{ACCOUNT}:root"]},
        name="app-role",
    )
    second = _asset(
        "aws.iam.role", f"arn:aws:iam::{ACCOUNT}:role/data-role",
        {"policy_analysis_complete": True,
         "s3_read_resources": ["arn:aws:s3:::customer-data-*"],
         "trust_principals": [f"arn:aws:iam::{ACCOUNT}:root"]},
        name="data-role",
    )
    _assert_parity([
        _public_lambda(role_name="app-role"), first, second,
        _bucket("customer-data-prod"),
    ])


def test_cross_account_and_cicd_parity(go_binary):
    wildcard = _asset(
        "aws.iam.role", f"arn:aws:iam::{ACCOUNT}:role/partner",
        {"has_admin": True, "policy_analysis_complete": True,
         "trust_external": True, "publicly_assumable": True,
         "trust_principals": ["*"]},
        name="partner",
    )
    cicd = _asset(
        "aws.iam.role", f"arn:aws:iam::{ACCOUNT}:role/deployer",
        {"policy_analysis_complete": True,
         "privesc_actions": ["iam:PutRolePolicy", "iam:CreateAccessKey"],
         "trust_federated": [
             f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"]},
        name="deployer",
    )
    terraform = _asset(
        "aws.iam.role", f"arn:aws:iam::{ACCOUNT}:role/tfc",
        {"has_admin": True, "policy_analysis_complete": True,
         "trust_federated": [f"arn:aws:iam::{ACCOUNT}:oidc-provider/app.terraform.io"]},
        name="tfc",
    )
    python_issues, _ = _assert_parity([wildcard, cicd, terraform])
    kinds = {i.issue_type for i in python_issues}
    assert "CROSS_ACCOUNT_LATERAL" in kinds
    assert "OVERPRIVILEGED_CICD_ROLE" in kinds


def test_direct_iam_privilege_escalation_parity(go_binary):
    role = _asset(
        "aws.iam.role", f"arn:aws:iam::{ACCOUNT}:role/policy-editor",
        {"policy_analysis_complete": True,
         "privesc_actions": ["iam:PutRolePolicy", "iam:AttachRolePolicy"],
         "trust_principals": [f"arn:aws:iam::{ACCOUNT}:root"]},
        name="policy-editor",
    )
    python_issues, _ = _assert_parity([role])
    assert any(i.issue_type == "IAM_PRIVILEGE_ESCALATION" for i in python_issues)


def test_second_order_lambda_role_escalation_parity(go_binary):
    function_arn = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:payment-worker"
    admin_role_arn = f"arn:aws:iam::{ACCOUNT}:role/payment-admin"
    principal = _asset(
        "aws.iam.user", f"arn:aws:iam::{ACCOUNT}:user/deployer",
        {"policy_analysis_complete": True,
         "effective_access_complete": True,
         "policy_grants": [{
             "effect": "Allow",
             "actions": ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
             "resources": [function_arn],
             "not_actions": [], "not_resources": [], "conditional": False,
         }]},
        name="deployer",
    )
    function = _asset(
        "aws.lambda.function", function_arn, {}, name="payment-worker",
        relationships=[{"type": "EXECUTES_AS", "target_id": admin_role_arn}],
    )
    admin = _asset(
        "aws.iam.role", admin_role_arn,
        {"has_admin": True, "admin_reason": "AdministratorAccess",
         "policy_analysis_complete": True,
         "trust_services": ["lambda.amazonaws.com"]},
        name="payment-admin",
    )
    python_issues, _ = _assert_parity([principal, function, admin])
    assert any(i.issue_type == "SECOND_ORDER_ROLE_ESCALATION" for i in python_issues)


def test_public_database_parity(go_binary):
    """Scoring text is part of the contract: the `scoring` string is rendered
    verbatim in the UI, so a formatting drift is a visible regression."""
    db = _asset(
        "aws.rds.db_instance", f"arn:aws:rds:us-east-1:{ACCOUNT}:db:payments",
        {"publicly_accessible": True, "port": 5432, "engine": "postgres",
         "vpc_id": "vpc-1", "subnet_ids": ["subnet-a"], "security_group_ids": ["sg-open"]},
        name="payments", is_public=True, encryption_enabled=False,
    )
    python_issues, go_issues = _both([_open_sg(), db])
    by_type = {i.issue_type: i for i in python_issues}
    if "PUBLIC_DATABASE_PATH" in by_type:
        go_by_type = {i.issue_type: i for i in go_issues}
        assert by_type["PUBLIC_DATABASE_PATH"].scoring == \
            go_by_type["PUBLIC_DATABASE_PATH"].scoring
    report = graph_engine.compare(python_issues, go_issues)
    assert report["match"], report


def test_environment_tags_rescale_identically(go_binary):
    """envWeight only ever raises the badge, never softens it. A drift here
    silently re-ranks the whole queue."""
    prod = _bucket("prod-data", is_public=True, tags={"Environment": "production"})
    sandbox = _bucket("sbx-data", is_public=True, tags={"Environment": "sandbox"})
    python_issues, go_issues = _assert_parity([prod, sandbox])
    scores = {i.resource_id: i.risk_score for i in python_issues}
    assert scores["arn:aws:s3:::prod-data"] > scores["arn:aws:s3:::sbx-data"]


def test_verified_onboarding_trust_is_suppressed_by_both(go_binary):
    """The one place a real cross-account trust is deliberately muted. If Go
    got this wrong in either direction it would either spam every customer or
    hide a genuine external trust."""
    scanner = "arn:aws:iam::999999999999:role/OdineyesScanner"
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/OdineyesReadOnly"
    role = _asset(
        "aws.iam.role", role_arn,
        {"policy_analysis_complete": True, "trust_external": True,
         "trust_principals": [scanner],
         "trust_statements": [{"principals": [scanner], "external_ids": ["ext-secret"]}]},
        name="OdineyesReadOnly",
    )
    kwargs = {
        "scanner_principal_arn": scanner,
        "account_external_ids": {ACCOUNT: "ext-secret"},
        "account_role_arns": {ACCOUNT: role_arn},
    }
    python_issues, _ = _assert_parity([role], **kwargs)
    assert not any(i.issue_type == "CROSS_ACCOUNT_LATERAL" for i in python_issues)

    # Same role, wrong ExternalId — the suppression must not apply.
    wrong = dict(kwargs, account_external_ids={ACCOUNT: "different"})
    python_issues, _ = _assert_parity([role], **wrong)
    assert any(i.issue_type == "CROSS_ACCOUNT_LATERAL" for i in python_issues)


def test_empty_inventory_parity(go_binary):
    python_issues, go_issues = _both([])
    assert python_issues == [] and go_issues == []


def test_engine_falls_back_to_python_when_the_binary_is_missing(monkeypatch):
    """A broken subprocess must never look like a clean security result."""
    monkeypatch.setenv(graph_engine.ENV_BINARY, "/nonexistent/odineyes-graph")
    assets = [_public_lambda(), _admin_role()]
    issues = graph_engine.analyze(assets, engine="go")
    assert any(i.issue_type == "PUBLIC_COMPUTE_TO_ADMIN" for i in issues), \
        "fallback must still return the real finding"
