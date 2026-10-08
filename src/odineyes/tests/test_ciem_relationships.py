"""Second-order CIEM relationship and issue coverage."""

from __future__ import annotations

from odineyes.inventory.ciem_relationships import derive_ciem_relationships
from odineyes.inventory.graph import AssetGraph
from odineyes.inventory.issues import analyze
from odineyes.inventory.normalizers import normalize_iam_role
from odineyes.inventory.schema import NormalizedAsset

ACCOUNT = "123456789012"


def _grant(actions, resources, *, effect="Allow", conditional=False):
    return {
        "effect": effect,
        "actions": [actions] if isinstance(actions, str) else list(actions),
        "not_actions": [],
        "resources": [resources] if isinstance(resources, str) else list(resources),
        "not_resources": [],
        "conditional": conditional,
    }


def _identity(*grants, name="developer", boundary_state="not_configured"):
    return NormalizedAsset(
        resource_id=f"arn:aws:iam::{ACCOUNT}:role/{name}",
        cloud_provider="aws",
        account_identifier=ACCOUNT,
        asset_type="aws.iam.role",
        name=name,
        properties={
            "policy_grants": list(grants),
            "policy_analysis_complete": True,
            "permissions_boundary_state": boundary_state,
            "permissions_boundary_grants": [],
            "authorization_scope": "identity_policies",
            "effective_access_complete": False,
        },
    )


def _target(*, name="admin-runtime", service="lambda.amazonaws.com", admin=True):
    return NormalizedAsset(
        resource_id=f"arn:aws:iam::{ACCOUNT}:role/{name}",
        cloud_provider="aws",
        account_identifier=ACCOUNT,
        asset_type="aws.iam.role",
        name=name,
        properties={
            "has_admin": admin,
            "trust_services": [service],
            "policy_analysis_complete": True,
        },
    )


def _function(role, name="payments"):
    arn = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{name}"
    return NormalizedAsset(
        resource_id=arn,
        cloud_provider="aws",
        account_identifier=ACCOUNT,
        asset_type="aws.lambda.function",
        name=name,
        region="us-east-1",
        properties={"execution_role": role.resource_id},
        relationships=[{"type": "EXECUTES_AS", "target_id": role.resource_id}],
    )


def test_existing_lambda_takeover_maps_principal_function_and_role():
    target = _target()
    function = _function(target)
    principal = _identity(_grant(
        ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
        function.resource_id,
    ))

    relationships = derive_ciem_relationships([principal, function, target])
    assert [(item.relationship_type, item.source_id, item.target_id) for item in relationships] == [
        ("CAN_MODIFY_AND_INVOKE", principal.resource_id, function.resource_id)
    ]

    graph = AssetGraph.build([principal, function, target])
    assert graph.out_edges(principal.resource_id, "CAN_MODIFY_AND_INVOKE")
    issues = [
        issue for issue in analyze([principal, function, target])
        if issue.issue_type == "SECOND_ORDER_ROLE_ESCALATION"
    ]
    assert len(issues) == 1
    assert [hop["kind"] for hop in issues[0].path] == ["role", "compute", "role"]
    assert issues[0].severity == "high"
    assert issues[0].confidence == 0.8


def test_lambda_takeover_requires_update_and_invoke():
    target = _target()
    function = _function(target)
    principal = _identity(_grant("lambda:UpdateFunctionCode", function.resource_id))
    assert derive_ciem_relationships([principal, function, target]) == []


def test_conditional_lambda_grant_fails_closed():
    target = _target()
    function = _function(target)
    principal = _identity(_grant(
        ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
        function.resource_id,
        conditional=True,
    ))
    assert derive_ciem_relationships([principal, function, target]) == []


def test_explicit_deny_cancels_lambda_takeover():
    target = _target()
    function = _function(target)
    principal = _identity(
        _grant(["lambda:UpdateFunctionCode", "lambda:InvokeFunction"], function.resource_id),
        _grant("lambda:InvokeFunction", function.resource_id, effect="Deny"),
    )
    assert derive_ciem_relationships([principal, function, target]) == []


def test_passrole_plus_service_execution_maps_second_order_escalation():
    target = _target()
    principal = _identity(
        _grant("iam:PassRole", target.resource_id),
        _grant(["lambda:CreateFunction", "lambda:InvokeFunction"], "*"),
    )
    relationships = derive_ciem_relationships([principal, target])
    assert len(relationships) == 1
    relation = relationships[0]
    assert relation.relationship_type == "CAN_IMPERSONATE_VIA_SERVICE"
    assert relation.properties["via_service"] == "lambda"

    issue = next(
        item for item in analyze([principal, target])
        if item.issue_type == "SECOND_ORDER_ROLE_ESCALATION"
    )
    assert issue.severity == "high"
    assert "PassRole" in issue.title


def test_passrole_path_requires_compatible_service_trust():
    target = _target(service="ec2.amazonaws.com")
    principal = _identity(
        _grant("iam:PassRole", target.resource_id),
        _grant(["lambda:CreateFunction", "lambda:InvokeFunction"], "*"),
    )
    assert derive_ciem_relationships([principal, target]) == []


def test_unreadable_boundary_fails_closed():
    target = _target()
    principal = _identity(
        _grant("iam:PassRole", target.resource_id),
        _grant(["lambda:CreateFunction", "lambda:InvokeFunction"], "*"),
        boundary_state="denied",
    )
    assert derive_ciem_relationships([principal, target]) == []


def test_role_normalizer_preserves_service_trust_for_relation_engine():
    role = normalize_iam_role({
        "RoleName": "lambda-runtime",
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/lambda-runtime",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": ["lambda.amazonaws.com", "ecs-tasks.amazonaws.com"]},
                "Action": "sts:AssumeRole",
            }],
        },
    }, ACCOUNT)
    assert role.properties["trust_services"] == [
        "ecs-tasks.amazonaws.com", "lambda.amazonaws.com",
    ]
