"""CIEM authorization evidence and permissions-boundary regression tests."""

from __future__ import annotations

from odineyes.inventory.graph import AssetGraph
from odineyes.inventory.iam_analysis import (
    ASSUME_ROLE_ACTIONS,
    analyze_identity_policies,
    boundary_allows,
    identity_allows,
)
from odineyes.inventory.normalizers import normalize_iam_role, normalize_iam_user
from odineyes.inventory.rules import (
    rule_iam_user_direct_policy_attachment,
    rule_identity_privilege_escalation_grant,
    rule_identity_unrestricted_admin_grant,
)

ACCOUNT = "111122223333"


def _entry(document, *, source_type="user_inline", inherited=False, group_name=""):
    return {
        "document": document,
        "source_type": source_type,
        "source_name": "policy",
        "inherited": inherited,
        "group_name": group_name,
    }


def test_conditioned_and_notaction_statements_are_evidence_not_capabilities():
    analysis = analyze_identity_policies([
        _entry({"Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalTag/team": "security"}},
            },
            {
                "Effect": "Allow",
                "NotAction": "billing:*",
                "Resource": "*",
            },
        ]}),
    ])

    assert analysis["assume_role_resources"] == []
    assert analysis["has_admin_grant"] is False
    assert analysis["conditional_statement_count"] == 1
    assert len(analysis["policy_grants"]) == 2


def test_permissions_boundary_restricts_identity_admin_grant():
    identity = {"Statement": [{
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*",
    }]}
    boundary = {"Statement": [{
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::approved/*",
    }]}
    analysis = analyze_identity_policies(
        [_entry(identity)],
        boundary_document=boundary,
        boundary_arn=f"arn:aws:iam::{ACCOUNT}:policy/ReadApproved",
        boundary_state="observed",
    )

    assert analysis["has_admin_grant"] is True
    assert analysis["has_admin"] is False
    assert analysis["boundary_restricts_admin"] is True
    assert boundary_allows(
        "observed",
        analysis["permissions_boundary_grants"],
        ASSUME_ROLE_ACTIONS,
        f"arn:aws:iam::{ACCOUNT}:role/admin",
    ) is False


def test_explicit_identity_deny_overrides_matching_allow():
    target = f"arn:aws:iam::{ACCOUNT}:role/blocked"
    analysis = analyze_identity_policies([
        _entry({"Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": f"arn:aws:iam::{ACCOUNT}:role/*",
            },
            {
                "Effect": "Deny",
                "Action": "sts:AssumeRole",
                "Resource": target,
            },
        ]}),
    ])

    assert target.rsplit("/", 1)[0] + "/*" in analysis["assume_role_resources"]
    assert identity_allows(
        analysis["policy_grants"],
        ASSUME_ROLE_ACTIONS,
        target,
    ) is False


def test_group_inheritance_is_preserved_as_policy_provenance():
    analysis = analyze_identity_policies([
        _entry(
            {"Statement": [{
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": f"arn:aws:iam::{ACCOUNT}:role/app-*",
            }]},
            source_type="group_managed",
            inherited=True,
            group_name="developers",
        ),
    ])

    assert analysis["direct_policy_count"] == 0
    assert analysis["inherited_policy_count"] == 1
    assert analysis["effective_privesc_actions"] == ["iam:PassRole"]
    assert analysis["policy_sources"][0]["group_name"] == "developers"


def test_rules_distinguish_admin_grant_boundary_and_direct_user_policy():
    bounded_admin = normalize_iam_user({
        "UserName": "bounded-admin",
        **analyze_identity_policies(
            [_entry({"Statement": [{
                "Effect": "Allow", "Action": "*", "Resource": "*",
            }]})],
            boundary_document={"Statement": [{
                "Effect": "Allow", "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::approved/*",
            }]},
            boundary_arn=f"arn:aws:iam::{ACCOUNT}:policy/ReadApproved",
            boundary_state="observed",
        ),
    }, ACCOUNT)

    admin_finding = rule_identity_unrestricted_admin_grant(bounded_admin)
    assert admin_finding is not None
    assert admin_finding.severity == "medium"
    assert rule_iam_user_direct_policy_attachment(bounded_admin) is not None
    assert rule_identity_privilege_escalation_grant(bounded_admin) is None


def test_graph_requires_boundary_and_role_trust_for_assume_edge():
    source_arn = f"arn:aws:iam::{ACCOUNT}:user/operator"
    target_arn = f"arn:aws:iam::{ACCOUNT}:role/target"
    identity_policy = {"Statement": [{
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": target_arn,
    }]}
    denying_boundary = {"Statement": [{
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "*",
    }]}
    source = normalize_iam_user({
        "UserName": "operator",
        "Arn": source_arn,
        **analyze_identity_policies(
            [_entry(identity_policy)],
            boundary_document=denying_boundary,
            boundary_arn=f"arn:aws:iam::{ACCOUNT}:policy/NoSTS",
            boundary_state="observed",
        ),
    }, ACCOUNT)
    target = normalize_iam_role({
        "RoleName": "target",
        "Arn": target_arn,
        "AssumeRolePolicyDocument": {"Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": source_arn},
            "Action": "sts:AssumeRole",
        }]},
        "trust_principals": [source_arn],
    }, ACCOUNT)

    denied_graph = AssetGraph.build([source, target])
    assert denied_graph.out_edges(source_arn, "CAN_ASSUME") == []

    permitted_source = normalize_iam_user({
        "UserName": "operator",
        "Arn": source_arn,
        **analyze_identity_policies([_entry(identity_policy)]),
    }, ACCOUNT)
    permitted_graph = AssetGraph.build([permitted_source, target])
    assert [edge.dst for edge in permitted_graph.out_edges(source_arn, "CAN_ASSUME")] == [
        target_arn
    ]
