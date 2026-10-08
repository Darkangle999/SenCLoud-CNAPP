"""Least-privilege policy derivation — offline, no AWS. Guards the exact class
of bug the generator itself caught during development: a service name in
OPERATIONS that isn't a real botocore client silently disappears from every
scan (see aws_raw_collector's strengthened self-check), and a hand-rolled
snake_case-to-PascalCase guess gets AWS's inconsistent acronym casing wrong
(DescribeDBClusters vs DescribeVpcs).
"""

from __future__ import annotations

from odineyes.core.iam_policy_generator import (
    collection_contract,
    flagged_services,
    least_privilege_policy,
    required_actions,
)


def test_actions_are_sorted_and_deduplicated():
    actions = required_actions()
    assert actions == sorted(set(actions))


def test_known_actions_present_with_correct_casing():
    actions = set(required_actions())
    assert "ec2:DescribeInstances" in actions
    assert "ec2:DescribeNetworkInterfaces" in actions
    assert "s3:ListAllMyBuckets" in actions
    assert "s3:ListBuckets" not in actions
    assert "iam:ListRoles" in actions
    # AWS's real casing keeps DB fully capitalized — a naive .capitalize()
    # per snake-case word produces "DescribeDbClusters" instead.
    assert "rds:DescribeDBClusters" in actions
    assert "rds:DescribeDbClusters" not in actions


def test_elbv2_client_maps_to_elasticloadbalancing_prefix():
    actions = required_actions()
    assert "elasticloadbalancing:DescribeLoadBalancers" in actions
    assert not any(a.startswith("elbv2:") for a in actions)


def test_config_client_name_matches_iam_prefix():
    # Both the botocore client and the IAM action prefix are "config" — no
    # override needed (the earlier "configservice" name was simply wrong).
    actions = required_actions()
    assert "config:DescribeConfigurationRecorders" in actions
    assert not any(a.startswith("configservice:") for a in actions)


def test_enrichment_actions_included():
    actions = set(required_actions())
    assert "s3:GetBucketPolicyStatus" in actions
    assert "s3:GetBucketLogging" in actions
    assert "iam:GetPolicyVersion" in actions
    assert "iam:ListGroupsForUser" in actions
    assert "iam:ListAttachedGroupPolicies" in actions
    assert "iam:GetGroupPolicy" in actions
    assert "kms:GetKeyRotationStatus" in actions
    assert "cloudtrail:GetTrailStatus" in actions


def test_collection_contract_covers_identifier_then_detail_collection():
    contract = collection_contract()
    assert set(contract["aws.ecs.cluster"]) == {
        "ecs:DescribeClusters",
        "ecs:ListClusters",
    }
    assert set(contract["aws.ecs.task_definition"]) == {
        "ecs:DescribeTaskDefinition", "ecs:ListTagsForResource", "ecs:ListTaskDefinitions",
    }
    assert set(contract["aws.eks.cluster"]) == {"eks:DescribeCluster", "eks:ListClusters"}
    assert {"ecr:DescribeRepositories", "ecr:GetRepositoryPolicy", "ecr:GetLifecyclePolicy"} <= set(
        contract["aws.ecr.repository"]
    )
    assert "ec2:DescribeRegions" in required_actions()


def test_sts_always_required():
    assert "sts:GetCallerIdentity" in required_actions()


def test_neptune_docdb_flagged_for_manual_verification():
    assert set(flagged_services()) == {"neptune", "docdb"}


def test_policy_document_shape():
    policy = least_privilege_policy()
    assert policy["Version"] == "2012-10-17"
    stmt = policy["Statement"][0]
    assert stmt["Effect"] == "Allow"
    assert stmt["Resource"] == "*"
    assert set(stmt["Action"]) == set(required_actions())


def test_policy_grants_no_write_actions():
    # Every action must be a read-only verb — this policy gets pasted into a
    # client's AWS account, so a Put/Delete/Create slipping in here is a
    # different severity of bug than a missing Describe.
    write_verbs = ("Put", "Delete", "Create", "Update", "Modify", "Attach", "Detach", "Start", "Stop")
    for action in required_actions():
        verb = action.split(":", 1)[1]
        assert not verb.startswith(write_verbs), f"non-read-only action leaked into policy: {action}"
