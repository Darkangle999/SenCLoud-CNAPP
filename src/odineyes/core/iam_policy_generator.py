"""Derive the least-privilege IAM policy the collector actually needs, straight
from aws_raw_collector.OPERATIONS — so the onboarding policy can never silently
drift from what the code calls (the exact gap flagged when reviewing the
hand-written policy JSON pasted into the IAM discussion earlier).

Deliberately scoped to the fixed OPERATIONS registry, not the
ODINEYES_SCAN_ALL dynamic sweep (~200 services) — that mode is
exhaustive-discovery/opt-in, not what a least-privilege grant should cover.
"""

from __future__ import annotations

from typing import Any

import boto3

from odineyes.inventory.aws_raw_collector import OPERATIONS

# botocore's client name isn't always the IAM action prefix. These are the
# confirmed mismatches among the services OPERATIONS touches — verified against
# AWS's IAM action reference, not guessed from the client name.
_SERVICE_IAM_PREFIX: dict[str, str] = {
    "elbv2": "elasticloadbalancing",
    # EFS's IAM namespace has never matched its client name.
    "efs": "elasticfilesystem",
    # Neptune/DocumentDB control-plane calls are documented as living under the
    # rds: action namespace (both engines reuse the RDS-compatible API) rather
    # than neptune:/docdb: — flagged in generated output for a human check
    # since this is the one pairing worth a second look before granting.
    "neptune": "rds",
    "docdb": "rds",
}
_VERIFY_PREFIXES = {"neptune", "docdb"}

# A small number of AWS API operation names do not equal the IAM action that
# authorizes them. Keep exceptions explicit and tested: deriving the action
# solely from botocore's method model produced the invalid ``s3:ListBuckets``
# action in an earlier generated onboarding policy.
_IAM_ACTION_OVERRIDES: dict[tuple[str, str], str] = {
    ("s3", "list_buckets"): "s3:ListAllMyBuckets",
    # API Gateway authorizes by HTTP verb over a resource path, not by operation
    # name: every read is apigateway:GET. Deriving "apigateway:GetRestApis" from
    # the method model would produce an action IAM does not recognize.
    ("apigateway", "get_rest_apis"): "apigateway:GET",
}

# Collection paths that cannot live in the flat OPERATIONS registry. Their list
# APIs return identifiers, so AwsRawCollector follows with scoped detail calls.
_SPECIALIZED_COLLECTION_ACTIONS: dict[str, tuple[str, ...]] = {
    "aws.ecs.cluster": (
        "ecs:ListClusters",
        "ecs:DescribeClusters",
    ),
    "aws.ecs.task_definition": (
        "ecs:ListTaskDefinitions",
        "ecs:DescribeTaskDefinition",
        "ecs:ListTagsForResource",
    ),
    "aws.eks.cluster": (
        "eks:ListClusters",
        "eks:DescribeCluster",
    ),
    "aws.sqs.queue": (
        "sqs:ListQueues",
        "sqs:GetQueueAttributes",
    ),
    "aws.dynamodb.table": (
        "dynamodb:ListTables",
        "dynamodb:DescribeTable",
        "dynamodb:DescribeContinuousBackups",
    ),
    "aws.guardduty.detector": (
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
    ),
    "aws.iam.account_settings": (
        "iam:GetAccountSummary",
        "iam:GetAccountPasswordPolicy",
    ),
}

# Region discovery is a real API call during normal scans, even though it does
# not emit an asset. It belongs in the customer role's read-only contract.
_DISCOVERY_ACTIONS = {"ec2:DescribeRegions"}


_client_cache: dict[str, Any] = {}


def _api_op_name(service: str, snake_op: str) -> str:
    """describe_db_clusters -> DescribeDBClusters, from botocore's own service
    model (the exact mapping aws_raw_collector's dynamic sweep already relies
    on) — not a hand-rolled capitalize(), which gets AWS's inconsistent
    acronym casing wrong (DescribeDBClusters vs DescribeVpcs: DB stays fully
    capitalized, Vpc doesn't). No credentials or network needed; client
    construction only reads the local botocore JSON model."""
    if service not in _client_cache:
        _client_cache[service] = boto3.client(service, region_name="us-east-1")
    return _client_cache[service].meta.method_to_api_mapping.get(snake_op, snake_op)


# service -> read-only API calls the enrichment hooks make beyond the base
# OPERATIONS entry. Hand-maintained (small, fixed set) rather than introspected
# from the hook bodies — mirrors REMEDIATION_CLI's hand-maintained-alongside-
# registry pattern elsewhere in this codebase.
_ENRICHMENT_ACTIONS: dict[str, list[str]] = {
    "aws.s3.bucket": [
        "s3:GetBucketPolicyStatus", "s3:GetBucketAcl", "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning", "s3:GetBucketPolicy", "s3:GetBucketTagging",
        "s3:GetBucketLocation", "s3:GetBucketLogging",
    ],
    "aws.iam.role": ["iam:ListAttachedRolePolicies", "iam:GetPolicy", "iam:GetPolicyVersion",
                     "iam:ListRolePolicies", "iam:GetRolePolicy",
                     "iam:GetRole"],  # RoleLastUsed for dormancy
    "aws.iam.user": ["iam:ListAttachedUserPolicies", "iam:GetPolicy", "iam:GetPolicyVersion",
                     "iam:ListUserPolicies", "iam:GetUserPolicy",
                     "iam:ListGroupsForUser", "iam:ListAttachedGroupPolicies",
                     "iam:ListGroupPolicies", "iam:GetGroupPolicy",
                     "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed",
                     "iam:GetLoginProfile", "iam:ListMFADevices"],
    "aws.lambda.function": ["lambda:GetFunctionUrlConfig", "lambda:GetPolicy"],
    "aws.secretsmanager.secret": ["secretsmanager:GetResourcePolicy"],
    "aws.cloudtrail.trail": ["cloudtrail:GetTrailStatus"],
    "aws.config.recorder": ["config:DescribeConfigurationRecorderStatus"],
    "aws.kms.key": ["kms:DescribeKey", "kms:GetKeyRotationStatus"],
    "aws.ecr.repository": ["ecr:GetRepositoryPolicy", "ecr:GetLifecyclePolicy"],
    "aws.ec2.snapshot": ["ec2:DescribeSnapshotAttribute"],
    "aws.ec2.vpc": ["ec2:DescribeFlowLogs"],
    "aws.efs.file_system": ["elasticfilesystem:DescribeFileSystemPolicy"],
    "aws.sns.topic": ["sns:GetTopicAttributes"],
    # get_stages is authorized by the same verb-based action as get_rest_apis.
    "aws.apigateway.rest_api": ["apigateway:GET"],
}


def _iam_prefix(service: str) -> str:
    return _SERVICE_IAM_PREFIX.get(service, service)


def collection_contract() -> dict[str, list[str]]:
    """Read-only actions grouped by emitted asset source type.

    This is the policy contract for the supported, normalized inventory. It
    intentionally excludes ODINEYES_SCAN_ALL and future sources until they
    have a normalizer, persistence path, tests, and an explainable consumer.
    """
    contract: dict[str, set[str]] = {}
    for service, snake_op, _kwargs, source_type in OPERATIONS:
        action = _IAM_ACTION_OVERRIDES.get(
            (service, snake_op),
            f"{_iam_prefix(service)}:{_api_op_name(service, snake_op)}",
        )
        contract.setdefault(source_type, set()).add(action)
        contract[source_type].update(_ENRICHMENT_ACTIONS.get(source_type, []))
    for source_type, actions in _SPECIALIZED_COLLECTION_ACTIONS.items():
        contract.setdefault(source_type, set()).update(actions)
    return {
        source_type: sorted(actions)
        for source_type, actions in sorted(contract.items())
    }


def required_actions() -> list[str]:
    """Every IAM action the collector calls today, sorted, deduplicated."""
    actions = set(_DISCOVERY_ACTIONS)
    for source_actions in collection_contract().values():
        actions.update(source_actions)
    # STS is needed for the trust handshake itself, always required regardless
    # of OPERATIONS contents.
    actions.add("sts:GetCallerIdentity")
    return sorted(actions)


def flagged_services() -> list[str]:
    """Services whose IAM prefix mapping should get a human second look before
    this policy is granted in a production account."""
    return sorted({s for s, _, _, _ in OPERATIONS if s in _VERIFY_PREFIXES})


def least_privilege_policy() -> dict:
    """A minimal IAM policy document covering exactly what the collector calls.
    ``Resource: "*"`` is unavoidable — Describe/List/Get calls enumerate
    resources whose ARNs aren't known ahead of time, so they can't be scoped
    tighter than the action itself."""
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "OdineyesReadOnly",
            "Effect": "Allow",
            "Action": required_actions(),
            "Resource": "*",
        }],
    }


if __name__ == "__main__":
    # Offline self-check: every OPERATIONS service resolves to an action string,
    # the known-mismatch prefixes apply, and the policy document is well-formed.
    actions = required_actions()
    assert "ec2:DescribeInstances" in actions
    assert "elasticloadbalancing:DescribeLoadBalancers" in actions  # elbv2 -> elasticloadbalancing
    assert "config:DescribeConfigurationRecorders" in actions
    assert "rds:DescribeDBClusters" in actions                      # correct case: DB stays fully capitalized
    assert "s3:GetBucketPolicyStatus" in actions                    # enrichment action present
    assert "iam:ListUsers" in actions                               # IAM user CIEM (base op)
    assert "s3:ListAllMyBuckets" in actions
    assert "ecs:DescribeClusters" in actions
    assert {"ecs:ListTaskDefinitions", "ecs:DescribeTaskDefinition", "eks:ListClusters",
            "eks:DescribeCluster", "ecr:DescribeRepositories", "ecr:GetRepositoryPolicy"} <= set(actions)
    assert {"iam:ListAccessKeys", "iam:GetAccessKeyLastUsed", "iam:ListMFADevices",
            "iam:GetRole"} <= set(actions)                          # user + dormancy enrich
    assert "sts:GetCallerIdentity" in actions
    assert actions == sorted(set(actions)), "must be sorted and deduplicated"

    policy = least_privilege_policy()
    assert policy["Statement"][0]["Resource"] == "*"
    assert set(policy["Statement"][0]["Action"]) == set(actions)

    assert flagged_services() == ["docdb", "neptune"]
    print(f"iam_policy_generator self-check OK: {len(actions)} actions, "
          f"{len(flagged_services())} service(s) flagged for manual verification")
