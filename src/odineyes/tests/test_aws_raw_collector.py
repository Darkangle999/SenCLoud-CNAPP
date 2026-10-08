"""AwsRawCollector shape coverage — offline, no real AWS.

Patches boto3.Session with fakes so the collector's glue (Region injection,
native-dict passthrough, IAM admin/privesc enrichment, S3 per-bucket detail
assembly, source-type tagging) is verified without credentials. End-to-end
collector->normalizer->persist is covered separately by the live scan script.
"""

from __future__ import annotations

import pytest

from odineyes.inventory import aws_raw_collector as mod
from odineyes.inventory.aws_raw_collector import AwsRawCollector


class _Paginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_):
        return iter(self._pages)


class _FakeClient:
    """Minimal client: canned paginators + canned method returns."""

    def __init__(self, paginators=None, methods=None):
        self._paginators = paginators or {}
        self._methods = methods or {}

    def get_paginator(self, op):
        # Unknown ops yield nothing — keeps the fake forward-compatible as the
        # collector grows new service calls without forcing every test to stub them.
        return _Paginator(self._paginators.get(op, []))

    def can_paginate(self, op):
        # Mirror botocore: paginate the ops we stubbed a paginator for; the rest
        # go through the direct-call branch (and unstubbed ones raise -> no rows).
        return op in self._paginators

    def __getattr__(self, name):
        if name in self._methods:
            val = self._methods[name]
            return (lambda *a, **k: val(*a, **k)) if callable(val) else (lambda *a, **k: val)
        raise AttributeError(name)


class _FakeSession:
    def __init__(self, clients):
        self._clients = clients

    def client(self, name, **_):
        # Unmapped services get an empty client (no paginators, no methods), so
        # newly-collected resource types default to "nothing here" under test.
        return self._clients.get(name, _FakeClient())

    def get_available_services(self):
        # The collector filters OPERATIONS against this; expose every service the
        # registry and specialized paths reference (+ sts) so collection runs
        # under test without a real botocore service-model installation.
        return [s for s, *_ in mod.OPERATIONS] + ["ecs", "eks", "sts"]


@pytest.fixture()
def collector(monkeypatch):
    sts = _FakeClient(methods={"get_caller_identity": {"Account": "111122223333"}})

    ec2 = _FakeClient(paginators={
        "describe_instances": [{"Reservations": [
            {"Instances": [{"InstanceId": "i-1", "PublicIpAddress": "1.2.3.4"}]}]}],
        "describe_security_groups": [{"SecurityGroups": [
            {"GroupId": "sg-1", "GroupName": "web",
             "IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]}],
        "describe_network_interfaces": [{"NetworkInterfaces": [{
            "NetworkInterfaceId": "eni-1", "VpcId": "vpc-1", "SubnetId": "subnet-1",
            "Status": "in-use",
        }]}],
    })

    s3 = _FakeClient(methods={
        "list_buckets": {"Buckets": [{"Name": "b1", "CreationDate": None}]},
        "get_bucket_location": {"LocationConstraint": "eu-west-1"},
        "get_public_access_block": {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}},
        "get_bucket_policy_status": {"PolicyStatus": {"IsPublic": False}},
        "get_bucket_acl": {"Grants": []},
        "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}},
        "get_bucket_versioning": {"Status": "Enabled"},
        "get_bucket_logging": {"LoggingEnabled": {"TargetBucket": "audit-logs"}},
        "get_bucket_policy": {"Policy": "{}"},
        "get_bucket_tagging": {"TagSet": [{"Key": "env", "Value": "lab"}]},
    })

    iam = _FakeClient(
        paginators={"list_roles": [{"Roles": [
            {"RoleName": "admin-role", "Arn": "arn:aws:iam::111122223333:role/admin-role", "Path": "/"},
            {"RoleName": "svc", "Arn": "arn", "Path": "/aws-service-role/x"},  # skipped
        ]}]},
        methods={
            "list_attached_role_policies": {"AttachedPolicies": [
                {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:p"}]},
            "get_policy": {"Policy": {"DefaultVersionId": "v1"}},
            "get_policy_version": {"PolicyVersion": {"Document": {
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}},
            "list_role_policies": {"PolicyNames": []},
        },
    )

    rds = _FakeClient(paginators={"describe_db_instances": [{"DBInstances": [
        {"DBInstanceIdentifier": "db1", "PubliclyAccessible": True, "StorageEncrypted": False}]}]})

    ecs = _FakeClient(
        paginators={
            "list_clusters": [{"clusterArns": ["arn:aws:ecs:us-east-1:111122223333:cluster/app"]}],
            "list_task_definitions": [{"taskDefinitionArns": [
                "arn:aws:ecs:us-east-1:111122223333:task-definition/app:3"
            ]}],
        },
        methods={"describe_clusters": {"clusters": [{
            "clusterArn": "arn:aws:ecs:us-east-1:111122223333:cluster/app",
            "clusterName": "app",
            "settings": [{"name": "containerInsights", "value": "enabled"}],
            "tags": [{"key": "environment", "value": "test"}],
        }], "failures": []}, "describe_task_definition": {
            "taskDefinition": {
                "taskDefinitionArn": "arn:aws:ecs:us-east-1:111122223333:task-definition/app:3",
                "family": "app", "revision": 3, "networkMode": "awsvpc",
                "containerDefinitions": [{"name": "web", "readonlyRootFilesystem": True}],
            },
        }, "list_tags_for_resource": {"tags": [{"key": "environment", "value": "test"}]}},
    )

    eks = _FakeClient(
        paginators={"list_clusters": [{"clusters": ["platform"]}]},
        methods={"describe_cluster": {"cluster": {
            "name": "platform", "arn": "arn:aws:eks:us-east-1:111122223333:cluster/platform",
            "resourcesVpcConfig": {"endpointPublicAccess": True, "endpointPrivateAccess": True,
                                   "publicAccessCidrs": ["10.0.0.0/8"]},
            "encryptionConfig": [{"resources": ["secrets"]}],
        }}},
    )
    ecr = _FakeClient(
        paginators={"describe_repositories": [{"repositories": [{
            "repositoryName": "app", "repositoryArn": "arn:aws:ecr:us-east-1:111122223333:repository/app",
            "imageScanningConfiguration": {"scanOnPush": True},
            "imageTagMutability": "IMMUTABLE", "encryptionConfiguration": {"encryptionType": "AES256"},
        }]}]},
        methods={"get_repository_policy": {"policyText": "{}"},
                 "get_lifecycle_policy": {"lifecyclePolicyText": "{}"}},
    )

    fake_session = _FakeSession({
        "ec2": ec2, "ecs": ecs, "eks": eks, "ecr": ecr, "iam": iam, "rds": rds, "s3": s3, "sts": sts,
    })
    monkeypatch.setattr(mod.boto3, "Session", lambda **_: fake_session)
    return AwsRawCollector(region="us-east-1")


def test_account_id(collector):
    assert collector.account_id() == "111122223333"


def test_collect_tags_and_counts(collector):
    resources = collector.collect()
    by_type = {}
    for t, _ in resources:
        by_type[t] = by_type.get(t, 0) + 1
    assert by_type == {
        "aws.ec2.instance": 1,
        "aws.ec2.security_group": 1,
        "aws.ec2.network_interface": 1,
        "aws.s3.bucket": 1,
        "aws.iam.role": 1,   # service-linked role skipped
        "aws.rds.db_instance": 1,
        "aws.ecs.cluster": 1,
        "aws.ecs.task_definition": 1,
        "aws.eks.cluster": 1,
        "aws.ecr.repository": 1,
    }


def test_region_injected(collector):
    raws = {t: r for t, r in collector.collect()}
    assert raws["aws.ec2.instance"]["Region"] == "us-east-1"
    assert raws["aws.ec2.security_group"]["Region"] == "us-east-1"
    assert raws["aws.ec2.network_interface"]["Region"] == "us-east-1"
    assert raws["aws.rds.db_instance"]["Region"] == "us-east-1"


def test_terminated_instances_skipped(monkeypatch):
    """describe_instances returns terminated boxes for ~1h post-termination;
    they are dead, not inventory, and must not surface as live assets."""
    ec2 = _FakeClient(paginators={"describe_instances": [{"Reservations": [{"Instances": [
        {"InstanceId": "i-live", "State": {"Name": "running"}, "PublicIpAddress": "1.2.3.4"},
        {"InstanceId": "i-dead", "State": {"Name": "terminated"}},
        {"InstanceId": "i-dying", "State": {"Name": "shutting-down"}},
    ]}]}]})
    sess = _FakeSession({"ec2": ec2, "sts": _FakeClient(
        methods={"get_caller_identity": {"Account": "111122223333"}})})
    monkeypatch.setattr(mod.boto3, "Session", lambda **_: sess)
    raws = [r for t, r in AwsRawCollector(region="us-east-1").collect() if t == "aws.ec2.instance"]
    assert [r["InstanceId"] for r in raws] == ["i-live"]


def test_s3_detail_assembled(collector):
    raws = {t: r for t, r in collector.collect()}
    b = raws["aws.s3.bucket"]
    assert b["Region"] == "eu-west-1"
    assert b["Encryption"] == {"enabled": True, "algorithm": "AES256"}
    assert b["Versioning"] == "Enabled"
    assert b["LoggingEnabled"] is True
    assert b["Policy"] is True
    assert b["_Evidence"]["encryption"] == "observed"


def test_iam_role_enriched_with_admin(collector):
    raws = {t: r for t, r in collector.collect()}
    role = raws["aws.iam.role"]
    assert role["RoleName"] == "admin-role"
    assert role["has_admin"] is True
    assert "managed policy AdministratorAccess" in role["admin_reason"]
    assert role["assume_role_resources"] == ["*"]
    assert role["s3_read_resources"] == ["*"]
    assert role["policy_analysis_complete"] is True


def test_iam_user_inherits_group_policy_with_provenance(collector):
    account = "111122223333"
    policy_arn = f"arn:aws:iam::{account}:policy/DevelopersAssumeApp"
    iam = _FakeClient(methods={
        "list_attached_user_policies": {"AttachedPolicies": []},
        "list_user_policies": {"PolicyNames": []},
        "list_groups_for_user": {"Groups": [{
            "GroupName": "developers",
            "Arn": f"arn:aws:iam::{account}:group/developers",
        }]},
        "list_attached_group_policies": {"AttachedPolicies": [{
            "PolicyName": "DevelopersAssumeApp",
            "PolicyArn": policy_arn,
        }]},
        "list_group_policies": {"PolicyNames": []},
        "get_policy": {"Policy": {"DefaultVersionId": "v1"}},
        "get_policy_version": {"PolicyVersion": {"Document": {"Statement": [{
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": f"arn:aws:iam::{account}:role/app-*",
        }]}}},
        "list_access_keys": {"AccessKeyMetadata": []},
        "get_login_profile": {},
        "list_mfa_devices": {"MFADevices": []},
    })
    user = {
        "UserName": "alice",
        "Arn": f"arn:aws:iam::{account}:user/alice",
    }

    collector._enrich_iam_user(user, iam)

    assert user["group_names"] == ["developers"]
    assert user["direct_policy_count"] == 0
    assert user["inherited_policy_count"] == 1
    assert user["assume_role_resources"] == [f"arn:aws:iam::{account}:role/app-*"]
    assert user["policy_sources"][0]["source_type"] == "group_managed"


def test_ecs_identifier_list_is_enriched_into_cluster_document(collector):
    resources = {source_type: raw for source_type, raw in collector.collect()}
    cluster = resources["aws.ecs.cluster"]
    assert cluster["clusterName"] == "app"
    assert cluster["Region"] == "us-east-1"
    assert ("aws.ecs.cluster", "us-east-1") in collector.authoritative_scopes


def test_container_and_kubernetes_identifier_lists_are_described(collector):
    resources = {source_type: raw for source_type, raw in collector.collect()}
    task = resources["aws.ecs.task_definition"]
    eks = resources["aws.eks.cluster"]
    ecr = resources["aws.ecr.repository"]
    assert task["family"] == "app" and task["Region"] == "us-east-1"
    assert eks["name"] == "platform" and eks["Region"] == "us-east-1"
    assert ecr["repositoryName"] == "app" and ecr["LifecyclePolicyPresent"] is True
    assert {("aws.ecs.task_definition", "us-east-1"), ("aws.eks.cluster", "us-east-1")} <= collector.authoritative_scopes


def test_service_linked_role_skipped(collector):
    roles = [r for t, r in collector.collect() if t == "aws.iam.role"]
    assert all(r["RoleName"] != "svc" for r in roles)


def test_multi_region_fans_out_regional_runs_global_once(monkeypatch):
    """Regional ops (EC2) run once per discovered region and carry that region;
    global ops (S3/IAM) run exactly once regardless of region count."""
    ec2 = _FakeClient(
        paginators={"describe_instances": [{"Reservations": [
            {"Instances": [{"InstanceId": "i-1", "State": {"Name": "running"}}]}]}]},
        methods={"describe_regions": {"Regions": [
            {"RegionName": "us-east-1"}, {"RegionName": "eu-west-1"}, {"RegionName": "ap-south-1"}]}},
    )
    s3 = _FakeClient(methods={
        "list_buckets": {"Buckets": [{"Name": "b1"}]},
        "get_bucket_location": {"LocationConstraint": "eu-west-1"},
        "get_public_access_block": {"PublicAccessBlockConfiguration": {}},
        "get_bucket_policy_status": {"PolicyStatus": {}},
        "get_bucket_acl": {"Grants": []},
        "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {"Rules": []}},
        "get_bucket_versioning": {},
        "get_bucket_logging": {},
        "get_bucket_policy": {"Policy": ""},
        "get_bucket_tagging": {"TagSet": []},
    })
    iam = _FakeClient(paginators={"list_roles": [{"Roles": [
        {"RoleName": "r", "Arn": "arn:aws:iam::1:role/r", "Path": "/"}]}]},
        methods={"list_attached_role_policies": {"AttachedPolicies": []},
                 "list_role_policies": {"PolicyNames": []}})
    sess = _FakeSession({"ec2": ec2, "s3": s3, "iam": iam,
                         "sts": _FakeClient(methods={"get_caller_identity": {"Account": "1"}})})
    monkeypatch.setattr(mod.boto3, "Session", lambda **_: sess)

    res = AwsRawCollector(region="us-east-1").collect()
    # Regional EC2 op ran once per discovered region (3); the shared fake mutates
    # one dict so labels collapse — count is the fan-out invariant that holds.
    assert sum(1 for t, _ in res if t == "aws.ec2.instance") == 3
    assert sum(1 for t, _ in res if t == "aws.iam.role") == 1       # global, once
    assert sum(1 for t, _ in res if t == "aws.s3.bucket") == 1      # global, once


def test_explicit_regions_override_discovery(monkeypatch):
    """An explicit `regions=` list skips discovery entirely."""
    ec2 = _FakeClient(
        paginators={"describe_instances": [{"Reservations": [
            {"Instances": [{"InstanceId": "i-1", "State": {"Name": "running"}}]}]}]},
        methods={"describe_regions": {"Regions": [{"RegionName": "us-east-1"}]}},  # ignored
    )
    sess = _FakeSession({"ec2": ec2,
                         "sts": _FakeClient(methods={"get_caller_identity": {"Account": "1"}})})
    monkeypatch.setattr(mod.boto3, "Session", lambda **_: sess)

    res = AwsRawCollector(region="us-east-1", regions=["eu-west-1", "eu-central-1"]).collect()
    # Two explicit regions → op ran twice (discovery would have given one).
    assert sum(1 for t, _ in res if t == "aws.ec2.instance") == 2
