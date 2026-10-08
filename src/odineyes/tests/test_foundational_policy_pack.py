"""Evidence-aware AWS foundational policy pack.

Every new rule has a positive case and the enrichment-backed rules prove that
missing/denied evidence does not become a false positive.
"""

from __future__ import annotations

from odineyes.inventory.aws_raw_collector import (
    AwsRawCollector,
    _has_unconditional_wildcard_principal,
)
from odineyes.api.inventory_routes import get_builtin_policy_catalog
from odineyes.inventory.normalizers import (
    normalize_cloudtrail,
    normalize_ec2_instance,
    normalize_ec2_subnet,
    normalize_ecs_cluster,
    get_normalizer,
    normalize_kms_key,
    normalize_rds_cluster,
    normalize_rds_instance,
    normalize_rds_proxy,
    normalize_s3_bucket,
    normalize_secret,
)
from odineyes.inventory.rules import (
    COMBINATION_RULES,
    COMPLIANCE,
    SINGLE_ASSET_RULES,
    builtin_policy_catalog,
    evaluate,
    rule_cloudtrail_not_logging,
)

ACCOUNT = "123456789012"


def _ids(*assets) -> set[str]:
    return {finding.rule_id for finding in evaluate(assets)}


def test_builtin_policy_pack_has_71_registered_rules():
    assert len(SINGLE_ASSET_RULES) == 64
    assert len(COMBINATION_RULES) == 6
    assert len(COMPLIANCE) == 71
    catalog = builtin_policy_catalog()
    assert len(catalog) == 71
    assert {item["policy_id"] for item in catalog} == set(COMPLIANCE)
    assert sum(item["evaluation_mode"] == "relationship" for item in catalog) == 6


def test_policy_catalog_api_summary_and_filters():
    all_policies = get_builtin_policy_catalog(None, None, None)
    s3_policies = get_builtin_policy_catalog("s3", None, None)
    relationships = get_builtin_policy_catalog(None, None, "relationship")
    assert all_policies["summary"]["total"] == 71
    assert all_policies["summary"]["resource_policies"] == 65
    assert s3_policies["filtered_total"] == 5
    assert relationships["filtered_total"] == 6


def test_s3_controls_fire_only_with_known_evidence():
    raw = {
        "Name": "evidence-bucket",
        "Encryption": {"enabled": False, "algorithm": None},
        "Versioning": None,
        "LoggingEnabled": False,
        "PublicAccessBlock": {},
        "_Evidence": {
            "encryption": "absent",
            "versioning": "observed",
            "logging": "observed",
            "public_access_block": "absent",
        },
    }
    assert {
        "S3_DEFAULT_ENCRYPTION_DISABLED",
        "S3_VERSIONING_DISABLED",
        "S3_ACCESS_LOGGING_DISABLED",
        "S3_PUBLIC_ACCESS_BLOCK_INCOMPLETE",
    } <= _ids(normalize_s3_bucket(raw, ACCOUNT))

    denied = dict(raw)
    denied["_Evidence"] = {
        "encryption": "denied",
        "versioning": "denied",
        "logging": "denied",
        "public_access_block": "denied",
    }
    assert not _ids(normalize_s3_bucket(denied, ACCOUNT))


def test_compute_and_subnet_hardening_rules():
    instance = normalize_ec2_instance({
        "InstanceId": "i-1",
        "Region": "us-east-1",
        # The instance sits in the subnet under test. Occupancy must not promote
        # the subnet launch default into an active threat; workload reachability
        # is evaluated separately by the graph.
        "SubnetId": "subnet-1",
        "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"},
    }, ACCOUNT)
    subnet = normalize_ec2_subnet({
        "SubnetId": "subnet-1",
        "Region": "us-east-1",
        "MapPublicIpOnLaunch": True,
    }, ACCOUNT)
    ids = _ids(instance, subnet)
    assert "EC2_IMDSV2_NOT_REQUIRED" in ids
    assert "SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED" not in ids
    suppressed = evaluate([instance, subnet], include_suppressed=True)
    subnet_finding = next(
        finding for finding in suppressed
        if finding.rule_id == "SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED"
    )
    assert subnet_finding.suppressed_by == "design"


def test_database_resilience_and_transport_rules():
    cluster = normalize_rds_cluster({
        "DBClusterIdentifier": "cluster-1",
        "Region": "us-east-1",
        "StorageEncrypted": False,
        "DeletionProtection": False,
    }, ACCOUNT)
    instance = normalize_rds_instance({
        "DBInstanceIdentifier": "db-1",
        "Region": "us-east-1",
        "StorageEncrypted": True,
        "BackupRetentionPeriod": 1,
        "DeletionProtection": False,
    }, ACCOUNT)
    proxy = normalize_rds_proxy({
        "DBProxyName": "proxy-1",
        "Region": "us-east-1",
        "RequireTLS": False,
    }, ACCOUNT)
    ids = _ids(cluster, instance, proxy)
    assert {
        "DB_CLUSTER_UNENCRYPTED",
        "DB_CLUSTER_DELETION_PROTECTION_DISABLED",
        "RDS_BACKUP_RETENTION_TOO_SHORT",
        "RDS_DELETION_PROTECTION_DISABLED",
        "RDS_PROXY_TLS_NOT_REQUIRED",
    } <= ids


def test_secret_and_ecs_observability_rules():
    secret = normalize_secret({
        "Name": "db-password",
        "ARN": f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:db-password",
        "RotationEnabled": False,
        "PublicPolicy": True,
        "_Evidence": {"resource_policy": "observed"},
    }, ACCOUNT)
    cluster = normalize_ecs_cluster({
        "clusterName": "app",
        "settings": [{"name": "containerInsights", "value": "disabled"}],
    }, ACCOUNT)
    ids = _ids(secret, cluster)
    assert {"SECRET_ROTATION_DISABLED", "SECRET_PUBLIC_POLICY"} <= ids
    assert "ECS_CONTAINER_INSIGHTS_DISABLED" in ids


def test_container_and_kubernetes_rules_are_specific_to_observed_posture():
    task = get_normalizer("aws.ecs.task_definition")({
        "taskDefinitionArn": f"arn:aws:ecs:us-east-1:{ACCOUNT}:task-definition/api:1",
        "family": "api", "revision": 1, "networkMode": "host",
        "containerDefinitions": [{"name": "api", "linuxParameters": {"privileged": True}}],
    }, ACCOUNT)
    eks = get_normalizer("aws.eks.cluster")({
        "name": "prod", "arn": f"arn:aws:eks:us-east-1:{ACCOUNT}:cluster/prod",
        "resourcesVpcConfig": {"endpointPublicAccess": True, "publicAccessCidrs": ["0.0.0.0/0"]},
        "encryptionConfig": [],
    }, ACCOUNT)
    ecr = get_normalizer("aws.ecr.repository")({
        "repositoryName": "api", "repositoryArn": f"arn:aws:ecr:us-east-1:{ACCOUNT}:repository/api",
        "imageScanningConfiguration": {"scanOnPush": False}, "UnrestrictedRepositoryPolicy": True,
        "LifecyclePolicyPresent": False,
        "_Evidence": {"resource_policy": "observed", "lifecycle_policy": "absent"},
    }, ACCOUNT)
    ids = _ids(task, eks, ecr)
    assert {
        "ECS_TASK_DEFINITION_PRIVILEGED_CONTAINER",
        "ECS_TASK_DEFINITION_HOST_NETWORK",
        "EKS_PUBLIC_ENDPOINT_UNRESTRICTED",
        "EKS_SECRETS_ENCRYPTION_DISABLED",
        "ECR_IMAGE_SCANNING_DISABLED",
        "ECR_UNRESTRICTED_REPOSITORY_POLICY",
        "ECR_LIFECYCLE_POLICY_MISSING",
    } <= ids


def test_public_secret_policy_requires_observed_policy_evidence():
    secret = normalize_secret({
        "Name": "unknown-policy",
        "PublicPolicy": True,
        "_Evidence": {"resource_policy": "denied"},
    }, ACCOUNT)
    assert "SECRET_PUBLIC_POLICY" not in _ids(secret)


def test_cloudtrail_stopped_and_kms_pending_deletion_rules():
    trail = normalize_cloudtrail({
        "Name": "org",
        "IsMultiRegionTrail": True,
        "IsLogging": False,
        "_Evidence": {"logging": "observed"},
    }, ACCOUNT)
    key = normalize_kms_key({
        "KeyId": "key-1",
        "KeyManager": "CUSTOMER",
        "KeyState": "PendingDeletion",
    }, ACCOUNT)
    assert rule_cloudtrail_not_logging(trail) is not None
    assert "KMS_KEY_PENDING_DELETION" in _ids(key)

    unknown_trail = normalize_cloudtrail({
        "Name": "unknown",
        "IsMultiRegionTrail": True,
        "IsLogging": False,
        "_Evidence": {"logging": "denied"},
    }, ACCOUNT)
    assert rule_cloudtrail_not_logging(unknown_trail) is None


def test_conditioned_wildcard_policy_is_not_called_public():
    conditioned = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "secretsmanager:GetSecretValue",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}},
        }]
    }
    public = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "secretsmanager:GetSecretValue",
        }]
    }
    assert _has_unconditional_wildcard_principal(conditioned) is False
    assert _has_unconditional_wildcard_principal(public) is True


def test_describe_subnets_uses_explicit_result_key():
    page = {
        "Warnings": ["not-a-resource"],
        "Subnets": [{"SubnetId": "subnet-1"}],
    }
    assert AwsRawCollector._extract_items(page, "describe_subnets") == [
        {"SubnetId": "subnet-1"}
    ]
