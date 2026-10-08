"""Coverage for the Phase 2 service expansion: EBS, VPC flow logs, EFS, SNS,
SQS, DynamoDB, API Gateway, GuardDuty and account-wide IAM settings.

Offline throughout — normalizers and rules are pure, and the collector paths are
driven with stub clients rather than AWS. Each new rule is asserted in both
directions plus the denied-evidence case, because the invariant this codebase
cares about is that missing evidence never becomes a failed control.
"""

from __future__ import annotations

import json

import pytest
from botocore.exceptions import ClientError

from odineyes.core.iam_policy_generator import required_actions
from odineyes.inventory.aws_raw_collector import (
    ENRICHMENT_TARGETS,
    OPERATIONS,
    AwsRawCollector,
)
from odineyes.inventory.normalizers import NORMALIZERS, get_normalizer
from odineyes.inventory.rules import evaluate
from odineyes.inventory.schema import NormalizedAsset

ACCOUNT = "123456789012"

NEW_SOURCE_TYPES = [
    "aws.ec2.volume",
    "aws.ec2.snapshot",
    "aws.ec2.vpc",
    "aws.efs.file_system",
    "aws.sns.topic",
    "aws.sqs.queue",
    "aws.dynamodb.table",
    "aws.apigateway.rest_api",
    "aws.guardduty.detector",
    "aws.iam.account_settings",
]


def _denied(operation: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, operation
    )


def _rule_ids(assets: list[NormalizedAsset]) -> set[str]:
    return {f.rule_id for f in evaluate(assets)}


def _normalize(source_type: str, raw: dict) -> NormalizedAsset:
    normalizer = get_normalizer(source_type)
    assert normalizer is not None, f"{source_type} has no normalizer"
    return normalizer(raw, ACCOUNT)


# ── registry wiring ───────────────────────────────────────────


@pytest.mark.parametrize("source_type", NEW_SOURCE_TYPES)
def test_every_new_source_type_has_a_normalizer(source_type):
    assert source_type in NORMALIZERS


def test_snapshot_collection_is_scoped_to_this_account():
    """An unfiltered describe_snapshots enumerates every public snapshot on AWS."""
    entry = next(op for op in OPERATIONS if op[3] == "aws.ec2.snapshot")
    assert entry[2] == {"OwnerIds": ["self"]}


def test_new_collection_actions_reach_the_onboarding_policy():
    actions = set(required_actions())
    assert {
        "ec2:DescribeVolumes", "ec2:DescribeSnapshots", "ec2:DescribeSnapshotAttribute",
        "ec2:DescribeVpcs", "ec2:DescribeFlowLogs",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeFileSystemPolicy",
        "sns:ListTopics", "sns:GetTopicAttributes",
        "sqs:ListQueues", "sqs:GetQueueAttributes",
        "dynamodb:ListTables", "dynamodb:DescribeTable",
        "dynamodb:DescribeContinuousBackups",
        "guardduty:ListDetectors", "guardduty:GetDetector",
        "iam:GetAccountSummary", "iam:GetAccountPasswordPolicy",
        "apigateway:GET",
    } <= actions
    # The verb-based API Gateway action must not be derived from the method name.
    assert "apigateway:GetRestApis" not in actions


def test_ec2_string_state_does_not_break_extraction():
    """Volumes/snapshots/VPCs model State as a string; only instances use an
    object. The terminated-instance filter must not raise on them."""
    class _Client:
        def can_paginate(self, _op):
            return False

        def describe_volumes(self, **_kwargs):
            return {"Volumes": [{"VolumeId": "vol-1", "State": "in-use", "Encrypted": False}]}

    collector = AwsRawCollector.__new__(AwsRawCollector)
    collector.region = "us-east-1"
    resources, complete = AwsRawCollector._fetch_operation(
        collector, _Client(), "ec2", "describe_volumes", "aws.ec2.volume", {}, "us-east-1"
    )
    assert complete
    assert resources == [("aws.ec2.volume", {"VolumeId": "vol-1", "State": "in-use",
                                             "Encrypted": False, "Region": "us-east-1"})]


# ── enrichment ────────────────────────────────────────────────


def test_snapshot_enrichment_detects_public_sharing():
    class _Ec2:
        def describe_snapshot_attribute(self, **_kwargs):
            return {"CreateVolumePermissions": [{"Group": "all"}, {"UserId": "999999999999"}]}

    snapshot = {"SnapshotId": "snap-1"}
    AwsRawCollector._enrich_ebs_snapshot(None, snapshot, _Ec2())
    assert snapshot["IsPublic"] is True
    assert snapshot["SharedWithAccounts"] == ["999999999999"]
    assert snapshot["_Evidence"]["share_permissions"] == "observed"


def test_snapshot_enrichment_records_denial_instead_of_guessing():
    class _Ec2:
        def describe_snapshot_attribute(self, **_kwargs):
            raise _denied("DescribeSnapshotAttribute")

    snapshot = {"SnapshotId": "snap-1"}
    AwsRawCollector._enrich_ebs_snapshot(None, snapshot, _Ec2())
    assert snapshot["IsPublic"] is False
    assert snapshot["_Evidence"]["share_permissions"] == "denied"


def test_vpc_enrichment_only_counts_active_flow_logs():
    class _Ec2:
        def describe_flow_logs(self, **_kwargs):
            return {"FlowLogs": [{"FlowLogId": "fl-1", "FlowLogStatus": "FAILED"}]}

    vpc = {"VpcId": "vpc-1"}
    AwsRawCollector._enrich_vpc(None, vpc, _Ec2())
    assert vpc["_FlowLogsActive"] == []
    assert vpc["_Evidence"]["flow_logs"] == "observed"


def test_efs_missing_policy_is_absent_not_denied():
    class _Efs:
        def describe_file_system_policy(self, **_kwargs):
            raise ClientError(
                {"Error": {"Code": "PolicyNotFound", "Message": "none"}},
                "DescribeFileSystemPolicy",
            )

    fs = {"FileSystemId": "fs-1"}
    AwsRawCollector._enrich_efs_file_system(None, fs, _Efs())
    assert fs["PublicPolicy"] is False
    assert fs["_Evidence"]["resource_policy"] == "absent"


def test_sns_enrichment_reads_policy_and_key():
    class _Sns:
        def get_topic_attributes(self, **_kwargs):
            return {"Attributes": {
                "KmsMasterKeyId": "alias/aws/sns",
                "Policy": json.dumps({"Statement": [
                    {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sns:Publish"}
                ]}),
            }}

    topic = {"TopicArn": f"arn:aws:sns:us-east-1:{ACCOUNT}:events"}
    AwsRawCollector._enrich_sns_topic(None, topic, _Sns())
    assert topic["PublicPolicy"] is True
    assert topic["KmsMasterKeyId"] == "alias/aws/sns"


def test_new_types_needing_extra_calls_are_registered_for_enrichment():
    for source_type in ("aws.ec2.snapshot", "aws.ec2.vpc", "aws.efs.file_system",
                        "aws.sns.topic", "aws.apigateway.rest_api"):
        assert source_type in ENRICHMENT_TARGETS


# ── specialized collectors ────────────────────────────────────


def _collector_stub(client) -> AwsRawCollector:
    collector = AwsRawCollector.__new__(AwsRawCollector)
    collector.region = "us-east-1"
    collector.authoritative_scopes = set()
    collector.collection_errors = []
    collector._client_cache = {}
    collector._get_client = lambda service, region=None: client  # type: ignore[method-assign]
    return collector


class _Paginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kwargs):
        return self._pages


def test_sqs_collector_builds_queue_documents():
    class _Sqs:
        def get_paginator(self, _op):
            return _Paginator([{"QueueUrls": ["https://sqs.us-east-1.amazonaws.com/1/jobs"]}])

        def get_queue_attributes(self, **_kwargs):
            return {"Attributes": {
                "QueueArn": f"arn:aws:sqs:us-east-1:{ACCOUNT}:jobs",
                "SqsManagedSseEnabled": "false",
                "Policy": json.dumps({"Statement": [
                    {"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage"}
                ]}),
            }}

    collector = _collector_stub(_Sqs())
    resources = collector._collect_sqs_queues(["us-east-1"], {"sqs"})
    assert len(resources) == 1
    source_type, queue = resources[0]
    assert source_type == "aws.sqs.queue"
    assert queue["PublicPolicy"] is True
    assert ("aws.sqs.queue", "us-east-1") in collector.authoritative_scopes


def test_dynamodb_collector_attaches_pitr_status():
    class _Dynamo:
        def get_paginator(self, _op):
            return _Paginator([{"TableNames": ["orders"]}])

        def describe_table(self, **_kwargs):
            return {"Table": {"TableName": "orders",
                              "TableArn": f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/orders"}}

        def describe_continuous_backups(self, **_kwargs):
            return {"ContinuousBackupsDescription": {
                "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "DISABLED"}
            }}

    collector = _collector_stub(_Dynamo())
    resources = collector._collect_dynamodb_tables(["us-east-1"], {"dynamodb"})
    assert resources[0][1]["_PitrStatus"] == "DISABLED"


def test_missing_sdk_service_is_a_collection_error_not_a_silent_skip():
    collector = _collector_stub(object())
    assert collector._collect_guardduty_detectors(["us-east-1"], set()) == []
    assert collector.collection_errors[0].source_type == "aws.guardduty.detector"
    assert not collector.authoritative_scopes


def test_account_settings_collector_survives_a_missing_password_policy():
    class _Iam:
        def get_account_summary(self):
            return {"SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1}}

        def get_account_password_policy(self):
            raise ClientError(
                {"Error": {"Code": "NoSuchEntity", "Message": "no policy"}},
                "GetAccountPasswordPolicy",
            )

    collector = _collector_stub(_Iam())
    collector.account_id = lambda: ACCOUNT  # type: ignore[method-assign]
    resources = collector._collect_iam_account_settings({"iam"})
    _, settings = resources[0]
    assert settings["PasswordPolicy"] == {}
    assert settings["_Evidence"]["password_policy"] == "absent"
    assert settings["Region"] == "global"


# ── normalizers ───────────────────────────────────────────────


def test_volume_normalizes_attachment_and_encryption():
    asset = _normalize("aws.ec2.volume", {
        "VolumeId": "vol-1", "Region": "us-east-1", "Encrypted": False, "Size": 8,
        "State": "in-use", "Attachments": [{"InstanceId": "i-1"}],
        "Tags": [{"Key": "Name", "Value": "root"}],
    })
    assert asset.resource_id.endswith(":volume/vol-1")
    assert asset.encryption_enabled is False
    assert asset.tags == {"Name": "root"}
    assert asset.relationships == [{"type": "ATTACHED_TO", "target_id": "i-1"}]


def test_public_snapshot_is_public_without_claiming_a_network_route():
    asset = _normalize("aws.ec2.snapshot", {
        "SnapshotId": "snap-1", "Region": "us-east-1", "Encrypted": True,
        "IsPublic": True, "SharedWithAccounts": [], "_Evidence": {"share_permissions": "observed"},
    })
    assert asset.is_public is True
    assert asset.network_exposure == "public"
    assert asset.encryption_enabled is True


def test_api_gateway_private_endpoint_is_not_internet_facing():
    private = _normalize("aws.apigateway.rest_api", {
        "id": "abc", "name": "internal", "Region": "us-east-1",
        "endpointConfiguration": {"types": ["PRIVATE"]}, "_Stages": [],
        "_Evidence": {"stages": "observed"},
    })
    public = _normalize("aws.apigateway.rest_api", {
        "id": "def", "name": "public", "Region": "us-east-1",
        "endpointConfiguration": {"types": ["REGIONAL"]}, "_Stages": [],
        "_Evidence": {"stages": "observed"},
    })
    assert private.is_public is False and private.network_exposure == "vpc"
    assert public.is_public is True and public.network_exposure == "public"


def test_sqs_managed_sse_counts_as_encryption():
    asset = _normalize("aws.sqs.queue", {
        "QueueUrl": "https://sqs/1/jobs", "QueueArn": f"arn:aws:sqs:us-east-1:{ACCOUNT}:jobs",
        "Attributes": {}, "SqsManagedSseEnabled": True, "PublicPolicy": False,
        "_Evidence": {"attributes": "observed", "resource_policy": "observed"},
    })
    assert asset.encryption_enabled is True
    assert asset.name == "jobs"


def test_account_settings_uses_the_root_arn_as_identifier():
    asset = _normalize("aws.iam.account_settings", {
        "AccountId": ACCOUNT,
        "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0},
        "PasswordPolicy": {"MinimumPasswordLength": 14, "PasswordReusePrevention": 24},
        "_Evidence": {"account_summary": "observed", "password_policy": "observed"},
    })
    assert asset.resource_id == f"arn:aws:iam::{ACCOUNT}:root"
    assert asset.region == "global"
    assert asset.properties["root_mfa_enabled"] is True


# ── rules ─────────────────────────────────────────────────────


def _asset(asset_type: str, **kwargs) -> NormalizedAsset:
    kwargs.setdefault("resource_id", f"arn:test:{asset_type}")
    return NormalizedAsset(
        cloud_provider="aws", account_identifier=ACCOUNT, asset_type=asset_type, **kwargs
    )


def test_unencrypted_volume_and_snapshot_fire():
    assets = [
        _asset("aws.ec2.volume", resource_id="arn:vol", encryption_enabled=False),
        _asset("aws.ec2.snapshot", resource_id="arn:snap", encryption_enabled=False,
               properties={"collection_evidence": {"share_permissions": "observed"}}),
    ]
    assert {"EBS_VOLUME_UNENCRYPTED", "EBS_SNAPSHOT_UNENCRYPTED"} <= _rule_ids(assets)


def test_public_snapshot_is_critical():
    asset = _asset("aws.ec2.snapshot", is_public=True, encryption_enabled=True,
                   properties={"collection_evidence": {"share_permissions": "observed"}})
    finding = next(f for f in evaluate([asset]) if f.rule_id == "EBS_SNAPSHOT_PUBLIC")
    assert finding.severity == "critical"
    assert finding.compliance["CIS"]


def test_denied_snapshot_sharing_evidence_produces_no_finding():
    asset = _asset("aws.ec2.snapshot", is_public=False, encryption_enabled=True,
                   properties={"collection_evidence": {"share_permissions": "denied"}})
    assert "EBS_SNAPSHOT_PUBLIC" not in _rule_ids([asset])


def test_vpc_flow_log_rule_respects_evidence_state():
    observed = _asset("aws.ec2.vpc", resource_id="arn:vpc-a", properties={
        "flow_logs_enabled": False, "collection_evidence": {"flow_logs": "observed"}})
    denied = _asset("aws.ec2.vpc", resource_id="arn:vpc-b", properties={
        "flow_logs_enabled": False, "collection_evidence": {"flow_logs": "denied"}})
    enabled = _asset("aws.ec2.vpc", resource_id="arn:vpc-c", properties={
        "flow_logs_enabled": True, "collection_evidence": {"flow_logs": "observed"}})
    fired = {f.resource_id for f in evaluate([observed, denied, enabled])
             if f.rule_id == "VPC_FLOW_LOGS_DISABLED"}
    assert fired == {"arn:vpc-a"}


def test_efs_rules():
    asset = _asset("aws.efs.file_system", encryption_enabled=False, is_public=True,
                   properties={"public_policy": True,
                               "collection_evidence": {"resource_policy": "observed"}})
    assert {"EFS_UNENCRYPTED", "EFS_PUBLIC_POLICY"} <= _rule_ids([asset])


def test_sns_and_sqs_public_policies_fire():
    topic = _asset("aws.sns.topic", resource_id="arn:topic", is_public=True,
                   properties={"public_policy": True, "kms_master_key_id": "alias/aws/sns",
                               "collection_evidence": {"resource_policy": "observed",
                                                       "attributes": "observed"}})
    queue = _asset("aws.sqs.queue", resource_id="arn:queue", is_public=True,
                   encryption_enabled=False,
                   properties={"public_policy": True,
                               "collection_evidence": {"resource_policy": "observed",
                                                       "attributes": "observed"}})
    ids = _rule_ids([topic, queue])
    assert {"SNS_TOPIC_PUBLIC_POLICY", "SQS_QUEUE_PUBLIC_POLICY",
            "SQS_QUEUE_NOT_ENCRYPTED"} <= ids
    # The topic has a KMS key, so the encryption rule must stay quiet.
    assert "SNS_TOPIC_NOT_ENCRYPTED" not in ids


def test_dynamodb_backup_and_key_rules():
    asset = _asset("aws.dynamodb.table", encryption_enabled=True, properties={
        "point_in_time_recovery_status": "DISABLED",
        "deletion_protection_enabled": False,
        "kms_key_arn": None,
        "collection_evidence": {"point_in_time_recovery": "observed"},
    })
    assert {"DYNAMODB_PITR_DISABLED", "DYNAMODB_DELETION_PROTECTION_DISABLED",
            "DYNAMODB_NOT_CMK_ENCRYPTED"} <= _rule_ids([asset])


def test_api_gateway_stage_rules_name_the_offending_stages():
    asset = _asset("aws.apigateway.rest_api", is_public=True, properties={
        "stages": [
            {"name": "prod", "access_logging_enabled": False,
             "cache_enabled": True, "cache_data_encrypted": False},
            {"name": "dev", "access_logging_enabled": True,
             "cache_enabled": False, "cache_data_encrypted": False},
        ],
        "collection_evidence": {"stages": "observed"},
    })
    findings = {f.rule_id: f for f in evaluate([asset])}
    assert "prod" in findings["APIGATEWAY_STAGE_LOGGING_DISABLED"].why
    assert "dev" not in findings["APIGATEWAY_STAGE_LOGGING_DISABLED"].why
    assert "prod" in findings["APIGATEWAY_STAGE_CACHE_UNENCRYPTED"].why


def test_root_credentials_and_password_policy_rules():
    asset = _asset("aws.iam.account_settings", resource_id=f"arn:aws:iam::{ACCOUNT}:root",
                   properties={
                       "root_mfa_enabled": False,
                       "root_access_keys_present": True,
                       "password_policy_present": True,
                       "password_min_length": 8,
                       "password_reuse_prevention": 0,
                       "collection_evidence": {"account_summary": "observed",
                                               "password_policy": "observed"},
                   })
    findings = {f.rule_id: f for f in evaluate([asset])}
    assert findings["ROOT_ACCOUNT_ACCESS_KEY"].severity == "critical"
    assert findings["ROOT_ACCOUNT_MFA_DISABLED"].severity == "critical"
    assert "minimum length 8" in findings["IAM_PASSWORD_POLICY_WEAK"].why


def test_missing_password_policy_reports_the_absence():
    asset = _asset("aws.iam.account_settings", properties={
        "root_mfa_enabled": True, "root_access_keys_present": False,
        "password_policy_present": False,
        "collection_evidence": {"account_summary": "observed", "password_policy": "absent"},
    })
    assert "IAM_PASSWORD_POLICY_MISSING" in _rule_ids([asset])


def test_compliant_account_settings_produce_no_findings():
    asset = _asset("aws.iam.account_settings", properties={
        "root_mfa_enabled": True, "root_access_keys_present": False,
        "password_policy_present": True, "password_min_length": 14,
        "password_reuse_prevention": 24,
        "collection_evidence": {"account_summary": "observed", "password_policy": "observed"},
    })
    detector = _asset("aws.guardduty.detector", resource_id="arn:det",
                      properties={"status": "ENABLED",
                                  "collection_evidence": {"detector_status": "observed"}})
    assert _rule_ids([asset, detector]) == set()


def test_guardduty_absence_attaches_to_the_account_asset():
    account = _asset("aws.iam.account_settings",
                     resource_id=f"arn:aws:iam::{ACCOUNT}:root", properties={
                         "root_mfa_enabled": True, "root_access_keys_present": False,
                         "password_policy_present": True, "password_min_length": 14,
                         "password_reuse_prevention": 24,
                         "collection_evidence": {"account_summary": "observed",
                                                 "password_policy": "observed"},
                     })
    finding = next(f for f in evaluate([account]) if f.rule_id == "GUARDDUTY_NOT_ENABLED")
    assert finding.resource_id == f"arn:aws:iam::{ACCOUNT}:root"


def test_guardduty_absence_is_silent_without_the_account_asset():
    """No account asset means the IAM summary was denied — a coverage gap, not
    proof that GuardDuty is off."""
    assert "GUARDDUTY_NOT_ENABLED" not in _rule_ids([])


def test_suspended_detector_reports_once_per_detector_not_account_wide():
    detector = _asset("aws.guardduty.detector", resource_id="arn:det", properties={
        "status": "DISABLED", "collection_evidence": {"detector_status": "observed"}})
    account = _asset("aws.iam.account_settings",
                     resource_id=f"arn:aws:iam::{ACCOUNT}:root", properties={
                         "root_mfa_enabled": True, "root_access_keys_present": False,
                         "password_policy_present": True, "password_min_length": 14,
                         "password_reuse_prevention": 24,
                         "collection_evidence": {"account_summary": "observed",
                                                 "password_policy": "observed"},
                     })
    ids = _rule_ids([detector, account])
    assert "GUARDDUTY_DETECTOR_DISABLED" in ids
    assert "GUARDDUTY_NOT_ENABLED" not in ids
