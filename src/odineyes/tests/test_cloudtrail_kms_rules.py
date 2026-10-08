"""CloudTrail/Config/KMS/CloudWatch Logs — collector normalize + rules, offline.

Each test builds a raw dict as the enriched collector would emit it, normalizes
it, and asserts the rule fires/doesn't fire. No AWS, no mocks of boto3 — the
normalizer is pure, so this is the same shape as test_rules.py.
"""

from __future__ import annotations

from odineyes.inventory.normalizers import (
    normalize_cloudtrail,
    normalize_cloudwatch_log_group,
    normalize_config_recorder,
    normalize_kms_key,
    normalize_s3_bucket,
)
from odineyes.inventory.rules import (
    evaluate,
    rule_cloudtrail_no_cloudwatch,
    rule_cloudtrail_no_log_validation,
    rule_cloudtrail_not_encrypted,
    rule_config_not_enabled,
    rule_kms_key_rotation_disabled,
    rule_log_group_no_retention,
    rule_log_group_not_encrypted,
)

ACCOUNT = "123456789012"


def _good_trail(**overrides) -> dict:
    raw = {
        "Name": "org-trail", "TrailARN": f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/org-trail",
        "HomeRegion": "us-east-1", "IsMultiRegionTrail": True, "IsLogging": True,
        "LogFileValidationEnabled": True, "KmsKeyId": "arn:aws:kms:us-east-1:123:key/abc",
        "S3BucketName": "trail-bucket", "CloudWatchLogsLogGroupArn": "arn:aws:logs:...:log-group:x",
    }
    raw.update(overrides)
    return raw


def trail(**overrides):
    return normalize_cloudtrail(_good_trail(**overrides), ACCOUNT)


def recorder(is_recording: bool):
    raw = {"name": "default", "Region": "us-east-1", "_IsRecording": is_recording,
           "_Evidence": {"recording_status": "observed"},
           "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True}}
    return normalize_config_recorder(raw, ACCOUNT)


def kms_key(manager="CUSTOMER", state="Enabled", rotation_enabled=False, checked=True):
    raw = {"KeyId": "abc-123", "Region": "us-east-1", "KeyManager": manager,
           "KeyState": state, "RotationEnabled": rotation_enabled, "RotationChecked": checked}
    return normalize_kms_key(raw, ACCOUNT)


def log_group(retention=None, kms=None):
    raw = {"logGroupName": "/aws/lambda/f", "Region": "us-east-1",
           "retentionInDays": retention, "kmsKeyId": kms}
    return normalize_cloudwatch_log_group(raw, ACCOUNT)


# ── CloudTrail single-asset rules ──────────────────────────────

def test_trail_missing_log_validation_fires():
    f = rule_cloudtrail_no_log_validation(trail(LogFileValidationEnabled=False))
    assert f is not None and f.severity == "medium"


def test_trail_with_log_validation_clean():
    assert rule_cloudtrail_no_log_validation(trail()) is None


def test_trail_missing_cloudwatch_fires():
    f = rule_cloudtrail_no_cloudwatch(trail(CloudWatchLogsLogGroupArn=None))
    assert f is not None and f.severity == "medium"


def test_trail_unencrypted_fires_high():
    f = rule_cloudtrail_not_encrypted(trail(KmsKeyId=None))
    assert f is not None and f.severity == "high"


def test_trail_encrypted_clean():
    assert rule_cloudtrail_not_encrypted(trail()) is None


def test_cloudtrail_normalizer_preserves_collector_tags():
    normalized = trail(Tags=[
        {"Key": "ManagedBy", "Value": "CSPM-G3"},
        {"Key": "Purpose", "Value": "OdineyesRealtimeCloudTrail"},
    ])
    assert normalized.tags == {
        "ManagedBy": "CSPM-G3",
        "Purpose": "OdineyesRealtimeCloudTrail",
    }


# ── Config ──────────────────────────────────────────────────────

def test_config_not_recording_fires():
    f = rule_config_not_enabled(recorder(is_recording=False))
    assert f is not None and f.rule_id == "CONFIG_NOT_ENABLED"


def test_config_recording_clean():
    assert rule_config_not_enabled(recorder(is_recording=True)) is None


# ── KMS ─────────────────────────────────────────────────────────

def test_customer_key_no_rotation_fires():
    f = rule_kms_key_rotation_disabled(kms_key(rotation_enabled=False))
    assert f is not None and f.severity == "medium"


def test_customer_key_with_rotation_clean():
    assert rule_kms_key_rotation_disabled(kms_key(rotation_enabled=True)) is None


def test_aws_managed_key_never_fires():
    # AWS-managed keys don't support rotation toggling by the customer.
    assert rule_kms_key_rotation_disabled(kms_key(manager="AWS", rotation_enabled=False)) is None


def test_unchecked_rotation_status_does_not_fire():
    # get_key_rotation_status failed (e.g. asymmetric key) — don't report a false positive.
    assert rule_kms_key_rotation_disabled(kms_key(checked=False)) is None


def test_disabled_key_does_not_fire():
    assert rule_kms_key_rotation_disabled(kms_key(state="PendingDeletion")) is None


# ── CloudWatch Logs ────────────────────────────────────────────

def test_log_group_no_retention_fires():
    f = rule_log_group_no_retention(log_group(retention=None))
    assert f is not None and f.severity == "low"


def test_log_group_with_retention_clean():
    assert rule_log_group_no_retention(log_group(retention=365)) is None


def test_log_group_unencrypted_fires():
    f = rule_log_group_not_encrypted(log_group(kms=None))
    assert f is not None and f.severity == "medium"


def test_log_group_encrypted_clean():
    assert rule_log_group_not_encrypted(log_group(kms="arn:aws:kms:...:key/x")) is None


# ── Combination rules (via evaluate) ───────────────────────────

def test_no_multiregion_trail_fires_once_account_wide():
    single_region = trail(Name="t1", TrailARN=f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/t1",
                          IsMultiRegionTrail=False)
    ids = {f.rule_id for f in evaluate([single_region])}
    assert "CLOUDTRAIL_NOT_MULTIREGION" in ids


def test_good_multiregion_trail_no_finding():
    good = trail()
    ids = {f.rule_id for f in evaluate([good])}
    assert "CLOUDTRAIL_NOT_MULTIREGION" not in ids


def test_zero_trails_produces_no_finding():
    # Absence is a coverage gap (coverage.py), not a Finding — no asset to attach it to.
    bucket = normalize_s3_bucket({"Name": "b"}, ACCOUNT)
    ids = {f.rule_id for f in evaluate([bucket])}
    assert "CLOUDTRAIL_NOT_MULTIREGION" not in ids


def test_trail_to_public_bucket_cross_ref_fires():
    t = trail(S3BucketName="trail-bucket")
    pub_bucket = normalize_s3_bucket({
        "Name": "trail-bucket",
        "PolicyStatus": {"IsPublic": True},
    }, ACCOUNT)
    findings = evaluate([t, pub_bucket])
    hits = [f for f in findings if f.rule_id == "CLOUDTRAIL_S3_PUBLIC"]
    assert len(hits) == 1
    assert hits[0].related == [pub_bucket.resource_id]


def test_trail_to_private_bucket_no_finding():
    t = trail(S3BucketName="trail-bucket")
    priv_bucket = normalize_s3_bucket({"Name": "trail-bucket"}, ACCOUNT)
    ids = {f.rule_id for f in evaluate([t, priv_bucket])}
    assert "CLOUDTRAIL_S3_PUBLIC" not in ids
