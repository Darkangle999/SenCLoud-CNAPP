"""Tests for the IaC misconfiguration scanner.

Every rule gets at least one positive-case (should fire) and one negative-case
(should NOT fire) fixture.  Combination checks get multi-resource plan fixtures
that prove both the all-conditions-met path (fires) and the partial-conditions
path (silent).

Run with:  pytest src/odineyes/tests/test_iac_scanner.py -v
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from odineyes.iac.scanner import (
    IacFinding,
    IacResource,
    _check_cloudtrail_no_cloudwatch,
    _check_cloudtrail_no_log_validation,
    _check_cloudtrail_not_encrypted,
    _check_config_not_enabled,
    _check_kms_key_rotation,
    _check_lambda_public_url,
    _check_log_group_no_retention,
    _check_log_group_not_encrypted,
    _check_open_sg,
    _check_public_s3,
    _check_redshift_public,
    _check_unencrypted_storage,
    _check_wildcard_iam,
    _combo_cloudtrail_multiregion,
    _combo_cloudtrail_public_s3,
    _combo_public_ec2_to_admin_role,
    _falsy,
    _truthy,
    parse,
    scan,
)


# ─── helpers ────────────────────────────────────────────────────

def tf(type_: str, name: str = "rsc", **props) -> IacResource:
    """Shorthand for a terraform IacResource with keyword props."""
    return IacResource("terraform", type_, name, dict(props))


def cfn(type_: str, name: str = "Rsc", **props) -> IacResource:
    """Shorthand for a cloudformation IacResource with keyword props."""
    return IacResource("cloudformation", type_, name, dict(props))


def plan_json(**resource_blocks) -> str:
    """Build a minimal raw HCL-as-JSON plan string for scan() tests."""
    return json.dumps({"resource": resource_blocks})


# ─── _truthy / _falsy ───────────────────────────────────────────

class TestHelpers:
    def test_truthy_bool(self):
        assert _truthy(True) is True
        assert _truthy(False) is False

    def test_truthy_strings(self):
        assert _truthy("true") is True
        assert _truthy("1") is True
        assert _truthy("yes") is True
        assert _truthy("false") is False
        assert _truthy("no") is False

    def test_truthy_skips_tf_interpolation(self):
        # Unresolved variable must NOT be treated as truthy or falsy — returns False.
        assert _truthy("${var.acl}") is False
        assert _truthy("var.enable") is False

    def test_falsy_explicit_false(self):
        assert _falsy(False) is True
        assert _falsy("false") is True
        assert _falsy("0") is True

    def test_falsy_skips_tf_interpolation(self):
        assert _falsy("${var.encrypted}") is False


# ─── parse() ────────────────────────────────────────────────────

class TestParse:
    def test_empty_string_returns_empty(self):
        assert parse("") == []

    def test_garbage_returns_empty(self):
        assert parse("not json or yaml at all !!!") == []

    def test_raw_hcl_json(self):
        text = json.dumps({"resource": {"aws_s3_bucket": {"my_bucket": {"acl": "private"}}}})
        resources = parse(text)
        assert len(resources) == 1
        assert resources[0].type == "aws_s3_bucket"
        assert resources[0].name == "my_bucket"
        assert resources[0].props["acl"] == "private"

    def test_cloudformation_json(self):
        text = json.dumps({
            "Resources": {
                "MyBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"AccessControl": "Private"},
                }
            }
        })
        resources = parse(text)
        assert len(resources) == 1
        assert resources[0].type == "AWS::S3::Bucket"
        assert resources[0].name == "MyBucket"
        assert resources[0].fmt == "cloudformation"

    def test_terraform_plan_json_resource_changes(self):
        plan = {
            "resource_changes": [
                {
                    "type": "aws_s3_bucket",
                    "address": "aws_s3_bucket.logs",
                    "change": {"after": {"acl": "private"}},
                }
            ]
        }
        resources = parse(json.dumps(plan))
        assert len(resources) == 1
        assert resources[0].name == "aws_s3_bucket.logs"

    def test_terraform_plan_json_planned_values(self):
        plan = {
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "type": "aws_s3_bucket",
                            "address": "aws_s3_bucket.main",
                            "values": {"acl": "public-read"},
                        }
                    ]
                }
            }
        }
        resources = parse(json.dumps(plan))
        assert len(resources) == 1
        assert resources[0].props["acl"] == "public-read"

    def test_cloudformation_yaml(self):
        yaml_text = """
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
"""
        resources = parse(yaml_text)
        assert len(resources) == 1
        assert resources[0].props["AccessControl"] == "PublicRead"


# ─── _check_public_s3 ───────────────────────────────────────────

class TestPublicS3:
    def test_fires_on_public_read_acl(self):
        r = tf("aws_s3_bucket", acl="public-read")
        f = _check_public_s3(r)
        assert f is not None
        assert f.check_id == "IAC_S3_PUBLIC_ACL"
        assert f.severity == "high"

    def test_fires_on_public_read_write_acl(self):
        r = tf("aws_s3_bucket", acl="public-read-write")
        assert _check_public_s3(r) is not None

    def test_fires_cfn_access_control(self):
        r = cfn("AWS::S3::Bucket", AccessControl="PublicRead")
        assert _check_public_s3(r) is not None

    def test_silent_on_private_acl(self):
        r = tf("aws_s3_bucket", acl="private")
        assert _check_public_s3(r) is None

    def test_silent_on_wrong_resource_type(self):
        r = tf("aws_instance", acl="public-read")
        assert _check_public_s3(r) is None

    def test_silent_on_no_acl(self):
        r = tf("aws_s3_bucket")
        assert _check_public_s3(r) is None


# ─── _check_unencrypted_storage ─────────────────────────────────

class TestUnencryptedStorage:
    def test_s3_fires_when_no_sse(self):
        r = tf("aws_s3_bucket", acl="private")
        f = _check_unencrypted_storage(r)
        assert f is not None
        assert f.check_id == "IAC_S3_NO_ENCRYPTION"
        assert f.severity == "medium"

    def test_s3_silent_when_sse_configured(self):
        r = tf("aws_s3_bucket", server_side_encryption_configuration={"rule": {}})
        assert _check_unencrypted_storage(r) is None

    def test_rds_fires_on_false_encryption(self):
        r = tf("aws_db_instance", storage_encrypted=False)
        f = _check_unencrypted_storage(r)
        assert f is not None
        assert f.check_id == "IAC_RDS_NO_ENCRYPTION"
        assert f.severity == "high"

    def test_rds_silent_when_encrypted_true(self):
        r = tf("aws_db_instance", storage_encrypted=True)
        assert _check_unencrypted_storage(r) is None

    def test_rds_silent_when_prop_absent(self):
        # No prop = unknown — give benefit of the doubt.
        r = tf("aws_db_instance")
        assert _check_unencrypted_storage(r) is None


# ─── _check_open_sg ─────────────────────────────────────────────

class TestOpenSG:
    def _sg(self, from_port=22, to_port=22, cidr_blocks=None, ipv6_cidr_blocks=None, **kw):
        rule = {"from_port": from_port, "to_port": to_port}
        if cidr_blocks is not None:
            rule["cidr_blocks"] = cidr_blocks
        if ipv6_cidr_blocks is not None:
            rule["ipv6_cidr_blocks"] = ipv6_cidr_blocks
        rule.update(kw)
        return tf("aws_security_group", ingress=[rule])

    def test_fires_on_ssh_world_open_ipv4(self):
        r = self._sg(cidr_blocks=["0.0.0.0/0"])
        f = _check_open_sg(r)
        assert f is not None
        assert f.check_id == "IAC_SG_WORLD_OPEN"
        assert f.severity == "critical"

    def test_fires_on_ssh_world_open_ipv6(self):
        """Gap #4 regression: IPv6-only open SG must fire."""
        r = self._sg(ipv6_cidr_blocks=["::/0"])
        f = _check_open_sg(r)
        assert f is not None, "IPv6 world-open SG must fire (was a gap)"
        assert f.check_id == "IAC_SG_WORLD_OPEN"

    def test_fires_on_rdp_world_open(self):
        r = self._sg(from_port=3389, to_port=3389, cidr_blocks=["0.0.0.0/0"])
        assert _check_open_sg(r) is not None

    def test_fires_on_mysql_world_open(self):
        r = self._sg(from_port=3306, to_port=3306, cidr_blocks=["0.0.0.0/0"])
        assert _check_open_sg(r) is not None

    def test_silent_on_restricted_cidr(self):
        r = self._sg(cidr_blocks=["10.0.0.0/8"])
        assert _check_open_sg(r) is None

    def test_silent_on_non_danger_port_world_open(self):
        r = self._sg(from_port=443, to_port=443, cidr_blocks=["0.0.0.0/0"])
        assert _check_open_sg(r) is None

    def test_fires_cfn_security_group_ingress(self):
        r = cfn("AWS::EC2::SecurityGroup", SecurityGroupIngress=[{
            "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0",
        }])
        assert _check_open_sg(r) is not None

    def test_fires_cfn_ipv6_ingress(self):
        """CFN IPv6 path — was missing before gap #4 fix."""
        r = cfn("AWS::EC2::SecurityGroup", SecurityGroupIngress=[{
            "FromPort": 22, "ToPort": 22, "CidrIpv6": "::/0",
        }])
        f = _check_open_sg(r)
        assert f is not None, "CFN IPv6 world-open SG must fire"

    def test_silent_on_wrong_type(self):
        r = tf("aws_instance", ingress=[{"from_port": 22, "to_port": 22,
                                         "cidr_blocks": ["0.0.0.0/0"]}])
        assert _check_open_sg(r) is None


# ─── _check_wildcard_iam ────────────────────────────────────────

class TestWildcardIAM:
    def _policy_doc(self, action="*", resource="*", effect="Allow"):
        return json.dumps({"Statement": [{"Effect": effect, "Action": action, "Resource": resource}]})

    def test_fires_on_star_action_star_resource(self):
        r = tf("aws_iam_policy", policy=self._policy_doc())
        f = _check_wildcard_iam(r)
        assert f is not None
        assert f.check_id == "IAC_IAM_WILDCARD"
        assert f.severity == "high"

    def test_fires_on_service_star(self):
        r = tf("aws_iam_policy", policy=self._policy_doc(action="s3:*"))
        assert _check_wildcard_iam(r) is not None

    def test_silent_on_deny(self):
        r = tf("aws_iam_policy", policy=self._policy_doc(effect="Deny"))
        assert _check_wildcard_iam(r) is None

    def test_silent_on_scoped_resource(self):
        doc = json.dumps({
            "Statement": [{"Effect": "Allow", "Action": "s3:*",
                            "Resource": "arn:aws:s3:::my-bucket/*"}]
        })
        r = tf("aws_iam_policy", policy=doc)
        assert _check_wildcard_iam(r) is None

    def test_fires_cfn_iam_role_with_policies(self):
        r = cfn("AWS::IAM::Role", Policies=[{
            "PolicyName": "admin",
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            },
        }])
        assert _check_wildcard_iam(r) is not None

    def test_silent_on_wrong_resource_type(self):
        r = tf("aws_s3_bucket", policy=self._policy_doc())
        assert _check_wildcard_iam(r) is None


# ─── CloudTrail checks ───────────────────────────────────────────

class TestCloudTrailLogValidation:
    def test_fires_when_disabled(self):
        r = tf("aws_cloudtrail", enable_log_file_validation=False)
        f = _check_cloudtrail_no_log_validation(r)
        assert f is not None
        assert f.check_id == "IAC_CLOUDTRAIL_NO_LOG_VALIDATION"
        assert f.severity == "medium"

    def test_fires_when_absent(self):
        r = tf("aws_cloudtrail", name="trail1")
        assert _check_cloudtrail_no_log_validation(r) is not None

    def test_silent_when_enabled(self):
        r = tf("aws_cloudtrail", enable_log_file_validation=True)
        assert _check_cloudtrail_no_log_validation(r) is None

    def test_silent_on_wrong_type(self):
        r = tf("aws_s3_bucket", enable_log_file_validation=False)
        assert _check_cloudtrail_no_log_validation(r) is None


class TestCloudTrailCloudWatch:
    def test_fires_when_no_cw_arn(self):
        r = tf("aws_cloudtrail")
        f = _check_cloudtrail_no_cloudwatch(r)
        assert f is not None
        assert f.check_id == "IAC_CLOUDTRAIL_NO_CLOUDWATCH"

    def test_silent_when_cw_arn_present(self):
        r = tf("aws_cloudtrail",
               cloud_watch_logs_group_arn="arn:aws:logs:us-east-1:123:log-group:/trail")
        assert _check_cloudtrail_no_cloudwatch(r) is None

    def test_cfn_property_name(self):
        r = cfn("AWS::CloudTrail::Trail",
                CloudWatchLogsLogGroupArn="arn:aws:logs:us-east-1:123:log-group:/trail")
        assert _check_cloudtrail_no_cloudwatch(r) is None


class TestCloudTrailEncryption:
    def test_fires_when_no_kms(self):
        r = tf("aws_cloudtrail")
        f = _check_cloudtrail_not_encrypted(r)
        assert f is not None
        assert f.check_id == "IAC_CLOUDTRAIL_NOT_ENCRYPTED"
        assert f.severity == "high"

    def test_silent_when_kms_set(self):
        r = tf("aws_cloudtrail", kms_key_id="arn:aws:kms:us-east-1:123:key/abc")
        assert _check_cloudtrail_not_encrypted(r) is None

    def test_cfn_kms_key(self):
        r = cfn("AWS::CloudTrail::Trail", KMSKeyId="arn:aws:kms:us-east-1:123:key/abc")
        assert _check_cloudtrail_not_encrypted(r) is None


# ─── Config recorder ────────────────────────────────────────────

class TestConfigNotEnabled:
    def test_fires_when_disabled(self):
        r = tf("aws_config_configuration_recorder_status", is_enabled=False)
        f = _check_config_not_enabled(r)
        assert f is not None
        assert f.check_id == "IAC_CONFIG_NOT_ENABLED"
        assert f.severity == "high"

    def test_fires_when_absent(self):
        r = tf("aws_config_configuration_recorder_status")
        assert _check_config_not_enabled(r) is not None

    def test_silent_when_enabled(self):
        r = tf("aws_config_configuration_recorder_status", is_enabled=True)
        assert _check_config_not_enabled(r) is None

    def test_silent_on_wrong_type(self):
        r = tf("aws_s3_bucket", is_enabled=False)
        assert _check_config_not_enabled(r) is None


# ─── KMS rotation ────────────────────────────────────────────────

class TestKMSRotation:
    def test_fires_when_rotation_false(self):
        r = tf("aws_kms_key", enable_key_rotation=False)
        f = _check_kms_key_rotation(r)
        assert f is not None
        assert f.check_id == "IAC_KMS_KEY_ROTATION_DISABLED"
        assert f.severity == "medium"

    def test_fires_when_rotation_absent(self):
        r = tf("aws_kms_key")
        assert _check_kms_key_rotation(r) is not None

    def test_silent_when_enabled(self):
        r = tf("aws_kms_key", enable_key_rotation=True)
        assert _check_kms_key_rotation(r) is None

    def test_silent_on_asymmetric_key(self):
        r = tf("aws_kms_key", key_usage="SIGN_VERIFY", enable_key_rotation=False)
        assert _check_kms_key_rotation(r) is None

    def test_cfn_property_name(self):
        r = cfn("AWS::KMS::Key", EnableKeyRotation=False)
        assert _check_kms_key_rotation(r) is not None

    def test_silent_on_wrong_type(self):
        r = tf("aws_s3_bucket", enable_key_rotation=False)
        assert _check_kms_key_rotation(r) is None


# ─── CloudWatch LogGroup ─────────────────────────────────────────

class TestLogGroupNoRetention:
    def test_fires_when_no_retention(self):
        r = tf("aws_cloudwatch_log_group", name="/app/logs")
        f = _check_log_group_no_retention(r)
        assert f is not None
        assert f.check_id == "IAC_LOG_GROUP_NO_RETENTION"
        assert f.severity == "low"

    def test_silent_when_retention_set(self):
        r = tf("aws_cloudwatch_log_group", retention_in_days=365)
        assert _check_log_group_no_retention(r) is None

    def test_cfn_property_name(self):
        r = cfn("AWS::Logs::LogGroup", RetentionInDays=90)
        assert _check_log_group_no_retention(r) is None

    def test_cfn_fires_when_absent(self):
        r = cfn("AWS::Logs::LogGroup")
        assert _check_log_group_no_retention(r) is not None


class TestLogGroupNotEncrypted:
    def test_fires_when_no_kms(self):
        r = tf("aws_cloudwatch_log_group", name="/app/logs")
        f = _check_log_group_not_encrypted(r)
        assert f is not None
        assert f.check_id == "IAC_LOG_GROUP_NOT_ENCRYPTED"
        assert f.severity == "medium"

    def test_silent_when_kms_set(self):
        r = tf("aws_cloudwatch_log_group",
               kms_key_id="arn:aws:kms:us-east-1:123:key/abc")
        assert _check_log_group_not_encrypted(r) is None

    def test_cfn_property_name(self):
        r = cfn("AWS::Logs::LogGroup", KmsKeyId="arn:aws:kms:us-east-1:123:key/abc")
        assert _check_log_group_not_encrypted(r) is None

    def test_silent_on_wrong_type(self):
        r = tf("aws_cloudtrail")
        assert _check_log_group_not_encrypted(r) is None


# ─── Lambda public URL ───────────────────────────────────────────

class TestLambdaPublicURL:
    def test_fires_on_none_auth(self):
        r = tf("aws_lambda_function_url", authorization_type="NONE")
        f = _check_lambda_public_url(r)
        assert f is not None
        assert f.check_id == "IAC_PUBLIC_LAMBDA_URL"
        assert f.severity == "high"

    def test_silent_on_iam_auth(self):
        r = tf("aws_lambda_function_url", authorization_type="AWS_IAM")
        assert _check_lambda_public_url(r) is None

    def test_cfn_auth_type(self):
        r = cfn("AWS::Lambda::Url", AuthType="NONE")
        assert _check_lambda_public_url(r) is not None

    def test_cfn_silent_on_iam(self):
        r = cfn("AWS::Lambda::Url", AuthType="AWS_IAM")
        assert _check_lambda_public_url(r) is None

    def test_silent_on_wrong_type(self):
        r = tf("aws_s3_bucket", authorization_type="NONE")
        assert _check_lambda_public_url(r) is None


# ─── Redshift public ─────────────────────────────────────────────

class TestRedshiftPublic:
    def test_fires_public_encrypted(self):
        r = tf("aws_redshift_cluster", publicly_accessible=True, encrypted=True)
        f = _check_redshift_public(r)
        assert f is not None
        assert f.check_id == "IAC_PUBLIC_WAREHOUSE"
        assert f.severity == "high"

    def test_fires_critical_public_unencrypted(self):
        r = tf("aws_redshift_cluster", publicly_accessible=True, encrypted=False)
        f = _check_redshift_public(r)
        assert f is not None
        assert f.severity == "critical"

    def test_silent_when_not_public(self):
        r = tf("aws_redshift_cluster", publicly_accessible=False)
        assert _check_redshift_public(r) is None

    def test_silent_when_prop_absent(self):
        r = tf("aws_redshift_cluster")
        assert _check_redshift_public(r) is None

    def test_cfn_property_name(self):
        r = cfn("AWS::Redshift::Cluster", PubliclyAccessible=True, Encrypted=True)
        assert _check_redshift_public(r) is not None

    def test_silent_on_wrong_type(self):
        r = tf("aws_s3_bucket", publicly_accessible=True)
        assert _check_redshift_public(r) is None


# ─── Combination: public EC2 + admin role ───────────────────────

class TestComboPublicEC2ToAdminRole:
    def _public_ec2(self, profile="my-profile"):
        return tf("aws_instance", "web_server",
                  associate_public_ip_address=True,
                  iam_instance_profile=profile)

    def _admin_role_policy(self):
        doc = json.dumps({
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        })
        return tf("aws_iam_role_policy", "admin_pol", policy=doc)

    def _admin_attachment(self):
        return tf("aws_iam_role_policy_attachment", "admin_attach",
                  policy_arn="arn:aws:iam::aws:policy/AdministratorAccess")

    def test_fires_with_public_ec2_and_wildcard_policy(self):
        resources = [self._public_ec2(), self._admin_role_policy()]
        findings = _combo_public_ec2_to_admin_role(resources)
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "IAC_PUBLIC_COMPUTE_TO_ADMIN"
        assert f.severity == "critical"
        assert "admin_pol" in f.related

    def test_fires_with_admin_attachment(self):
        resources = [self._public_ec2(), self._admin_attachment()]
        findings = _combo_public_ec2_to_admin_role(resources)
        assert len(findings) == 1

    def test_silent_when_no_admin_role(self):
        # EC2 is public but no admin IAM resource present.
        doc = json.dumps({
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::my-bucket/*"}]
        })
        limited_pol = tf("aws_iam_role_policy", "lim_pol", policy=doc)
        resources = [self._public_ec2(), limited_pol]
        assert _combo_public_ec2_to_admin_role(resources) == []

    def test_silent_when_ec2_not_public(self):
        private_ec2 = tf("aws_instance", "priv",
                         associate_public_ip_address=False,
                         iam_instance_profile="my-profile")
        resources = [private_ec2, self._admin_role_policy()]
        assert _combo_public_ec2_to_admin_role(resources) == []

    def test_silent_when_ec2_has_no_profile(self):
        ec2_no_profile = tf("aws_instance", "web",
                            associate_public_ip_address=True)
        resources = [ec2_no_profile, self._admin_role_policy()]
        assert _combo_public_ec2_to_admin_role(resources) == []

    def test_multiple_public_ec2_all_fire(self):
        resources = [
            tf("aws_instance", "web1", associate_public_ip_address=True,
               iam_instance_profile="p1"),
            tf("aws_instance", "web2", associate_public_ip_address=True,
               iam_instance_profile="p2"),
            self._admin_role_policy(),
        ]
        findings = _combo_public_ec2_to_admin_role(resources)
        assert len(findings) == 2


# ─── Combination: CloudTrail multiregion ────────────────────────

class TestComboCloudTrailMultiregion:
    def test_fires_when_no_trails(self):
        # No trails at all => no finding (nothing to attach to).
        assert _combo_cloudtrail_multiregion([]) == []

    def test_fires_when_trails_but_none_multiregion(self):
        r = tf("aws_cloudtrail", "trail1", is_multi_region_trail=False)
        findings = _combo_cloudtrail_multiregion([r])
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "IAC_CLOUDTRAIL_NOT_MULTIREGION"
        assert f.severity == "high"

    def test_fires_when_multiregion_prop_absent(self):
        r = tf("aws_cloudtrail", "trail1")
        assert len(_combo_cloudtrail_multiregion([r])) == 1

    def test_silent_when_one_multiregion_trail(self):
        good = tf("aws_cloudtrail", "trail_good", is_multi_region_trail=True)
        bad = tf("aws_cloudtrail", "trail_bad", is_multi_region_trail=False)
        assert _combo_cloudtrail_multiregion([good, bad]) == []

    def test_related_contains_other_trails(self):
        t1 = tf("aws_cloudtrail", "t1", is_multi_region_trail=False)
        t2 = tf("aws_cloudtrail", "t2", is_multi_region_trail=False)
        findings = _combo_cloudtrail_multiregion([t1, t2])
        assert "t2" in findings[0].related


# ─── Combination: CloudTrail -> public S3 bucket ────────────────

class TestComboCloudTrailPublicS3:
    def test_fires_when_trail_bucket_is_public(self):
        trail = tf("aws_cloudtrail", "trail1", s3_bucket_name="audit-logs")
        bucket = tf("aws_s3_bucket", "audit-logs",
                    bucket="audit-logs", acl="public-read")
        findings = _combo_cloudtrail_public_s3([trail, bucket])
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "IAC_CLOUDTRAIL_S3_PUBLIC"
        assert f.severity == "critical"
        assert "audit-logs" in f.related

    def test_silent_when_bucket_private(self):
        trail = tf("aws_cloudtrail", "trail1", s3_bucket_name="audit-logs")
        bucket = tf("aws_s3_bucket", "audit-logs",
                    bucket="audit-logs", acl="private")
        assert _combo_cloudtrail_public_s3([trail, bucket]) == []

    def test_silent_when_bucket_not_in_plan(self):
        # Trail references a bucket not declared in this plan — no finding.
        trail = tf("aws_cloudtrail", "trail1", s3_bucket_name="external-bucket")
        assert _combo_cloudtrail_public_s3([trail]) == []

    def test_silent_when_no_trails(self):
        bucket = tf("aws_s3_bucket", "b", bucket="b", acl="public-read")
        assert _combo_cloudtrail_public_s3([bucket]) == []


# ─── scan() integration ──────────────────────────────────────────

class TestScanIntegration:
    def test_empty_plan_returns_zero_findings(self):
        result = scan("")
        assert result["total"] == 0
        assert result["resources_scanned"] == 0

    def test_clean_plan_no_findings(self):
        plan = json.dumps({
            "resource": {
                "aws_s3_bucket": {
                    "my_bucket": {
                        "acl": "private",
                        "server_side_encryption_configuration": {"rule": {}},
                    }
                }
            }
        })
        result = scan(plan)
        assert result["total"] == 0

    def test_single_public_s3_detected(self):
        plan = json.dumps({
            "resource": {
                "aws_s3_bucket": {
                    "bad_bucket": {"acl": "public-read"},
                }
            }
        })
        result = scan(plan)
        # public-read ACL fires + no encryption fires
        check_ids = {f["check_id"] for f in result["findings"]}
        assert "IAC_S3_PUBLIC_ACL" in check_ids
        assert "IAC_S3_NO_ENCRYPTION" in check_ids

    def test_toxic_combination_end_to_end(self):
        """Full scan of a plan with public EC2 + admin role => combo finding."""
        plan = json.dumps({
            "resource": {
                "aws_instance": {
                    "web": {
                        "associate_public_ip_address": True,
                        "iam_instance_profile": "admin-profile",
                    }
                },
                "aws_iam_role_policy": {
                    "admin_pol": {
                        "policy": json.dumps({
                            "Statement": [
                                {"Effect": "Allow", "Action": "*", "Resource": "*"}
                            ]
                        })
                    }
                },
            }
        })
        result = scan(plan)
        check_ids = {f["check_id"] for f in result["findings"]}
        assert "IAC_PUBLIC_COMPUTE_TO_ADMIN" in check_ids, (
            "Toxic combination (public EC2 + admin role) must fire"
        )

    def test_findings_sorted_critical_first(self):
        """Critical findings must sort before high/medium/low."""
        plan = json.dumps({
            "resource": {
                "aws_security_group": {
                    "open_sg": {
                        "ingress": [{"from_port": 22, "to_port": 22,
                                     "cidr_blocks": ["0.0.0.0/0"]}]
                    }
                },
                "aws_s3_bucket": {
                    "no_enc": {"acl": "private"},
                },
            }
        })
        result = scan(plan)
        severities = [f["severity"] for f in result["findings"]]
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        assert severities == sorted(severities, key=lambda s: rank.get(s, 9))

    def test_by_severity_summary_correct(self):
        plan = json.dumps({
            "resource": {
                "aws_security_group": {
                    "bad_sg": {
                        "ingress": [{"from_port": 22, "to_port": 22,
                                     "cidr_blocks": ["0.0.0.0/0"]}]
                    }
                },
            }
        })
        result = scan(plan)
        assert result["by_severity"].get("critical", 0) >= 1

    def test_format_field_terraform(self):
        plan = json.dumps({"resource": {"aws_s3_bucket": {"b": {"acl": "private"}}}})
        result = scan(plan)
        assert result["format"] == "terraform"

    def test_format_field_cloudformation(self):
        template = json.dumps({
            "Resources": {
                "MyBucket": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "Private"}}
            }
        })
        result = scan(template)
        assert result["format"] == "cloudformation"

    def test_to_dict_includes_related(self):
        """Combination findings must propagate related field through to_dict."""
        plan = json.dumps({
            "resource": {
                "aws_cloudtrail": {
                    "trail1": {"s3_bucket_name": "audit-logs"}
                },
                "aws_s3_bucket": {
                    "audit-logs": {"bucket": "audit-logs", "acl": "public-read"},
                },
            }
        })
        result = scan(plan)
        combo = next(
            (f for f in result["findings"] if f["check_id"] == "IAC_CLOUDTRAIL_S3_PUBLIC"),
            None,
        )
        assert combo is not None
        assert isinstance(combo["related"], list)
        assert len(combo["related"]) > 0
