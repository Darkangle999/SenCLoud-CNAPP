"""One-click CloudFormation onboarding stays private, reviewable and automatic."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import yaml

from odineyes.core.iac_templates import (
    _CloudFormationLoader,
    cloudformation_autoconnect_template,
    cloudformation_parameterized_template,
    cloudformation_regional_telemetry_template,
)
from odineyes.core.onboarding_hosting import (
    OnboardingHostingConfigurationError,
    cloudformation_quick_create_url,
    public_api_url,
    publish_cloudformation_template,
)


@pytest.fixture(autouse=True)
def central_account(monkeypatch):
    monkeypatch.setenv("ODINEYES_AWS_ACCOUNT_ID", "999999999999")


def test_autoconnect_template_is_valid_yaml_and_does_not_hardcode_role_name():
    template = cloudformation_autoconnect_template(
        "cs-enrolment", "https://api.example.com", "key", "secret",
    )
    parsed = yaml.safe_load(template)

    assert parsed["Resources"]["OdineyesReadOnly"]["Type"] == "AWS::IAM::Role"
    assert "RoleName" not in parsed["Resources"]["OdineyesReadOnly"]["Properties"]
    assert parsed["Resources"]["OdineyesAutoConnect"]["Type"] == "Custom::OdineyesAutoConnect"
    # Generous by design: a callback that runs out of time fails the stack, and
    # the rollback deletes the role the customer just approved.
    assert parsed["Resources"]["OdineyesAutoConnectFunction"]["Properties"]["Timeout"] == 300
    assert "ODINEYES_API_SECRET" in template
    assert "/api/inventory/accounts/autoconnect" in template
    assert "RequestType\"] != \"Create\"" in template


def test_autoconnect_template_requires_https_callback():
    with pytest.raises(ValueError, match="HTTPS"):
        cloudformation_autoconnect_template("cs-enrolment", "http://localhost:8000", "key", "secret")


def test_parameterized_template_has_no_customer_value_or_callback_secret():
    template = cloudformation_parameterized_template()
    parsed = yaml.load(template, Loader=_CloudFormationLoader)

    assert "  ExternalId:" in template
    assert "  CSPMPlatformPrincipalArn:" in template
    assert "  OnboardingToken:" in template
    assert "  CallbackUrl:" in template
    assert "  EnableRealtimeCloudTrail:" in template
    assert "  RealtimeTrailRetentionDays:" in template
    assert "  RealtimeEventBusArn:" in template
    assert "CSPMPlatformPrincipalArn" in template
    assert "sts:ExternalId: !Ref ExternalId" in template
    assert "events:PutEvents" in template
    assert "cs-enrolment" not in template
    assert "ODINEYES_API_SECRET" not in template
    assert parsed["Resources"]["CSPMAccessRole"]["Type"] == "AWS::IAM::Role"
    assert parsed["Resources"]["CSPMOnboardingFunction"]["Type"] == "AWS::Lambda::Function"
    assert parsed["Resources"]["CSPMDataGuardPolicy"]["Type"] == "AWS::IAM::ManagedPolicy"
    trail = parsed["Resources"]["RealtimeCloudTrail"]
    bucket = parsed["Resources"]["RealtimeCloudTrailLogBucket"]
    assert trail["Condition"] == "RealtimeCloudTrailEnabled"
    assert trail["Properties"]["EventSelectors"][0]["ReadWriteType"] == "WriteOnly"
    assert bucket["DeletionPolicy"] == "Retain"
    assert bucket["Properties"]["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] is True
    # EventBridge rejects RetryPolicy when the target is another event bus.
    assert "RetryPolicy" not in parsed["Resources"]["RealtimeMutationRule"]["Properties"]["Targets"][0]


def test_regional_telemetry_template_has_no_global_scanner_role():
    template = cloudformation_regional_telemetry_template()
    parsed = yaml.load(template, Loader=_CloudFormationLoader)

    assert "CSPMAccessRole" not in parsed["Resources"]
    assert parsed["Resources"]["RealtimeMutationRule"]["Type"] == "AWS::Events::Rule"
    assert "RealtimeEventBusArn" in parsed["Parameters"]
    assert parsed["Resources"]["RealtimeDeliveryRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0]["Action"] == "events:PutEvents"
    assert parsed["Resources"]["RealtimeCloudTrail"]["Condition"] == "CreateRealtimeCloudTrail"
    assert "RetryPolicy" not in parsed["Resources"]["RealtimeMutationRule"]["Properties"]["Targets"][0]


def test_quick_create_url_prefills_parameterized_onboarding_values():
    url = cloudformation_quick_create_url(
        template_url="https://s3.example.test/signed-template?X-Amz-Signature=abc",
        region="us-east-1",
        stack_name="odineyes-onboarding-123456789012",
        parameters={
            "ExternalId": "cs-abcdefghijklmnopqrstuvwxyz123456",
            "CSPMPlatformAccountId": "999999999999",
            "CSPMPlatformPrincipalArn": "arn:aws:iam::999999999999:role/OdineyesScanner",
            "OnboardingToken": "abcdefghijklmnopqrstuvwxyz1234567890ABCD",
            "CallbackUrl": "https://api.example.test/api/inventory/accounts/onboarding-callback",
        },
    )

    assert "#/stacks/create/review?" in url
    assert "param_ExternalId=cs-abcdefghijklmnopqrstuvwxyz123456" in url
    assert "param_CSPMPlatformAccountId=999999999999" in url
    assert "param_CSPMPlatformPrincipalArn=arn%3Aaws%3Aiam%3A%3A999999999999%3Arole%2FOdineyesScanner" in url
    assert "param_OnboardingToken=" in url
    assert "param_CallbackUrl=https%3A%2F%2Fapi.example.test" in url


def test_public_api_url_rejects_browser_local_url(monkeypatch):
    monkeypatch.setenv("ODINEYES_PUBLIC_API_URL", "http://localhost:8000")
    with pytest.raises(OnboardingHostingConfigurationError, match="public HTTPS"):
        public_api_url()


def test_publish_uses_a_private_encrypted_object_and_a_short_presigned_url(monkeypatch):
    monkeypatch.setenv("ODINEYES_ONBOARDING_TEMPLATE_BUCKET", "odineyes-onboarding-templates")
    monkeypatch.setenv("ODINEYES_ONBOARDING_TEMPLATE_REGION", "us-east-1")
    s3 = MagicMock()
    s3.generate_presigned_url.return_value = "https://s3.example.test/signed-template"
    import boto3

    monkeypatch.setattr(boto3, "client", lambda service, region_name: s3)
    hosted = publish_cloudformation_template(account_identifier="123456789012", template="Resources: {}\n")

    assert hosted.template_url == "https://s3.example.test/signed-template"
    assert "#/stacks/create/review" in hosted.quick_create_url
    assert hosted.expires_at > datetime.now(timezone.utc)
    kwargs = s3.put_object.call_args.kwargs
    assert kwargs["Bucket"] == "odineyes-onboarding-templates"
    assert kwargs["ServerSideEncryption"] == "AES256"
    assert kwargs["Key"] == "cloudformation-onboarding/aws/123456789012/onboarding.yaml"
    assert s3.generate_presigned_url.call_args.kwargs["ExpiresIn"] == 900
