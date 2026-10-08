"""CloudFormation + Terraform generation — offline, no AWS."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from odineyes.core.iac_templates import (
    ConfigurationError,
    _CloudFormationLoader,
    cloudformation_template,
    odineyes_account_id,
    terraform_snippet,
)

EID = "cs-abcdefghijklmnopqrstuvwxyz123456"
PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _uncommented(template: str) -> str:
    """Absence assertions must read the policy, not the prose explaining it —
    a comment naming what was removed otherwise reads as still granting it."""
    return "\n".join(
        line for line in template.splitlines() if not line.lstrip().startswith("#")
    )


@pytest.fixture(autouse=True)
def _account_id(monkeypatch):
    monkeypatch.setenv("ODINEYES_AWS_ACCOUNT_ID", "999999999999")
    monkeypatch.setenv(
        "ODINEYES_SCANNER_PRINCIPAL_ARN",
        "arn:aws:iam::999999999999:role/OdineyesApi",
    )


def test_missing_account_id_raises_configuration_error(monkeypatch):
    # Unset env AND no resolvable STS identity → must fail loud.
    import odineyes.core.iac_templates as tpl
    monkeypatch.delenv("ODINEYES_AWS_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("ODINEYES_SCANNER_PRINCIPAL_ARN", raising=False)
    monkeypatch.setattr(tpl, "_caller_account_id", lambda: None)
    with pytest.raises(ConfigurationError):
        odineyes_account_id()


def test_missing_account_id_uses_configured_scanner_principal(monkeypatch):
    import odineyes.core.iac_templates as tpl
    monkeypatch.delenv("ODINEYES_AWS_ACCOUNT_ID", raising=False)
    monkeypatch.setenv(
        "ODINEYES_SCANNER_PRINCIPAL_ARN",
        "arn:aws:iam::123456789012:user/CloudSentinelLocalScanner",
    )
    monkeypatch.setattr(tpl, "_caller_account_id", lambda: None)

    assert odineyes_account_id() == "123456789012"


def test_invalid_explicit_account_id_is_rejected(monkeypatch):
    monkeypatch.setenv("ODINEYES_AWS_ACCOUNT_ID", "not-an-account")
    with pytest.raises(ConfigurationError, match="12-digit"):
        odineyes_account_id()


def test_missing_env_falls_back_to_caller_account(monkeypatch):
    # Unset env but STS resolves the scanner's account → use it, no error.
    import odineyes.core.iac_templates as tpl
    monkeypatch.delenv("ODINEYES_AWS_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("ODINEYES_SCANNER_PRINCIPAL_ARN", raising=False)
    monkeypatch.setattr(tpl, "_caller_account_id", lambda: "123456789012")
    assert odineyes_account_id() == "123456789012"


def test_cfn_managed_mode_embeds_trust_and_managed_policies():
    cfn = cloudformation_template(EID, "managed")
    assert "arn:aws:iam::999999999999:role/OdineyesApi" in cfn
    assert "arn:aws:iam::999999999999:root" not in cfn
    assert EID in cfn
    assert "iam::aws:policy/SecurityAudit" in cfn
    # ViewOnlyAccess is deliberately NOT attached here. The four custom policies
    # below name every service the collectors call, so it granted only surplus
    # reach that no auditor could tie to a collected resource. The legacy
    # per-account and Terraform paths still need it — they have no custom
    # policies — which is why MANAGED_POLICIES keeps it.
    assert "ViewOnlyAccess" not in _uncommented(cfn)
    assert "CSPMReadCorePolicy" in cfn
    assert "CSPMReadDataPolicy" in cfn
    assert "CSPMReadSecurityPolicy" in cfn
    assert "CSPMDataGuardPolicy" in cfn
    assert "secretsmanager:GetSecretValue" in cfn
    assert "LeastPrivilege" not in cfn


def test_cfn_managed_mode_covers_ai_and_zero_trust_services():
    """CIEM that reads only IAM misses Cedar-based authorisation, and AI-SPM
    that reads only models misses agents wired to corporate data. Both are
    read-only additions, so the guardrail must still deny the data plane."""
    cfn = cloudformation_template(EID, "managed")
    for action in (
        "verifiedpermissions:Get*",
        "verifiedpermissions:List*",
        "qbusiness:Get*",
        "qbusiness:List*",
        "codeguru-security:Get*",
        "codeguru-security:List*",
    ):
        assert action in cfn, action
    # Agents and knowledge bases authorise under the bedrock: prefix, so the
    # existing wildcards already reach them — no bedrock-agent: grant needed.
    assert "bedrock:Get*" in cfn and "bedrock:List*" in cfn
    assert "bedrock-agent:" not in _uncommented(cfn)
    # Adding reach must never soften the guardrail.
    assert "s3:GetObject" in cfn and "dynamodb:Scan" in cfn


def test_cfn_managed_mode_callback_survives_a_slow_platform():
    """A callback that times out fails the stack, and the rollback deletes the
    roles the customer just approved — the worst outcome in the flow."""
    parsed = yaml.load(cloudformation_template(EID, "managed"), Loader=_CloudFormationLoader)
    assert parsed["Resources"]["CSPMOnboardingFunction"]["Properties"]["Timeout"] == 300
    code = parsed["Resources"]["CSPMOnboardingFunction"]["Properties"]["Code"]["ZipFile"]
    # Per-attempt socket timeout, not the old 20s, is the real binding limit.
    assert "urlopen(request, timeout=60)" in code
    # 4xx is a verdict on the token; retrying it only stalls the rollback.
    assert "if exc.code < 500 or attempt == attempts:" in code
    # Every lifecycle request, including Delete, must retry its response PUT.
    # Otherwise a transient S3 response URL failure leaves DELETE_IN_PROGRESS
    # until CloudFormation gives up.
    assert "CloudFormation response PUT attempt {attempt}/3 failed" in code
    assert "for attempt in range(1, 4):" in code
    assert parsed["Resources"]["CSPMOnboarding"]["Properties"]["ServiceTimeout"] == 300


def test_cfn_least_privilege_mode_embeds_derived_policy():
    cfn = cloudformation_template(EID, "least-privilege")
    assert "OdineyesLeastPrivilege" in cfn
    assert "ec2:DescribeInstances" in cfn
    assert "SecurityAudit" not in cfn


def test_cfn_rejects_unknown_policy_mode():
    with pytest.raises(ValueError):
        cloudformation_template(EID, "readwrite")


def test_cfn_outputs_role_arn():
    cfn = cloudformation_template(EID)
    assert "Outputs:" in cfn and "RoleArn" in cfn


def test_terraform_managed_mode():
    tf = terraform_snippet(EID, "managed")
    assert EID in tf
    assert 'resource "aws_iam_role" "odineyes_readonly"' in tf
    assert "SecurityAudit" in tf and "ViewOnlyAccess" in tf
    assert 'resource "aws_iam_policy" "odineyes_read_core"' in tf
    assert 'resource "aws_iam_policy" "odineyes_data_guard"' in tf
    assert "secretsmanager:GetSecretValue" in tf
    assert "output " in tf


def test_terraform_least_privilege_mode():
    tf = terraform_snippet(EID, "least-privilege")
    assert "jsonencode(" in tf
    assert "ec2:DescribeInstances" in tf


@pytest.mark.parametrize(
    "relative_path",
    [
        "infrastructure/aws-bootstrap.yaml",
        "infrastructure/onboarding-template-hosting.yaml",
    ],
)
def test_template_hosting_can_grant_scoped_local_operator_access(relative_path: str):
    """Local API hosting needs real object access, never public bucket access."""
    template = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")

    assert "LocalTemplateOperatorPrincipalArn" in template
    assert "AllowLocalOperatorTemplateObjects" in template
    assert "s3:GetObject" in template
    assert "s3:PutObject" in template
    assert "AllowLocalOperatorTemplatePrefixListing" in template
    assert "s3:GetBucketPolicyStatus" in template
    assert "Principal: '*'" not in template


def test_different_external_ids_produce_different_trust_policies():
    first = "cs-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    second = "cs-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    cfn_a = cloudformation_template(first)
    cfn_b = cloudformation_template(second)
    assert first in cfn_a and first not in cfn_b
    assert second in cfn_b and second not in cfn_a
