import os
import pytest
from odineyes.core.iac_templates import (
    _trust_policy,
    stackset_cloudformation_template,
    terraform_autoconnect_snippet,
)

def test_terraform_autoconnect_snippet_is_self_contained():
    # No external module source (repo is private — a git:: source would need
    # creds baked into every client's terraform run). Instead the snippet
    # writes its own trigger script and wires it via local_file + external.
    os.environ["ODINEYES_AWS_ACCOUNT_ID"] = "111111111111"
    os.environ["ODINEYES_API_URL"] = "https://api.test.com"

    snippet = terraform_autoconnect_snippet(
        external_id="ext-123", api_key="key", api_secret="secret",
    )

    assert "git::" not in snippet             # no external module source
    assert 'resource "aws_iam_role" "odineyes_readonly"' in snippet
    assert 'resource "local_file" "odineyes_trigger"' in snippet
    assert 'data "external" "odineyes_autoconnect"' in snippet
    assert 'api_url     = "https://api.test.com"' in snippet
    assert 'api_key     = "key"' in snippet
    assert 'api_secret  = "secret"' in snippet
    assert 'external_id = "ext-123"' in snippet
    # the embedded trigger.py posts to /accounts/autoconnect with an HMAC sig.
    assert "/api/inventory/accounts/autoconnect" in snippet
    assert "hmac.new(" in snippet


def test_terraform_autoconnect_snippet_least_privilege_mode():
    os.environ["ODINEYES_AWS_ACCOUNT_ID"] = "111111111111"
    snippet = terraform_autoconnect_snippet(
        external_id="ext-123", api_key="key", api_secret="secret",
        policy_mode="least-privilege",
    )
    assert "OdineyesLeastPrivilege" in snippet
    assert "SecurityAudit" not in snippet


def test_terraform_autoconnect_snippet_rejects_bad_policy_mode():
    os.environ["ODINEYES_AWS_ACCOUNT_ID"] = "111111111111"
    with pytest.raises(ValueError):
        terraform_autoconnect_snippet("ext-123", "key", "secret", "readwrite")


def test_embedded_trigger_matches_infra_module_source():
    # Guard against the embedded copy drifting from the real module file
    # (infrastructure/modules/odineyes-onboarding/trigger.py is what a
    # Terraform-module-source user gets; the embedded copy is what a
    # generated-snippet user gets — they must stay identical).
    import odineyes.core.iac_templates as tpl
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    infra_path = os.path.join(here, "infrastructure", "modules", "odineyes-onboarding", "trigger.py")
    if not os.path.isfile(infra_path):
        pytest.skip("infra module not present in this checkout")
    with open(infra_path, encoding="utf-8") as f:
        on_disk = f.read()
    norm = lambda s: "\n".join(line.rstrip() for line in s.strip().splitlines())  # noqa: E731
    assert norm(tpl._TRIGGER_PY_SOURCE) == norm(on_disk)

def test_trust_policy_hardening():
    os.environ["ODINEYES_AWS_ACCOUNT_ID"] = "111111111111"
    
    # Test without IPs
    os.environ["ODINEYES_SCANNER_IP_CIDRS"] = ""
    pol = _trust_policy("ext-123")
    cond = pol["Statement"][0]["Condition"]
    assert "StringEquals" in cond
    assert "IpAddress" not in cond

    # Test with IPs
    os.environ["ODINEYES_SCANNER_IP_CIDRS"] = "1.2.3.4/32"
    pol2 = _trust_policy("ext-123")
    cond2 = pol2["Statement"][0]["Condition"]
    assert "StringEquals" in cond2
    assert "IpAddress" in cond2
    assert cond2["IpAddress"]["aws:SourceIp"] == ["1.2.3.4/32"]

def test_stackset_template():
    # Stackset template should just be the base template for now
    os.environ["ODINEYES_AWS_ACCOUNT_ID"] = "111111111111"
    tpl = stackset_cloudformation_template("ext-123")
    assert "AWSTemplateFormatVersion" in tpl
