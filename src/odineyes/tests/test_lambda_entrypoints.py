"""Resource-policy parsing that turns a Lambda's triggers into a reachable path.

The collector reduces a Lambda's resource policy to booleans. That was enough
while "public" meant a function URL, and wrong the moment an API Gateway sat in
front: the policy is the only place the front door is named.
"""

from __future__ import annotations

from odineyes.inventory.aws_raw_collector import _service_trigger_source_arns
from odineyes.inventory.normalizers import normalize_lambda_function

API_ARN = "arn:aws:execute-api:eu-west-1:123456789012:abc123/*/GET/orders"


def test_api_gateway_integration_yields_its_source_arn():
    policy = {"Version": "2012-10-17", "Statement": [{
        "Sid": "apigateway-prod", "Effect": "Allow",
        "Principal": {"Service": "apigateway.amazonaws.com"},
        "Action": "lambda:InvokeFunction",
        "Resource": "arn:aws:lambda:eu-west-1:123456789012:function:orders",
        "Condition": {"ArnLike": {"AWS:SourceArn": API_ARN}},
    }]}
    assert _service_trigger_source_arns(policy) == [API_ARN]


def test_a_statement_with_no_source_arn_condition_names_no_front_door():
    """An unconditional service grant points at nothing resolvable, so it must
    not be turned into a phantom entrypoint."""
    policy = {"Statement": [{
        "Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"},
        "Action": "lambda:InvokeFunction",
    }]}
    assert _service_trigger_source_arns(policy) == []


def test_deny_statements_and_junk_are_ignored():
    assert _service_trigger_source_arns(None) == []
    assert _service_trigger_source_arns({"Statement": "not-a-list"}) == []
    assert _service_trigger_source_arns({"Statement": [{
        "Effect": "Deny", "Principal": {"Service": "apigateway.amazonaws.com"},
        "Condition": {"ArnLike": {"AWS:SourceArn": API_ARN}},
    }]}) == []


def test_lowercase_condition_key_is_accepted():
    """AWS accepts aws:SourceArn in either case and real policies use both."""
    policy = {"Statement": [{
        "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
        "Condition": {"StringEquals": {"aws:SourceArn": API_ARN}},
    }]}
    assert _service_trigger_source_arns(policy) == [API_ARN]


def test_normalizer_carries_triggers_and_vpc_subnets_through():
    asset = normalize_lambda_function({
        "FunctionName": "orders",
        "FunctionArn": "arn:aws:lambda:eu-west-1:123456789012:function:orders",
        "Region": "eu-west-1",
        "FunctionUrlAuthType": "AWS_IAM",
        "PublicPolicy": False,
        "TriggerSourceArns": [API_ARN],
        "VpcConfig": {"VpcId": "vpc-1", "SubnetIds": ["subnet-a", "subnet-b"],
                      "SecurityGroupIds": ["sg-1"]},
        "_Evidence": {"resource_policy": "observed"},
    }, "123456789012")

    assert asset.properties["trigger_source_arns"] == [API_ARN]
    # Subnets matter twice over: they prove the function occupies those subnets,
    # which is what stops the empty-subnet filter muting a live one.
    assert asset.properties["subnet_ids"] == ["subnet-a", "subnet-b"]
    assert asset.properties["security_group_ids"] == ["sg-1"]
    assert asset.is_public is False


def test_cicd_oidc_covers_the_providers_that_hold_account_credentials():
    from odineyes.inventory.issues import _CICD_OIDC

    for issuer in ("token.actions.githubusercontent.com", "gitlab.com",
                   "bitbucket.org", "oidc.circleci.com", "app.terraform.io",
                   "auth.idp.hashicorp.cloud", "rolesanywhere.amazonaws.com",
                   "vstoken.dev.azure.com", "accounts.google.com",
                   "oidc.eks.eu-west-1.amazonaws.com"):
        assert _CICD_OIDC.search(f"arn:aws:iam::1:oidc-provider/{issuer}"), issuer

    # Not every federation is a CI/CD pivot — a corporate SSO issuer is not.
    assert not _CICD_OIDC.search("arn:aws:iam::1:saml-provider/OktaCorp")
