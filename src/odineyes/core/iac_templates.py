"""Generate the CloudFormation template and Terraform snippet a client uses to
provision the read-only cross-account role — replaces the "hand-edit this JSON
trust policy" onboarding step with a reviewable, versioned artifact their
security/platform team can diff and run through their existing pipeline.

Both formats embed the same trust condition (our AWS account id as principal +
a server-generated ExternalId — see CloudAccount.external_id) and the same
policy body (either the two AWS-managed read-only policies, or the derived
least-privilege policy from iam_policy_generator).

Not built here: a one-click "Launch Stack" console URL. That requires the
template hosted at a public/presigned S3 URL — a real infra decision (a
bucket, a publish step) this module shouldn't silently assume. Until that
exists, the client uploads the generated template body through CloudFormation's
"Upload a template file" flow — still a single reviewable file, not novel JSON
assembled by hand, just without the extra click.

Current implementation: ``cloudformation_autoconnect_template`` generates the
one-click variant. ``onboarding_hosting`` puts it in a private S3 bucket and
returns a short-lived CloudFormation Quick Create URL. The stack callback then
submits the generated role ARN through the existing HMAC endpoint.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

import boto3
import yaml

from odineyes.core.iam_policy_generator import least_privilege_policy

ROLE_NAME = "OdineyesReadOnly"
MANAGED_POLICIES = [
    "arn:aws:iam::aws:policy/SecurityAudit",
    "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
]
ENTERPRISE_TEMPLATE_PATH = Path(__file__).with_name("templates") / "cspm_g3_onboarding.yaml"
REGIONAL_TELEMETRY_TEMPLATE_PATH = Path(__file__).with_name("templates") / "cspm_g3_regional_telemetry.yaml"
_ENTERPRISE_POLICY_RESOURCES = (
    "CSPMReadCorePolicy",
    "CSPMReadDataPolicy",
    "CSPMReadSecurityPolicy",
    "CSPMDataGuardPolicy",
)


class ConfigurationError(RuntimeError):
    pass


class _CloudFormationLoader(yaml.SafeLoader):
    """Safe YAML loader that preserves CloudFormation intrinsic arguments."""


def _cloudformation_tag(loader: yaml.SafeLoader, _tag: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_CloudFormationLoader.add_multi_constructor("!", _cloudformation_tag)


@lru_cache(maxsize=1)
def _enterprise_template() -> str:
    """Load the reviewed, reusable full-visibility onboarding template."""
    try:
        template = ENTERPRISE_TEMPLATE_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(
            f"Odineyes enterprise onboarding template is unavailable: {exc}"
        ) from exc
    if not template.strip():
        raise ConfigurationError("Odineyes enterprise onboarding template is empty")
    return template


@lru_cache(maxsize=1)
def cloudformation_regional_telemetry_template() -> str:
    """Return the region-only EventBridge/CloudTrail telemetry stack.

    It deliberately creates no IAM scanner role. Customers deploy the account
    foundation once, then this smaller template once per monitored Region.
    """
    try:
        template = REGIONAL_TELEMETRY_TEMPLATE_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(
            f"Odineyes regional telemetry template is unavailable: {exc}"
        ) from exc
    if not template.strip():
        raise ConfigurationError("Odineyes regional telemetry template is empty")
    parsed = yaml.load(template, Loader=_CloudFormationLoader)
    resources = parsed.get("Resources", {}) if isinstance(parsed, dict) else {}
    if resources.get("RealtimeMutationRule", {}).get("Type") != "AWS::Events::Rule":
        raise ConfigurationError("regional telemetry template is missing RealtimeMutationRule")
    if "CSPMAccessRole" in resources:
        raise ConfigurationError("regional telemetry template must not create CSPMAccessRole")
    return template


@lru_cache(maxsize=1)
def _enterprise_policy_documents() -> dict[str, dict[str, Any]]:
    parsed = yaml.load(_enterprise_template(), Loader=_CloudFormationLoader)
    resources = parsed.get("Resources", {}) if isinstance(parsed, dict) else {}
    documents: dict[str, dict[str, Any]] = {}
    for resource_name in _ENTERPRISE_POLICY_RESOURCES:
        resource = resources.get(resource_name, {})
        document = resource.get("Properties", {}).get("PolicyDocument")
        if not isinstance(document, dict):
            raise ConfigurationError(
                f"enterprise onboarding template is missing {resource_name}.PolicyDocument"
            )
        documents[resource_name] = document
    return documents


def _set_parameter_default(template: str, parameter: str, value: str) -> str:
    """Set a String parameter default without embedding callback credentials."""
    pattern = re.compile(
        rf"(?m)^(  {re.escape(parameter)}:\r?\n    Type: String\r?\n)(?:    Default:.*\r?\n)?"
    )
    rendered, count = pattern.subn(
        lambda match: match.group(1) + f"    Default: {json.dumps(value)}\n",
        template,
        count=1,
    )
    if count != 1:
        raise ConfigurationError(f"enterprise template parameter {parameter} was not found")
    return rendered


def _manual_enterprise_template(external_id: str) -> str:
    """Full template with trust defaults, while leaving auto-connect disabled."""
    rendered = _enterprise_template()
    rendered = _set_parameter_default(rendered, "CSPMPlatformAccountId", odineyes_account_id())
    rendered = _set_parameter_default(
        rendered, "CSPMPlatformPrincipalArn", odineyes_scanner_principal_arn()
    )
    rendered = _set_parameter_default(rendered, "ExternalId", external_id)
    return rendered


def _enterprise_terraform_attachments() -> str:
    """Terraform equivalent of the managed template's four guarded policies."""
    blocks: list[str] = []
    for index, arn in enumerate(MANAGED_POLICIES, start=1):
        blocks.append(
            f'resource "aws_iam_role_policy_attachment" "odineyes_managed_{index}" {{\n'
            '  role       = aws_iam_role.odineyes_readonly.name\n'
            f'  policy_arn = "{arn}"\n'
            '}'
        )

    names = {
        "CSPMReadCorePolicy": ("read_core", "Read-Core"),
        "CSPMReadDataPolicy": ("read_data", "Read-Data"),
        "CSPMReadSecurityPolicy": ("read_security", "Read-Security"),
        "CSPMDataGuardPolicy": ("data_guard", "Data-Guard"),
    }
    for resource_name, document in _enterprise_policy_documents().items():
        terraform_name, suffix = names[resource_name]
        blocks.append(
            f'resource "aws_iam_policy" "odineyes_{terraform_name}" {{\n'
            f'  name   = "${{aws_iam_role.odineyes_readonly.name}}-{suffix}"\n'
            f'  policy = jsonencode({json.dumps(document)})\n'
            '}\n\n'
            f'resource "aws_iam_role_policy_attachment" "odineyes_{terraform_name}" {{\n'
            '  role       = aws_iam_role.odineyes_readonly.name\n'
            f'  policy_arn = aws_iam_policy.odineyes_{terraform_name}.arn\n'
            '}'
        )
    return "\n\n".join(blocks)


_CACHED_CALLER_ACCOUNT: Optional[str] = None
_ACCOUNT_ID_RE = re.compile(r"\d{12}")
_SCANNER_PRINCIPAL_RE = re.compile(
    r"arn:aws[a-z-]*:iam::(?P<account_id>\d{12}):(user|role)/[\w+=,.@/-]+"
)


def _caller_account_id() -> Optional[str]:
    """The 12-digit account id the scanner process itself runs as, via STS, or
    None if it can't be resolved (no credentials). Cached — get_caller_identity
    is a fixed fact for the life of the process."""
    global _CACHED_CALLER_ACCOUNT
    if _CACHED_CALLER_ACCOUNT:
        return _CACHED_CALLER_ACCOUNT
    try:
        acct = boto3.client("sts").get_caller_identity().get("Account")
    except Exception:  # noqa: BLE001 — no creds / offline; caller handles None
        return None
    if acct and _ACCOUNT_ID_RE.fullmatch(acct):
        _CACHED_CALLER_ACCOUNT = acct
        return acct
    return None


def _configured_scanner_account_id() -> Optional[str]:
    """Return account embedded in a configured scanner IAM principal."""
    configured = os.environ.get("ODINEYES_SCANNER_PRINCIPAL_ARN", "").strip()
    match = _SCANNER_PRINCIPAL_RE.fullmatch(configured)
    return match.group("account_id") if match else None


def odineyes_account_id() -> str:
    """Our AWS account id — the trust principal every client role must allow.

    ODINEYES_AWS_ACCOUNT_ID wins when set. For offline template generation, a
    configured scanner IAM user or role ARN supplies the same account without
    an STS call. Otherwise the scanner's own STS identity is used. Only when
    no trusted account source is available do we fail instead of emitting a
    template that trusts nothing."""
    val = os.environ.get("ODINEYES_AWS_ACCOUNT_ID", "").strip()
    if val:
        if not _ACCOUNT_ID_RE.fullmatch(val):
            raise ConfigurationError("ODINEYES_AWS_ACCOUNT_ID must be a 12-digit AWS account ID")
        return val
    configured_scanner_account = _configured_scanner_account_id()
    if configured_scanner_account:
        return configured_scanner_account
    caller = _caller_account_id()
    if caller:
        return caller
    raise ConfigurationError(
        "ODINEYES_AWS_ACCOUNT_ID is not set and the scanner's AWS account "
        "could not be resolved via STS. Configure AWS credentials for the "
        "scanner, or set ODINEYES_AWS_ACCOUNT_ID to the account it assumes "
        "roles from."
    )


def odineyes_scanner_principal_arn() -> str:
    """Return the narrowest AWS principal that may assume customer roles.

    A configured IAM user/role ARN is authoritative.  Locally, STS normally
    returns an IAM user ARN; on AWS workloads it returns an assumed-role ARN,
    which is converted back to the owning IAM role ARN.  The account-root
    fallback preserves compatibility for offline template generation only.
    """
    configured = os.environ.get("ODINEYES_SCANNER_PRINCIPAL_ARN", "").strip()
    if configured:
        if not _SCANNER_PRINCIPAL_RE.fullmatch(configured):
            raise ConfigurationError(
                "ODINEYES_SCANNER_PRINCIPAL_ARN must be an IAM user or role ARN"
            )
        return configured

    try:
        caller_arn = boto3.client("sts").get_caller_identity().get("Arn", "")
    except Exception:  # noqa: BLE001 - offline generation falls back below
        caller_arn = ""

    if re.fullmatch(r"arn:aws[a-z-]*:iam::\d{12}:(?:user|role)/[\w+=,.@/-]+", caller_arn):
        return caller_arn

    assumed_role = re.fullmatch(
        r"arn:aws[a-z-]*:sts::(\d{12}):assumed-role/([\w+=,.@-]+)/[^/]+", caller_arn
    )
    if assumed_role:
        return f"arn:aws:iam::{assumed_role.group(1)}:role/{assumed_role.group(2)}"

    return f"arn:aws:iam::{odineyes_account_id()}:root"


def _trust_policy(external_id: str) -> dict:
    condition: dict[str, Any] = {"StringEquals": {"sts:ExternalId": external_id}}
    
    scanner_ips = os.environ.get("ODINEYES_SCANNER_IP_CIDRS", "").strip()
    if scanner_ips:
        cidrs = [ip.strip() for ip in scanner_ips.split(",") if ip.strip()]
        if cidrs:
            condition["IpAddress"] = {"aws:SourceIp": cidrs}
            
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": odineyes_scanner_principal_arn()},
            "Action": "sts:AssumeRole",
            "Condition": condition,
        }],
    }


def cloudformation_template(external_id: str, policy_mode: str = "managed") -> str:
    """YAML CloudFormation template provisioning the role. policy_mode:
    'managed' (broad discovery through SecurityAudit + ViewOnlyAccess,
    AWS-maintained) or
    'least-privilege' (derived from the collector's actual OPERATIONS
    registry — narrower, but re-verify after upgrading Odineyes since a
    new resource type means a new required action)."""
    if policy_mode not in ("managed", "least-privilege"):
        raise ValueError(f"policy_mode must be 'managed' or 'least-privilege', got {policy_mode!r}")

    if policy_mode == "managed":
        return _manual_enterprise_template(external_id)

    trust_json = json.dumps(_trust_policy(external_id), indent=8)
    policy_doc = json.dumps(least_privilege_policy(), indent=10)
    policy_block = (
        "      Policies:\n"
        "        - PolicyName: OdineyesLeastPrivilege\n"
        f"          PolicyDocument: {policy_doc}"
    )

    return f"""AWSTemplateFormatVersion: '2010-09-09'
Description: >
  Odineyes read-only cross-account scanner role. Grants no write access —
  every permission is Describe/List/Get. Review before applying.

Resources:
  {ROLE_NAME}:
    Type: AWS::IAM::Role
    Properties:
      RoleName: {ROLE_NAME}
      AssumeRolePolicyDocument: {trust_json}
{policy_block}

Outputs:
  RoleArn:
    Description: Paste this into Odineyes's Accounts page.
    Value: !GetAtt {ROLE_NAME}.Arn
"""


def cloudformation_parameterized_template(policy_mode: str = "managed") -> str:
    """Return reusable CloudFormation YAML for Quick Create onboarding.

    Unlike :func:`cloudformation_template`, this release artifact contains no
    customer-specific value.  The API supplies ``ExternalId`` and the narrow
    Odineyes workload principal as Quick Create parameters.  This lets one
    immutable, reviewable S3 object serve many customer accounts without
    embedding an ExternalId or an onboarding callback credential in it.
    """
    if policy_mode not in ("managed", "least-privilege"):
        raise ValueError(f"policy_mode must be 'managed' or 'least-privilege', got {policy_mode!r}")

    if policy_mode == "managed":
        return _enterprise_template()

    policy_doc = json.dumps(least_privilege_policy(), indent=10)
    policy_block = (
        "      Policies:\n"
        "        - PolicyName: OdineyesLeastPrivilege\n"
        f"          PolicyDocument: {policy_doc}"
    )

    return f"""AWSTemplateFormatVersion: '2010-09-09'
Description: >
  Odineyes read-only cross-account onboarding. ExternalId and scanner principal
  are supplied by the Odineyes Quick Create link, not stored in this template.

Parameters:
  ExternalId:
    Type: String
    MinLength: 2
    MaxLength: 1224
    AllowedPattern: '^[\\w+=,.@:/-]+$'
    ConstraintDescription: ExternalId contains only AWS STS-supported characters.
  ProviderPrincipalArn:
    Type: String
    AllowedPattern: '^arn:aws[a-z-]*:iam::[0-9]{{12}}:(role|user)/[A-Za-z0-9_+=,.@/-]+$'
    ConstraintDescription: Provide an IAM user or role ARN from the Odineyes provider account.
  ConnectionId:
    Type: String
    MinLength: 1
    MaxLength: 64

Resources:
  {ROLE_NAME}:
    Type: AWS::IAM::Role
    Properties:
      RoleName: {ROLE_NAME}
      Tags:
        - Key: odineyes:connection-id
          Value: !Ref ConnectionId
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Ref ProviderPrincipalArn
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: !Ref ExternalId
{policy_block}

Outputs:
  RoleArn:
    Description: Role Odineyes verifies automatically after stack creation.
    Value: !GetAtt {ROLE_NAME}.Arn
  ConnectionId:
    Description: Odineyes connection reference.
    Value: !Ref ConnectionId
"""


# Lambda-backed custom resources must PUT a status document to CloudFormation's
# presigned ResponseURL. Keep this stdlib-only so an inline ZipFile deployment
# needs no extra layer or package download in a customer's account.
_CFN_AUTOCONNECT_HANDLER = '''import hashlib
import hmac
import json
import os
import time
import traceback
import urllib.parse
import urllib.request


def _respond(event, context, status, data=None, reason=None):
    response = {
        "Status": status,
        "Reason": reason or f"See CloudWatch Log Stream: {context.log_stream_name}",
        "PhysicalResourceId": event.get("PhysicalResourceId") or f"odineyes-{event['LogicalResourceId']}",
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        # The response contains only status and the generated role ARN; never
        # return the HMAC values held in the Lambda environment.
        "NoEcho": False,
        "Data": data or {},
    }
    body = json.dumps(response).encode("utf-8")
    request = urllib.request.Request(
        event["ResponseURL"], data=body, method="PUT",
        headers={"content-type": "", "content-length": str(len(body))},
    )
    with urllib.request.urlopen(request, timeout=20):
        pass


def _connect(event):
    # A stack update/delete must never re-enrol or deactivate an account. The
    # role ARN is submitted exactly once: after the original Create succeeds.
    if event["RequestType"] != "Create":
        return {"connection": "unchanged"}

    role_arn = event["ResourceProperties"]["RoleArn"]
    payload = {
        "external_id": os.environ["ODINEYES_EXTERNAL_ID"],
        "role_arn": role_arn,
        "cloud": "aws",
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    url = os.environ["ODINEYES_API_URL"].rstrip("/") + "/api/inventory/accounts/autoconnect"
    timestamp = str(int(time.time() * 1000))
    path = urllib.parse.urlsplit(url).path
    message = timestamp + "POST" + path + body.decode("utf-8")
    signature = hmac.new(
        os.environ["ODINEYES_API_SECRET"].encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("X-API-Key", os.environ["ODINEYES_API_KEY"])
    request.add_header("X-Signature", signature)
    request.add_header("X-Timestamp", timestamp)
    # Generous: a slow platform response here fails the stack, and the rollback
    # deletes the role the customer just approved. Not retried, unlike the
    # enterprise template's callback — this request is HMAC-signed over a
    # timestamp, so a second attempt needs a fresh signature, not a replay.
    with urllib.request.urlopen(request, timeout=60) as response:
        result = json.loads(response.read().decode("utf-8"))
    if result.get("status") != "connected":
        raise RuntimeError(f"unexpected Odineyes response: {result}")
    return {"connection": "connected", "role_arn": role_arn}


def handler(event, context):
    try:
        result = _connect(event)
        _respond(event, context, "SUCCESS", result)
    except Exception as exc:
        print(traceback.format_exc())
        _respond(event, context, "FAILED", {"connection": "failed"}, str(exc))
'''


def cloudformation_autoconnect_template(
    external_id: str,
    api_url: str,
    api_key: str,
    api_secret: str,
    policy_mode: str = "managed",
) -> str:
    """Create a role and connect it without a role-ARN copy/paste step.

    The custom resource runs only on stack creation and can only write Lambda
    logs. It submits the exact generated role ARN through the existing
    account-bound HMAC autoconnect endpoint.
    """
    if policy_mode not in ("managed", "least-privilege"):
        raise ValueError(f"policy_mode must be 'managed' or 'least-privilege', got {policy_mode!r}")
    if not api_url.startswith("https://"):
        raise ValueError("api_url for CloudFormation autoconnect must be HTTPS")

    trust_json = json.dumps(_trust_policy(external_id), indent=8)
    if policy_mode == "managed":
        policies_yaml = "\n".join(f"        - {arn}" for arn in MANAGED_POLICIES)
        policy_block = f"      ManagedPolicyArns:\n{policies_yaml}"
    else:
        policy_doc = json.dumps(least_privilege_policy(), indent=10)
        policy_block = (
            "      Policies:\n"
            "        - PolicyName: OdineyesLeastPrivilege\n"
            f"          PolicyDocument: {policy_doc}"
        )

    handler = "\n".join(f"          {line}" if line else "" for line in _CFN_AUTOCONNECT_HANDLER.splitlines())
    return f"""AWSTemplateFormatVersion: '2010-09-09'
Description: >
  Odineyes one-click, read-only cross-account onboarding. The role has no write
  permissions. A deployment helper submits its ARN only after the stack creates it.

Resources:
  {ROLE_NAME}:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument: {trust_json}
{policy_block}

  OdineyesAutoConnectFunctionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: OdineyesAutoConnectLogs
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: '*'

  OdineyesAutoConnectFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Timeout: 300
      Role:
        Fn::GetAtt:
          - OdineyesAutoConnectFunctionRole
          - Arn
      Environment:
        Variables:
          ODINEYES_API_URL: {json.dumps(api_url)}
          ODINEYES_API_KEY: {json.dumps(api_key)}
          ODINEYES_API_SECRET: {json.dumps(api_secret)}
          ODINEYES_EXTERNAL_ID: {json.dumps(external_id)}
      Code:
        ZipFile: |
{handler}

  OdineyesAutoConnect:
    Type: Custom::OdineyesAutoConnect
    DependsOn:
      - {ROLE_NAME}
      - OdineyesAutoConnectFunction
    Properties:
      ServiceToken:
        Fn::GetAtt:
          - OdineyesAutoConnectFunction
          - Arn
      RoleArn:
        Fn::GetAtt:
          - {ROLE_NAME}
          - Arn

Outputs:
  RoleArn:
    Description: Registered automatically after stack creation succeeds.
    Value:
      Fn::GetAtt:
        - {ROLE_NAME}
        - Arn
  ConnectionStatus:
    Description: Connected only after Odineyes accepts the generated role ARN.
    Value:
      Fn::GetAtt:
        - OdineyesAutoConnect
        - connection
"""


def terraform_snippet(external_id: str, policy_mode: str = "managed") -> str:
    """HCL for a Terraform-managed AWS org — drop into an existing module so
    the role lands in the client's own state/PR-review workflow instead of
    being a console-clicked resource that drifts from their IaC."""
    if policy_mode not in ("managed", "least-privilege"):
        raise ValueError(f"policy_mode must be 'managed' or 'least-privilege', got {policy_mode!r}")

    trust_json = json.dumps(_trust_policy(external_id))
    if policy_mode == "managed":
        attachments = _enterprise_terraform_attachments()
    else:
        policy_json = json.dumps(least_privilege_policy())
        attachments = (
            'resource "aws_iam_role_policy" "odineyes_least_privilege" {\n'
            '  name   = "OdineyesLeastPrivilege"\n'
            '  role   = aws_iam_role.odineyes_readonly.id\n'
            f'  policy = jsonencode({policy_json})\n'
            '}'
        )

    return f"""resource "aws_iam_role" "odineyes_readonly" {{
  name               = "{ROLE_NAME}"
  assume_role_policy = jsonencode({trust_json})
}}

{attachments}

output "odineyes_role_arn" {{
  value       = aws_iam_role.odineyes_readonly.arn
  description = "Paste this into Odineyes's Accounts page."
}}
"""


# Kept byte-identical to infrastructure/modules/odineyes-onboarding/trigger.py
# (test_iac_templates_v2.py asserts they match) — this is what actually posts
# the role ARN back to Odineyes once Terraform creates it, so onboarding needs
# zero manual copy-paste of the ARN.
_TRIGGER_PY_SOURCE = '''import json
import sys
import hmac
import hashlib
import time
import urllib.request
import urllib.error
import urllib.parse

def log(message):
    print(message, file=sys.stderr)

def main():
    try:
        # Read input from Terraform external data source
        input_data = sys.stdin.read()
        if not input_data:
            return
        query = json.loads(input_data)
    except Exception as e:
        log(f"Failed to read input: {e}")
        sys.exit(1)

    api_url = query.get('api_url')
    api_key = query.get('api_key')
    api_secret = query.get('api_secret')
    external_id = query.get('external_id')
    role_arn = query.get('role_arn')
    cloud = query.get('cloud', 'aws')

    if not all([api_url, api_key, api_secret, external_id, role_arn]):
        log("Missing required parameters for autoconnect")
        sys.exit(1)

    url = f"{api_url.rstrip('/')}/api/inventory/accounts/autoconnect"
    tstmp = str(int(time.time() * 1000))

    body_dict = {
        "external_id": external_id,
        "role_arn": role_arn,
        "cloud": cloud
    }
    body_bytes = json.dumps(body_dict).encode('utf-8')

    path = urllib.parse.urlparse(url).path

    # Compute HMAC signature
    enc = tstmp + "POST" + path + body_bytes.decode('utf-8')
    sig = hmac.new(
        api_secret.encode('utf-8'),
        enc.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    req = urllib.request.Request(url, data=body_bytes, method="POST")
    req.add_header("X-API-Key", api_key)
    req.add_header("X-Signature", sig)
    req.add_header("X-Timestamp", tstmp)
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req) as response:
            res_body = response.read().decode('utf-8')
            log(f"Autoconnect response: {response.status} {res_body}")
            # Output to terraform
            print(json.dumps({"status": "connected"}))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8')
        log(f"Autoconnect failed with HTTP {e.code}: {err_body}")
        # Return error status to terraform but don't fail the deployment
        print(json.dumps({"status": f"failed: {e.code}"}))
    except Exception as e:
        log(f"Autoconnect failed: {e}")
        print(json.dumps({"status": "error"}))

if __name__ == "__main__":
    main()
'''

_AUTOCONNECT_TEMPLATE = '''resource "aws_iam_role" "odineyes_readonly" {
  name               = "ROLE_NAME__"
  assume_role_policy = jsonencode(TRUST_JSON__)
}

ATTACHMENTS__

# Auto-connect: Terraform writes the trigger script itself (nothing extra to
# save or download) and runs it right after the role is created, POSTing the
# ARN back to Odineyes. Requires python3 on the machine running `terraform
# apply`. If this step fails for any reason, paste odineyes_role_arn (below)
# into the Accounts page manually — the role itself is unaffected.
resource "local_file" "odineyes_trigger" {
  filename = "${path.module}/.odineyes_trigger.py"
  content  = <<PYEOF
TRIGGER_PY__
PYEOF
}

data "external" "odineyes_autoconnect" {
  program = ["python3", "${path.module}/.odineyes_trigger.py"]
  query = {
    api_url     = "API_URL__"
    api_key     = "API_KEY__"
    api_secret  = "API_SECRET__"
    external_id = "EXTERNAL_ID__"
    role_arn    = aws_iam_role.odineyes_readonly.arn
    cloud       = "aws"
  }
  depends_on = [local_file.odineyes_trigger, aws_iam_role.odineyes_readonly]
}

output "odineyes_onboarding_status" {
  value = data.external.odineyes_autoconnect.result.status
}

output "odineyes_role_arn" {
  value       = aws_iam_role.odineyes_readonly.arn
  description = "Auto-submitted to Odineyes; paste here only if the auto-connect step above failed."
}
'''


def terraform_autoconnect_snippet(
    external_id: str,
    api_key: str,
    api_secret: str,
    policy_mode: str = "managed",
) -> str:
    """Self-contained Terraform: creates the read-only role AND wires the
    auto-connect trigger (local_file + data external), so `terraform apply`
    alone completes onboarding — no external module source (this repo is
    private; a git:: source would need creds baked into every client's run),
    no second file to hand the client, no manual ARN paste."""
    if policy_mode not in ("managed", "least-privilege"):
        raise ValueError(f"policy_mode must be 'managed' or 'least-privilege', got {policy_mode!r}")

    trust_json = json.dumps(_trust_policy(external_id))
    if policy_mode == "managed":
        attachments = _enterprise_terraform_attachments()
    else:
        policy_json = json.dumps(least_privilege_policy())
        attachments = (
            'resource "aws_iam_role_policy" "odineyes_least_privilege" {\n'
            '  name   = "OdineyesLeastPrivilege"\n'
            '  role   = aws_iam_role.odineyes_readonly.id\n'
            f'  policy = jsonencode({policy_json})\n'
            '}'
        )

    api_url = os.environ.get("ODINEYES_API_URL", "http://localhost:8000")

    # .replace(), not str.format()/f-string: the HCL template and trigger.py
    # source are both full of literal { } braces — interpolation would require
    # doubling every one of them. Plain substring replace sidesteps that.
    return (
        _AUTOCONNECT_TEMPLATE
        .replace("ROLE_NAME__", ROLE_NAME)
        .replace("TRUST_JSON__", trust_json)
        .replace("ATTACHMENTS__", attachments)
        .replace("TRIGGER_PY__", _TRIGGER_PY_SOURCE)
        .replace("API_URL__", api_url)
        .replace("API_KEY__", api_key)
        .replace("API_SECRET__", api_secret)
        .replace("EXTERNAL_ID__", external_id)
    )


def stackset_cloudformation_template(external_id: str, policy_mode: str = "managed") -> str:
    """Wraps the CloudFormation template in a format suitable for AWS Organizations StackSets.
    This doesn't generate the StackSet itself (since StackSets are created in the management account
    but provision roles in child accounts), but gives the user the raw template body they need."""
    # For now, it's identical to the standard template, but we expose it as a separate function
    # so we can inject StackSet-specific parameters (like OrganizationalUnitIds) if needed later.
    return cloudformation_template(external_id, policy_mode)



if __name__ == "__main__":
    # Offline self-check: no AWS, no env var required (injected directly).
    os.environ["ODINEYES_AWS_ACCOUNT_ID"] = "999999999999"
    eid = "cs-test-external-id"

    cfn = cloudformation_template(eid, "managed")
    assert "arn:aws:iam::999999999999:root" in cfn
    assert eid in cfn
    assert "SecurityAudit" in cfn and "ViewOnlyAccess" in cfn
    assert "!GetAtt OdineyesReadOnly.Arn" in cfn

    cfn_lp = cloudformation_template(eid, "least-privilege")
    assert "OdineyesLeastPrivilege" in cfn_lp
    assert "ec2:DescribeInstances" in cfn_lp

    tf = terraform_snippet(eid, "managed")
    assert eid in tf and "aws_iam_role" in tf and "SecurityAudit" in tf

    tf_lp = terraform_snippet(eid, "least-privilege")
    assert "jsonencode" in tf_lp and "ec2:DescribeInstances" in tf_lp

    del os.environ["ODINEYES_AWS_ACCOUNT_ID"]
    globals()["_caller_account_id"] = lambda: None  # simulate no STS identity
    try:
        cloudformation_template(eid)
        raise AssertionError("should have raised without account id or STS identity")
    except ConfigurationError:
        pass

    print("iac_templates self-check OK: CloudFormation + Terraform, both policy modes")
