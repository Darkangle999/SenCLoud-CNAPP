"""Post-connection permission validation (ported from CSPM-v2 ``cspm.validator``).

A role that assumes successfully is not a role that can actually collect.
Customers deploy old template versions, attach permissions boundaries, and sit
under SCPs that strip actions the trust policy happily allowed. This probes the
account and reports coverage per domain before the first real scan.

Two kinds of probe:
  * positive  - an action collection depends on; missing it degrades findings
  * negative  - an action the onboarding template's Deny guard must block;
                succeeding is a finding against us, not the customer
"""

from __future__ import annotations

import concurrent.futures
import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

logger = logging.getLogger(__name__)

_DENIAL_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
    "AccessDeniedFault",
    "NotAuthorized",
    "UnauthorizedException",
    "InsufficientPrivilegesException",
    "MissingAuthenticationToken",
}

# Regional services that are simply absent in some partitions or regions.
_UNSUPPORTED_CODES = {
    "InvalidAction",
    "UnknownOperationException",
    "OptInRequired",
    "SubscriptionRequiredException",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
}


@dataclass(frozen=True)
class Probe:
    domain: str
    service: str
    operation: str
    params: dict[str, Any] = field(default_factory=dict)
    # Global-only services must be probed in their home region.
    region: Optional[str] = None
    expect_denied: bool = False
    # A few APIs (s3control, anything account-scoped) require the caller's own
    # account ID as an explicit parameter. It is only known at probe time.
    account_id_param: Optional[str] = None

    def resolved_params(self, account_id: str) -> dict[str, Any]:
        # Some probes need the account id inside a value rather than as its own
        # parameter — a per-customer resource name, so a probe target cannot be
        # squatted once and reused against every tenant.
        params = {
            key: value.format(account_id=account_id)
            if isinstance(value, str) and "{account_id}" in value
            else value
            for key, value in self.params.items()
        }
        if not self.account_id_param:
            return params
        return {**params, self.account_id_param: account_id}


@dataclass
class ProbeResult:
    probe: Probe
    status: str  # ok | denied | unsupported | error
    detail: str = ""

    @property
    def is_problem(self) -> bool:
        if self.probe.expect_denied:
            return self.status == "ok"
        return self.status == "denied"


@dataclass
class ValidationReport:
    account_id: str
    region: str
    results: list[ProbeResult]

    @property
    def healthy(self) -> bool:
        return not any(r.is_problem for r in self.results)

    @property
    def missing_permissions(self) -> list[ProbeResult]:
        return [r for r in self.results if not r.probe.expect_denied and r.status == "denied"]

    @property
    def guard_failures(self) -> list[ProbeResult]:
        return [r for r in self.results if r.probe.expect_denied and r.status == "ok"]

    def coverage_by_domain(self) -> dict[str, tuple[int, int]]:
        """domain -> (passing, total), counting positive probes only."""
        tally: dict[str, list[int]] = {}
        for result in self.results:
            if result.probe.expect_denied:
                continue
            bucket = tally.setdefault(result.probe.domain, [0, 0])
            bucket[1] += 1
            if result.status in ("ok", "unsupported"):
                bucket[0] += 1
        return {domain: (ok, total) for domain, (ok, total) in tally.items()}

    def to_dict(self) -> dict[str, Any]:
        """API shape. Probe detail carries the AWS error code, never credentials."""
        return {
            "account_identifier": self.account_id,
            "region": self.region,
            "healthy": self.healthy,
            "coverage": {
                domain: {"ok": ok, "total": total}
                for domain, (ok, total) in sorted(self.coverage_by_domain().items())
            },
            "missing": [_result_dict(r) for r in self.missing_permissions],
            "guard_failures": [_result_dict(r) for r in self.guard_failures],
        }


def _result_dict(result: ProbeResult) -> dict[str, str]:
    return {
        "domain": result.probe.domain,
        "action": f"{result.probe.service}:{result.probe.operation}",
        "detail": result.detail,
    }


# One representative call per domain. Deliberately cheap, unpaginated, and safe
# to run against a production account.
POSITIVE_PROBES: tuple[Probe, ...] = (
    Probe("identity", "iam", "list_account_aliases", region="us-east-1"),
    Probe("identity", "iam", "get_account_summary", region="us-east-1"),
    Probe("identity", "iam", "list_roles", {"MaxItems": 1}, region="us-east-1"),
    Probe("compute", "ec2", "describe_instances", {"MaxResults": 5}),
    Probe("compute", "ec2", "get_ebs_encryption_by_default"),
    Probe("compute", "autoscaling", "describe_auto_scaling_groups", {"MaxRecords": 1}),
    Probe("network", "ec2", "describe_security_groups", {"MaxResults": 5}),
    Probe("network", "ec2", "describe_vpcs", {"MaxResults": 5}),
    Probe("network", "elbv2", "describe_load_balancers", {"PageSize": 1}),
    Probe("storage", "s3", "list_buckets", region="us-east-1"),
    Probe(
        "storage", "s3control", "get_public_access_block",
        region="us-east-1", account_id_param="AccountId",
    ),
    Probe("storage", "efs", "describe_file_systems", {"MaxItems": 1}),
    Probe("storage", "backup", "list_backup_vaults", {"MaxResults": 1}),
    Probe("containers", "ecs", "list_clusters", {"maxResults": 1}),
    Probe("containers", "eks", "list_clusters", {"maxResults": 1}),
    Probe("containers", "ecr", "describe_repositories", {"maxResults": 1}),
    Probe("serverless", "lambda", "list_functions", {"MaxItems": 1}),
    Probe("serverless", "apigateway", "get_rest_apis", {"limit": 1}),
    Probe("serverless", "stepfunctions", "list_state_machines", {"maxResults": 1}),
    Probe("database", "rds", "describe_db_instances", {"MaxRecords": 20}),
    Probe("database", "dynamodb", "list_tables", {"Limit": 1}),
    Probe("database", "elasticache", "describe_cache_clusters", {"MaxRecords": 20}),
    Probe("database", "redshift", "describe_clusters", {"MaxRecords": 20}),
    Probe("analytics", "athena", "list_work_groups", {"MaxResults": 2}),
    Probe("analytics", "glue", "get_security_configurations", {"MaxResults": 1}),
    Probe("analytics", "kinesis", "list_streams", {"Limit": 1}),
    Probe("analytics", "opensearch", "list_domain_names"),
    Probe("messaging", "sns", "list_topics"),
    Probe("messaging", "sqs", "list_queues", {"MaxResults": 1}),
    Probe("messaging", "events", "list_event_buses", {"Limit": 1}),
    Probe("security", "kms", "list_keys", {"Limit": 1}),
    Probe("security", "secretsmanager", "list_secrets", {"MaxResults": 1}),
    Probe("security", "guardduty", "list_detectors", {"MaxResults": 1}),
    Probe("security", "securityhub", "describe_hub"),
    Probe("security", "accessanalyzer", "list_analyzers", {"maxResults": 1}),
    Probe("security", "acm", "list_certificates", {"MaxItems": 1}),
    Probe("security", "wafv2", "list_web_acls", {"Scope": "REGIONAL", "Limit": 1}),
    Probe("logging", "cloudtrail", "describe_trails"),
    Probe("logging", "logs", "describe_log_groups", {"limit": 1}),
    Probe("logging", "config", "describe_configuration_recorders"),
    Probe("logging", "cloudwatch", "describe_alarms", {"MaxRecords": 1}),
    Probe("edge", "cloudfront", "list_distributions", {"MaxItems": "1"}, region="us-east-1"),
    Probe("edge", "route53", "list_hosted_zones", {"MaxItems": "1"}, region="us-east-1"),
    Probe("governance", "cloudformation", "describe_stacks"),
    Probe("governance", "ssm", "describe_parameters", {"MaxResults": 1}),
    Probe("governance", "organizations", "describe_organization", region="us-east-1"),
    Probe("governance", "sts", "get_caller_identity"),
    Probe("devops", "codebuild", "list_projects"),
    Probe("devops", "codepipeline", "list_pipelines", {"maxResults": 1}),
    Probe("aiml", "sagemaker", "list_notebook_instances", {"MaxResults": 1}),
    Probe("aiml", "bedrock", "list_custom_models", {"maxResults": 1}),
)

# The Deny guard is the load-bearing part of the least-privilege story the
# onboarding template promises. Verify it in the customer's account, not just
# in review.
NEGATIVE_PROBES: tuple[Probe, ...] = (
    Probe("guard", "ssm", "get_parameters_by_path", {"Path": "/", "MaxResults": 1},
          expect_denied=True),
    Probe("guard", "logs", "filter_log_events",
          {"logGroupName": "odineyes-nonexistent-probe", "limit": 1}, expect_denied=True),
    Probe("guard", "ecr", "get_authorization_token", expect_denied=True),
    # The two the product actually promises: CSPM reads configuration, never
    # customer data. Both target a resource that does not exist, so with the
    # Deny in place IAM rejects before the service ever resolves the name,
    # while a missing Deny surfaces as NoSuchBucket / ResourceNotFound — which
    # classifies as "reached", i.e. a reported guard failure.
    # ponytail: the S3 name is per-account because the bucket namespace is
    # global — a fixed name could be squatted to fake a 403 and mask a missing
    # Deny. Per-account raises that cost; a pre-signed canary bucket we own
    # would close it entirely, if this ever needs to be airtight.
    Probe("guard", "s3", "get_object",
          {"Bucket": "odineyes-guard-probe-{account_id}", "Key": "probe"},
          expect_denied=True),
    Probe("guard", "dynamodb", "get_item",
          {"TableName": "odineyes-guard-probe-nonexistent",
           "Key": {"id": {"S": "probe"}}},
          expect_denied=True),
)


class _Clients:
    """boto3 client *creation* is not thread-safe; method calls are. Create once
    per (service, region) under a lock, then share across the probe pool."""

    def __init__(self, session: boto3.Session):
        self._session = session
        self._cache: dict[tuple[str, str], Any] = {}
        self._lock = threading.Lock()

    def get(self, service: str, region: str) -> Any:
        key = (service, region)
        with self._lock:
            client = self._cache.get(key)
            if client is None:
                client = self._session.client(service, region_name=region)
                self._cache[key] = client
            return client


def validate(
    session: boto3.Session,
    account_id: str,
    region: str,
    *,
    probes: Optional[tuple[Probe, ...]] = None,
    include_negative: bool = True,
    max_workers: int = 12,
) -> ValidationReport:
    """Run the probe set against one region of one account. Never raises."""
    selected = list(probes or POSITIVE_PROBES)
    if include_negative and probes is None:
        selected.extend(NEGATIVE_PROBES)

    clients = _Clients(session)
    results: list[ProbeResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_run_probe, clients, account_id, probe, region)
                   for probe in selected]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: (r.probe.domain, r.probe.service, r.probe.operation))
    return ValidationReport(account_id=account_id, region=region, results=results)


def _run_probe(clients: _Clients, account_id: str, probe: Probe, region: str) -> ProbeResult:
    target_region = probe.region or region
    try:
        client = clients.get(probe.service, target_region)
        operation: Callable[..., Any] = getattr(client, probe.operation)
        operation(**probe.resolved_params(account_id))
        return ProbeResult(probe, "ok")
    except ClientError as exc:
        error = exc.response.get("Error", {})
        code, message = error.get("Code", ""), error.get("Message", "")
        if code in _DENIAL_CODES:
            return ProbeResult(probe, "denied", f"{code}: {message}")
        if code in _UNSUPPORTED_CODES:
            return ProbeResult(probe, "unsupported", code)
        # Anything else means the call was authorized and reached the service:
        # "no such resource", "not subscribed", "invalid parameter". That is a
        # pass for permission purposes.
        return ProbeResult(probe, "ok", code)
    except EndpointConnectionError:
        return ProbeResult(probe, "unsupported", "service not available in region")
    except Exception as exc:  # noqa: BLE001 — a probe failure must not abort validation
        logger.debug("probe %s.%s errored: %s", probe.service, probe.operation, exc)
        return ProbeResult(probe, "error", str(exc))


if __name__ == "__main__":
    # Offline self-check: classification and report arithmetic, no AWS.
    class _FakeClient:
        def __init__(self, behaviour):
            self._behaviour = behaviour

        def __getattr__(self, name):
            def call(**_kw):
                outcome = self._behaviour(name)
                if outcome is not None:
                    raise outcome
                return {}
            return call

    def _client_error(code):
        return ClientError({"Error": {"Code": code, "Message": "m"}}, "op")

    class _FakeSession:
        def __init__(self, behaviour):
            self._behaviour = behaviour

        def client(self, service, region_name=None):
            return _FakeClient(lambda op: self._behaviour(service, op))

    probes = (
        Probe("compute", "ec2", "describe_instances"),
        Probe("security", "kms", "list_keys"),
        Probe("edge", "cloudfront", "list_distributions"),
    )
    denied_kms = _FakeSession(
        lambda s, op: _client_error("AccessDenied") if s == "kms"
        else (_client_error("OptInRequired") if s == "cloudfront" else None)
    )
    report = validate(denied_kms, "123456789012", "us-east-1", probes=probes)
    assert not report.healthy, "a denied positive probe must be unhealthy"
    assert [r.probe.service for r in report.missing_permissions] == ["kms"]
    # unsupported counts as covered — an absent regional service is not a gap.
    assert report.coverage_by_domain() == {
        "compute": (1, 1), "security": (0, 1), "edge": (1, 1),
    }

    guard = (Probe("guard", "ssm", "get_parameters_by_path", expect_denied=True),)
    allowed = validate(_FakeSession(lambda s, op: None), "123456789012", "us-east-1",
                       probes=guard)
    assert allowed.guard_failures, "a permitted deny-guard action must be reported"
    assert not allowed.healthy
    blocked = validate(_FakeSession(lambda s, op: _client_error("AccessDeniedException")),
                       "123456789012", "us-east-1", probes=guard)
    assert blocked.healthy and not blocked.guard_failures
    # Guard probes are excluded from coverage — they are not collection surface.
    assert blocked.coverage_by_domain() == {}

    # A non-denial AWS error is still proof of authorization.
    reached = validate(_FakeSession(lambda s, op: _client_error("NoSuchEntity")),
                       "123456789012", "us-east-1", probes=probes[:1])
    assert reached.healthy, "'resource not found' means the call was authorized"

    payload = report.to_dict()
    assert payload["healthy"] is False
    assert payload["missing"][0]["action"] == "kms:list_keys"
    print("onboarding_validator self-check OK")
