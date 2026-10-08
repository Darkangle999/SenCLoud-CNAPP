"""Dynamic, read-only AWS collector for the inventory persistence path.

Dynamically discovers and collects data for all available AWS services (~200) 
using botocore's service models. Preserves native describe_*/list_*/get_* 
dicts to be fed into the normalizer layer as (source_type, raw_dict) pairs.

Every API call is read-only. Each raw dict gets a ``Region`` key injected. 
Critical resources (IAM roles, Lambdas, Secrets) are enriched in place.
"""

from __future__ import annotations

import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from odineyes.cloud.aws_collector import AwsCollector
from odineyes.inventory.collection import CollectionError, CollectionScope
from odineyes.inventory.iam_analysis import analyze_identity_policies

logger = logging.getLogger(__name__)

# Adaptive retry absorbs the throttling a parallel sweep provokes; without it,
# concurrency just trades "slow" for RequestLimitExceeded.
_RETRY = Config(retries={"mode": "adaptive", "max_attempts": 6})

# Expected/noise error codes during a broad sweep — never logged above debug.
_QUIET_CODES = {
    "AccessDeniedException", "AccessDenied", "UnauthorizedOperation",
    "UnrecognizedClientException", "OptInRequired", "NoSuchEntity",
    "InvalidClientTokenId", "InvalidAction",
}

# (source_type, native_raw_dict)
RawResource = tuple[str, dict[str, Any]]


def _client_error_evidence(
    exc: ClientError,
    *,
    absent_codes: tuple[str, ...] = (),
) -> str:
    """Classify a failed enrichment call without turning unknown into unsafe.

    Policy rules may treat ``absent`` as a real configuration state. ``denied``
    and ``error`` are coverage gaps and must not produce a finding.
    """
    code = str((exc.response.get("Error") or {}).get("Code") or "")
    if code in absent_codes:
        return "absent"
    if code in _QUIET_CODES or "AccessDenied" in code or code == "Forbidden":
        return "denied"
    return "error"


def _has_unconditional_wildcard_principal(policy: Any) -> bool:
    """True only for an unconditional Allow statement trusting everyone.

    A wildcard principal constrained by an organization, source account, VPC
    endpoint, or another condition is not equivalent to anonymous public
    access. Conservatively leave those policies for the IAM condition engine.
    """
    if not isinstance(policy, dict):
        return False
    statements = policy.get("Statement") or []
    statements = [statements] if isinstance(statements, dict) else statements
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition"):
            continue
        principal = statement.get("Principal")
        if principal == "*":
            return True
        if not isinstance(principal, dict):
            continue
        aws_principals = principal.get("AWS")
        aws_principals = [aws_principals] if isinstance(aws_principals, str) else aws_principals
        if isinstance(aws_principals, list) and "*" in aws_principals:
            return True
    return False


def _service_trigger_source_arns(policy: Any) -> list[str]:
    """ARNs of the AWS services allowed to invoke this resource.

    An API Gateway integration writes a statement granting
    apigateway.amazonaws.com with the API's ARN pinned in the SourceArn
    condition. That condition is what makes the grant safe as a *permission*
    and is also the only pointer back to the front door, so it is the ARN we
    keep — not the service name, which says nothing about who can reach it.
    """
    if not isinstance(policy, dict):
        return []
    statements = policy.get("Statement") or []
    statements = [statements] if isinstance(statements, dict) else statements
    out: list[str] = []
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if not isinstance(principal, dict) or not principal.get("Service"):
            continue
        condition = statement.get("Condition")
        if not isinstance(condition, dict):
            continue
        for operator in condition.values():
            if not isinstance(operator, dict):
                continue
            source = operator.get("AWS:SourceArn") or operator.get("aws:SourceArn")
            for value in ([source] if isinstance(source, str) else source or []):
                if isinstance(value, str) and value:
                    out.append(value)
    return sorted(set(out))


# Services that are global (e.g. IAM, Route53, CloudFront). We use 'global' 
# instead of a specific region for the injected Region key.
GLOBAL_SERVICES = {
    "iam", "route53", "cloudfront", "s3", "waf", "health", "organizations",
    "budgets", "cur", "support", "iamrolesanywhere", "account",
    # cloudtrail: treated as global here for posture purposes only — a single
    # home-region describe_trails call already returns every trail in the
    # account (default includeShadowTrails behavior), so a per-region sweep
    # would just duplicate multi-region trails once per region.
    "cloudtrail",
}

# Billing/pricing/telemetry firehoses: their list_/describe_ ops return millions
# of rows with zero CSPM-posture value. Skipped wholesale so they never run.
SKIP_SERVICES = {
    "pricing", "ce", "cost-optimization-hub", "compute-optimizer",
    "billing", "freetier", "bcm-data-exports", "marketplacecommerceanalytics",
}

# The production registry: explicit (service, operation, kwargs, source_type) for
# the ops that enumerate ACCOUNT resources AND have a normalizer (see
# inventory/normalizers.py NORMALIZERS). source_type is the canonical asset key
# the spine dispatches on — emitting the op name instead just errors as
# "no normalizer registered". Owner-scoped ops MUST carry their filter or they
# enumerate all of public AWS. ponytail: grow this as normalizers land for new
# resource types, not speculatively. ODINEYES_SCAN_ALL=1 = exhaustive sweep.
def _age_days(dt: datetime) -> int:
    """Whole days between an AWS timestamp and now (UTC). Naive datetimes are
    assumed UTC. Never negative."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - dt).days)


OPERATIONS: list[tuple[str, str, dict[str, Any], str]] = [
    ("ec2", "describe_instances", {}, "aws.ec2.instance"),
    ("ec2", "describe_security_groups", {}, "aws.ec2.security_group"),
    # Supporting network controls are first-class scan evidence. They let the
    # reachability engine prove a path instead of equating an RDS endpoint flag
    # with internet access.
    ("ec2", "describe_subnets", {}, "aws.ec2.subnet"),
    ("ec2", "describe_route_tables", {}, "aws.ec2.route_table"),
    ("ec2", "describe_network_acls", {}, "aws.ec2.network_acl"),
    ("ec2", "describe_internet_gateways", {}, "aws.ec2.internet_gateway"),
    # ENIs prove whether a subnet/VPC is really occupied, including consumers
    # that do not have a dedicated normalizer yet (NAT gateways, endpoints and
    # other AWS-managed network appliances).
    ("ec2", "describe_network_interfaces", {}, "aws.ec2.network_interface"),
    ("s3", "list_buckets", {}, "aws.s3.bucket"),
    ("iam", "list_roles", {}, "aws.iam.role"),
    ("iam", "list_users", {}, "aws.iam.user"),
    ("rds", "describe_db_instances", {}, "aws.rds.db_instance"),
    ("rds", "describe_db_clusters", {}, "aws.rds.db_cluster"),
    ("rds", "describe_db_proxies", {}, "aws.rds.db_proxy"),
    ("lambda", "list_functions", {}, "aws.lambda.function"),
    ("elbv2", "describe_load_balancers", {}, "aws.elbv2.load_balancer"),
    ("secretsmanager", "list_secrets", {}, "aws.secretsmanager.secret"),
    ("redshift", "describe_clusters", {}, "aws.redshift.cluster"),
    ("neptune", "describe_db_clusters", {}, "aws.neptune.cluster"),
    ("docdb", "describe_db_clusters", {}, "aws.docdb.cluster"),
    ("cloudtrail", "describe_trails", {}, "aws.cloudtrail.trail"),
    # Note: botocore's client name is "config", not the AWS CLI's "configservice"
    # subcommand name — get this wrong and get_available_services() silently
    # never contains it, so the op is skipped every scan with no error at all.
    ("config", "describe_configuration_recorders", {}, "aws.config.recorder"),
    ("kms", "list_keys", {}, "aws.kms.key"),
    ("logs", "describe_log_groups", {}, "aws.cloudwatch.log_group"),
    # Container image inventory is independent of runtime vulnerability scans.
    # The repository posture below is available even when images cannot be pulled
    # locally for Trivy analysis.
    ("ecr", "describe_repositories", {}, "aws.ecr.repository"),
    # Storage-at-rest and the classic public-snapshot exposure. OwnerIds=self is
    # mandatory: an unfiltered describe_snapshots enumerates every public
    # snapshot on AWS, not this account's (see DYNAMIC_SKIP_OPS below).
    ("ec2", "describe_volumes", {}, "aws.ec2.volume"),
    ("ec2", "describe_snapshots", {"OwnerIds": ["self"]}, "aws.ec2.snapshot"),
    # VPCs carry the flow-log control and anchor the network graph above the
    # subnet/route-table level.
    ("ec2", "describe_vpcs", {}, "aws.ec2.vpc"),
    ("efs", "describe_file_systems", {}, "aws.efs.file_system"),
    ("sns", "list_topics", {}, "aws.sns.topic"),
    ("apigateway", "get_rest_apis", {}, "aws.apigateway.rest_api"),
]

# Catalog/reference firehose ops nested inside otherwise-relevant services — they
# enumerate all of AWS (public AMIs, the full price/offering/instance-type catalog),
# not your account. Excluded even from the ALL-services sweep.
DYNAMIC_SKIP_OPS = {
    "describe_images", "describe_snapshots", "describe_spot_price_history",
    "describe_reserved_instances_offerings", "describe_instance_types",
    "describe_instance_type_offerings", "describe_regions",
    "describe_availability_zones", "describe_vpc_endpoint_services",
    "describe_managed_prefix_lists", "describe_prefix_lists", "list_metrics",
}

# Stable result keys for the curated registry. Relying on "the first list in
# the response" can accidentally select a metadata/warning list and hand a
# string to a normalizer. Dynamic discovery still uses the conservative
# fallback in ``_extract_items``.
_RESULT_KEYS = {
    "describe_security_groups": "SecurityGroups",
    "describe_subnets": "Subnets",
    "describe_route_tables": "RouteTables",
    "describe_network_acls": "NetworkAcls",
    "describe_internet_gateways": "InternetGateways",
    "describe_network_interfaces": "NetworkInterfaces",
    "list_buckets": "Buckets",
    "list_roles": "Roles",
    "list_users": "Users",
    "describe_db_instances": "DBInstances",
    "describe_db_clusters": "DBClusters",
    "describe_db_proxies": "DBProxies",
    "list_functions": "Functions",
    "describe_load_balancers": "LoadBalancers",
    "list_secrets": "SecretList",
    "describe_clusters": "Clusters",
    "describe_trails": "trailList",
    "describe_configuration_recorders": "ConfigurationRecorders",
    "list_keys": "Keys",
    "describe_log_groups": "logGroups",
    "describe_repositories": "repositories",
    "describe_volumes": "Volumes",
    "describe_snapshots": "Snapshots",
    "describe_vpcs": "Vpcs",
    "describe_file_systems": "FileSystems",
    "list_topics": "Topics",
    "get_rest_apis": "items",
}

# Hard ceiling on items pulled per operation. Stops a single firehose op
# (e.g. cloudwatch list_metrics) from paginating through millions of rows and
# ballooning memory. ponytail: flat cap; make it per-(service,op) if a real
# account legitimately holds >5k of one resource type and we're truncating.
_MAX_ITEMS_PER_OP = 5000

# Enrichment hooks for specific resource types that require multiple API calls 
# to resolve security posture (e.g. public access, admin privileges).
# Keyed on the canonical asset source_type the collector EMITS (not the op name).
ENRICHMENT_TARGETS = {
    "aws.s3.bucket": "_enrich_s3_bucket",
    "aws.iam.role": "_enrich_iam_role",
    "aws.iam.user": "_enrich_iam_user",
    "aws.lambda.function": "_enrich_lambda",
    "aws.secretsmanager.secret": "_enrich_secret",
    "aws.cloudtrail.trail": "_enrich_cloudtrail",
    "aws.config.recorder": "_enrich_config_recorder",
    "aws.kms.key": "_enrich_kms_key",
    "aws.ecr.repository": "_enrich_ecr_repository",
    "aws.ec2.snapshot": "_enrich_ebs_snapshot",
    "aws.ec2.vpc": "_enrich_vpc",
    "aws.efs.file_system": "_enrich_efs_file_system",
    "aws.sns.topic": "_enrich_sns_topic",
    "aws.apigateway.rest_api": "_enrich_rest_api",
}

class AwsRawCollector:
    """Collect native AWS resource dicts dynamically across all services."""

    def __init__(
        self,
        region: str = "us-east-1",
        profile: Optional[str] = None,
        session: Optional[boto3.Session] = None,
        max_workers: Optional[int] = None,
        regions: Optional[list[str]] = None,
    ):
        # `region` is the home/primary region: STS identity, global-service
        # clients, and the fallback when region discovery is unavailable.
        # `regions` is the sweep set; None means "discover every enabled region"
        # at collect time — the shadow-IT default (you can't find rogue resources
        # in a region you never look at).
        self.region = region
        self.session = session or boto3.Session(profile_name=profile, region_name=region)
        if max_workers is None:
            try:
                configured_workers = int(os.environ.get("ODINEYES_SCAN_WORKERS", "32"))
            except ValueError:
                logger.warning("Invalid ODINEYES_SCAN_WORKERS; using 32")
                configured_workers = 32
        else:
            configured_workers = max_workers
        # Protect the scanner host and AWS API quotas from accidental values such
        # as 0 or several thousand workers.
        self.max_workers = min(max(configured_workers, 1), 64)
        self._regions = regions

        # Rebuilt for every collect(). A scope is added only after its listing
        # operation completes without an API error or pagination truncation.
        self.authoritative_scopes: set[CollectionScope] = set()
        self.collection_errors: list[CollectionError] = []

        # Service clients cached per (service, region) — the same service in two
        # regions is two distinct endpoints.
        self._client_cache: dict[str, Any] = {}
        self._managed_policy_document_cache: dict[str, Any] = {}
        self.sts = self.session.client("sts", region_name=region)

    def _get_client(self, service_name: str, region: Optional[str] = None) -> Any:
        region = region or self.region
        key = f"{service_name}@{region}"
        if key not in self._client_cache:
            self._client_cache[key] = self.session.client(
                service_name, region_name=region, config=_RETRY
            )
        return self._client_cache[key]

    def discover_regions(self) -> list[str]:
        """Every region this account has enabled (opt-in-not-required + opted-in).
        Falls back to the home region if the call is denied/unavailable, so a
        scan never silently collapses to nothing."""
        try:
            ec2 = self._get_client("ec2", self.region)
            resp = ec2.describe_regions(
                Filters=[{"Name": "opt-in-status",
                          "Values": ["opt-in-not-required", "opted-in"]}]
            )
            names = sorted(r["RegionName"] for r in resp.get("Regions", []) if r.get("RegionName"))
            return names or [self.region]
        except Exception as e:  # noqa: BLE001 — denied/offline/fake-session: home region only
            logger.debug("region discovery failed (%s); scanning home region %s only", e, self.region)
            return [self.region]

    # -- identity --------------------------------------------------
    def account_id(self) -> str:
        try:
            return self.sts.get_caller_identity().get("Account", "unknown")
        except ClientError as e:
            logger.error("get_caller_identity failed: %s", e)
            return "unknown"

    # -- full collect ---------------------------------------------
    def resolve_regions(self) -> list[str]:
        """The sweep set: explicit `regions` if given, else every enabled region."""
        return self._regions if self._regions is not None else self.discover_regions()

    def collect(self) -> list[RawResource]:
        """Default: the explicit OPERATIONS registry (fast, safe). Set
        ODINEYES_SCAN_ALL=1 for the exhaustive ~200-service sweep. Both
        sweep every region in `resolve_regions()`; global services (IAM/S3/…)
        are collected once, regional services once per region."""
        self.authoritative_scopes.clear()
        self.collection_errors.clear()
        self._managed_policy_document_cache.clear()
        regions = self.resolve_regions()
        logger.info("Collecting across %d region(s): %s", len(regions), ", ".join(regions))
        if os.environ.get("ODINEYES_SCAN_ALL", "").lower() in ("1", "true", "yes"):
            return self._collect_dynamic(regions)
        return self._collect_registry(regions)

    def _collect_registry(self, regions: list[str]) -> list[RawResource]:
        available = set(self.session.get_available_services())
        work: list[tuple] = []
        for service_name, snake_op, kwargs, source_type in OPERATIONS:
            if service_name not in available:
                self.collection_errors.append(CollectionError(
                    source_type=source_type,
                    operation=f"{service_name}.{snake_op}",
                    message="service is unavailable in the installed AWS SDK",
                ))
                continue
            # Global services live outside any region — collect them once
            # (label "global"); regional services run once per region.
            op_regions = ["global"] if service_name in GLOBAL_SERVICES else regions
            for region in op_regions:
                client_region = self.region if region == "global" else region
                try:
                    client = self._get_client(service_name, client_region)
                except Exception as e:
                    logger.error("Skip %s@%s (client init): %s", service_name, region, e)
                    self.collection_errors.append(CollectionError(
                        source_type=source_type,
                        operation=f"{service_name}.{snake_op}",
                        region=None if region == "global" else region,
                        message=f"client initialization failed: {e}",
                    ))
                    continue
                work.append((client, service_name, snake_op, source_type, kwargs, region))
        logger.info("Registry scan: %d operations, %d workers.", len(work), self.max_workers)
        resources = self._run_parallel(work)
        # These APIs list identifiers rather than resource documents. The generic
        # registry deliberately accepts only dictionaries, so collect the parent
        # list and child describe calls here instead of silently producing an
        # authoritative-but-empty scope.
        resources.extend(self._collect_ecs_clusters(regions, available))
        resources.extend(self._collect_ecs_task_definitions(regions, available))
        resources.extend(self._collect_eks_clusters(regions, available))
        resources.extend(self._collect_sqs_queues(regions, available))
        resources.extend(self._collect_dynamodb_tables(regions, available))
        resources.extend(self._collect_guardduty_detectors(regions, available))
        resources.extend(self._collect_iam_account_settings(available))
        return resources

    def _collect_ecs_clusters(
        self,
        regions: list[str],
        available_services: set[str],
    ) -> list[RawResource]:
        """Collect ECS clusters through ListClusters then DescribeClusters.

        ``ListClusters`` returns ARNs, not dictionaries. Enriching each batch
        with ``DescribeClusters`` obtains the posture fields and tags consumed by
        ``normalize_ecs_cluster``. A failed detail call leaves the scope
        non-authoritative, preventing reconciliation from deleting real assets.
        """
        source_type = "aws.ecs.cluster"
        if "ecs" not in available_services:
            self.collection_errors.append(CollectionError(
                source_type=source_type,
                operation="ecs.ListClusters",
                message="service is unavailable in the installed AWS SDK",
            ))
            return []

        resources: list[RawResource] = []
        for region in regions:
            try:
                client = self._get_client("ecs", region)
                paginator = client.get_paginator("list_clusters")
                arns: list[str] = []
                for page in paginator.paginate(
                    PaginationConfig={"MaxItems": _MAX_ITEMS_PER_OP}
                ):
                    remaining = _MAX_ITEMS_PER_OP - len(arns)
                    arns.extend(str(arn) for arn in page.get("clusterArns", [])[:remaining])
                    if len(arns) >= _MAX_ITEMS_PER_OP:
                        break

                if len(arns) >= _MAX_ITEMS_PER_OP:
                    self.collection_errors.append(CollectionError(
                        source_type=source_type,
                        operation="ecs.ListClusters",
                        region=region,
                        message=f"result exceeded the {_MAX_ITEMS_PER_OP}-item safety limit",
                    ))
                    continue

                detail_failed = False
                for start in range(0, len(arns), 100):
                    response = client.describe_clusters(
                        clusters=arns[start:start + 100],
                        include=["SETTINGS", "TAGS"],
                    )
                    failures = response.get("failures", [])
                    if failures:
                        detail_failed = True
                        self.collection_errors.append(CollectionError(
                            source_type=source_type,
                            operation="ecs.DescribeClusters",
                            region=region,
                            message=(
                                "DescribeClusters returned "
                                f"{len(failures)} resource failure(s)"
                            ),
                        ))
                    for cluster in response.get("clusters", []):
                        if not isinstance(cluster, dict):
                            continue
                        cluster["Region"] = region
                        resources.append((source_type, cluster))
                if not detail_failed:
                    self.authoritative_scopes.add((source_type, region))
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                self.collection_errors.append(CollectionError(
                    source_type=source_type,
                    operation="ecs.ListClusters+DescribeClusters",
                    region=region,
                    message=f"{code or 'ClientError'}: {exc}",
                ))
            except Exception as exc:  # noqa: BLE001 - SDK/model/client failures become scan evidence
                self.collection_errors.append(CollectionError(
                    source_type=source_type,
                    operation="ecs.ListClusters+DescribeClusters",
                    region=region,
                    message=str(exc),
                ))
        return resources

    def _collect_ecs_task_definitions(
        self,
        regions: list[str],
        available_services: set[str],
    ) -> list[RawResource]:
        """Collect active ECS task definitions through list then describe calls.

        Task definitions contain the workload identity and container-security
        posture that an ECS cluster record deliberately does not expose.  Only
        active revisions are relevant to current cloud exposure.
        """
        source_type = "aws.ecs.task_definition"
        if "ecs" not in available_services:
            self.collection_errors.append(CollectionError(
                source_type=source_type,
                operation="ecs.ListTaskDefinitions",
                message="service is unavailable in the installed AWS SDK",
            ))
            return []

        resources: list[RawResource] = []
        for region in regions:
            try:
                client = self._get_client("ecs", region)
                paginator = client.get_paginator("list_task_definitions")
                arns: list[str] = []
                for page in paginator.paginate(
                    status="ACTIVE",
                    PaginationConfig={"MaxItems": _MAX_ITEMS_PER_OP},
                ):
                    remaining = _MAX_ITEMS_PER_OP - len(arns)
                    arns.extend(
                        str(arn) for arn in page.get("taskDefinitionArns", [])[:remaining]
                    )
                    if len(arns) >= _MAX_ITEMS_PER_OP:
                        break

                if len(arns) >= _MAX_ITEMS_PER_OP:
                    self.collection_errors.append(CollectionError(
                        source_type=source_type,
                        operation="ecs.ListTaskDefinitions",
                        region=region,
                        message=f"result exceeded the {_MAX_ITEMS_PER_OP}-item safety limit",
                    ))
                    continue

                detail_failed = False
                for arn in arns:
                    try:
                        response = client.describe_task_definition(taskDefinition=arn)
                    except ClientError as exc:
                        detail_failed = True
                        code = exc.response.get("Error", {}).get("Code", "")
                        self.collection_errors.append(CollectionError(
                            source_type=source_type,
                            operation="ecs.DescribeTaskDefinition",
                            region=region,
                            message=f"{code or 'ClientError'}: {exc}",
                        ))
                        continue
                    task_definition = response.get("taskDefinition")
                    if not isinstance(task_definition, dict):
                        detail_failed = True
                        self.collection_errors.append(CollectionError(
                            source_type=source_type,
                            operation="ecs.DescribeTaskDefinition",
                            region=region,
                            message="response did not contain a taskDefinition document",
                        ))
                        continue
                    try:
                        task_definition["tags"] = client.list_tags_for_resource(
                            resourceArn=arn
                        ).get("tags") or []
                    except ClientError as exc:
                        detail_failed = True
                        code = exc.response.get("Error", {}).get("Code", "")
                        self.collection_errors.append(CollectionError(
                            source_type=source_type,
                            operation="ecs.ListTagsForResource",
                            region=region,
                            message=f"{code or 'ClientError'}: {exc}",
                        ))
                        task_definition["tags"] = []
                    task_definition["Region"] = region
                    resources.append((source_type, task_definition))
                if not detail_failed:
                    self.authoritative_scopes.add((source_type, region))
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                self.collection_errors.append(CollectionError(
                    source_type=source_type,
                    operation="ecs.ListTaskDefinitions+DescribeTaskDefinition",
                    region=region,
                    message=f"{code or 'ClientError'}: {exc}",
                ))
            except Exception as exc:  # noqa: BLE001 - preserve collection evidence
                self.collection_errors.append(CollectionError(
                    source_type=source_type,
                    operation="ecs.ListTaskDefinitions+DescribeTaskDefinition",
                    region=region,
                    message=str(exc),
                ))
        return resources

    def _collect_eks_clusters(
        self,
        regions: list[str],
        available_services: set[str],
    ) -> list[RawResource]:
        """Collect EKS clusters through ListClusters then DescribeCluster.

        EKS returns cluster names from the list operation.  The per-cluster
        describe response carries endpoint, encryption, logging, IAM, VPC and
        access configuration needed for posture evaluation.
        """
        source_type = "aws.eks.cluster"
        if "eks" not in available_services:
            self.collection_errors.append(CollectionError(
                source_type=source_type,
                operation="eks.ListClusters",
                message="service is unavailable in the installed AWS SDK",
            ))
            return []

        resources: list[RawResource] = []
        for region in regions:
            try:
                client = self._get_client("eks", region)
                paginator = client.get_paginator("list_clusters")
                names: list[str] = []
                for page in paginator.paginate(
                    PaginationConfig={"MaxItems": _MAX_ITEMS_PER_OP}
                ):
                    remaining = _MAX_ITEMS_PER_OP - len(names)
                    names.extend(str(name) for name in page.get("clusters", [])[:remaining])
                    if len(names) >= _MAX_ITEMS_PER_OP:
                        break

                if len(names) >= _MAX_ITEMS_PER_OP:
                    self.collection_errors.append(CollectionError(
                        source_type=source_type,
                        operation="eks.ListClusters",
                        region=region,
                        message=f"result exceeded the {_MAX_ITEMS_PER_OP}-item safety limit",
                    ))
                    continue

                detail_failed = False
                for name in names:
                    try:
                        response = client.describe_cluster(name=name)
                    except ClientError as exc:
                        detail_failed = True
                        code = exc.response.get("Error", {}).get("Code", "")
                        self.collection_errors.append(CollectionError(
                            source_type=source_type,
                            operation="eks.DescribeCluster",
                            region=region,
                            message=f"{code or 'ClientError'}: {exc}",
                        ))
                        continue
                    cluster = response.get("cluster")
                    if not isinstance(cluster, dict):
                        detail_failed = True
                        self.collection_errors.append(CollectionError(
                            source_type=source_type,
                            operation="eks.DescribeCluster",
                            region=region,
                            message="response did not contain a cluster document",
                        ))
                        continue
                    cluster["Region"] = region
                    resources.append((source_type, cluster))
                if not detail_failed:
                    self.authoritative_scopes.add((source_type, region))
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                self.collection_errors.append(CollectionError(
                    source_type=source_type,
                    operation="eks.ListClusters+DescribeCluster",
                    region=region,
                    message=f"{code or 'ClientError'}: {exc}",
                ))
            except Exception as exc:  # noqa: BLE001 - preserve collection evidence
                self.collection_errors.append(CollectionError(
                    source_type=source_type,
                    operation="eks.ListClusters+DescribeCluster",
                    region=region,
                    message=str(exc),
                ))
        return resources

    def _collect_detailed(
        self,
        source_type: str,
        service: str,
        operation: str,
        regions: list[str],
        available_services: set[str],
        fetch: Callable[[Any, str], list[dict[str, Any]]],
    ) -> list[RawResource]:
        """Run a list-then-describe collection callback per region.

        ``fetch(client, region)`` returns resource documents or raises. The
        uniform part — SDK availability, client construction, error capture and
        marking the scope authoritative only on a clean pass — lives here so
        each identifier-list service is just its own few lines of API shape.
        Regions may contain the sentinel ``"global"`` for account-wide data.
        """
        if service not in available_services:
            self.collection_errors.append(CollectionError(
                source_type=source_type,
                operation=f"{service}.{operation}",
                message="service is unavailable in the installed AWS SDK",
            ))
            return []

        resources: list[RawResource] = []
        for region in regions:
            scope_region = None if region == "global" else region
            try:
                client = self._get_client(service, self.region if region == "global" else region)
                for document in fetch(client, region):
                    document["Region"] = region
                    resources.append((source_type, document))
                self.authoritative_scopes.add((source_type, scope_region))
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                self.collection_errors.append(CollectionError(
                    source_type=source_type,
                    operation=f"{service}.{operation}",
                    region=scope_region,
                    message=f"{code or 'ClientError'}: {exc}",
                ))
            except Exception as exc:  # noqa: BLE001 - preserve collection evidence
                self.collection_errors.append(CollectionError(
                    source_type=source_type,
                    operation=f"{service}.{operation}",
                    region=scope_region,
                    message=str(exc),
                ))
        return resources

    def _collect_sqs_queues(
        self, regions: list[str], available_services: set[str]
    ) -> list[RawResource]:
        """ListQueues returns URLs; every posture field (policy, KMS key,
        encryption) is in GetQueueAttributes."""
        def fetch(client: Any, _region: str) -> list[dict[str, Any]]:
            urls: list[str] = []
            for page in client.get_paginator("list_queues").paginate(
                PaginationConfig={"MaxItems": _MAX_ITEMS_PER_OP}
            ):
                urls.extend(str(u) for u in page.get("QueueUrls", []) or [])
            queues: list[dict[str, Any]] = []
            for url in urls[:_MAX_ITEMS_PER_OP]:
                attributes = client.get_queue_attributes(
                    QueueUrl=url, AttributeNames=["All"]
                ).get("Attributes", {}) or {}
                queues.append({
                    "QueueUrl": url,
                    "QueueArn": attributes.get("QueueArn"),
                    "Attributes": attributes,
                    "KmsMasterKeyId": attributes.get("KmsMasterKeyId"),
                    "SqsManagedSseEnabled": attributes.get("SqsManagedSseEnabled") == "true",
                    "PublicPolicy": _has_unconditional_wildcard_principal(
                        json.loads(attributes.get("Policy") or "{}")
                    ),
                    "_Evidence": {"attributes": "observed", "resource_policy": "observed"},
                })
            return queues

        return self._collect_detailed(
            "aws.sqs.queue", "sqs", "ListQueues+GetQueueAttributes",
            regions, available_services, fetch,
        )

    def _collect_dynamodb_tables(
        self, regions: list[str], available_services: set[str]
    ) -> list[RawResource]:
        """ListTables returns names. Encryption and deletion protection come
        from DescribeTable; point-in-time recovery is a separate call."""
        def fetch(client: Any, _region: str) -> list[dict[str, Any]]:
            names: list[str] = []
            for page in client.get_paginator("list_tables").paginate(
                PaginationConfig={"MaxItems": _MAX_ITEMS_PER_OP}
            ):
                names.extend(str(n) for n in page.get("TableNames", []) or [])
            tables: list[dict[str, Any]] = []
            for name in names[:_MAX_ITEMS_PER_OP]:
                table = client.describe_table(TableName=name).get("Table")
                if not isinstance(table, dict):
                    raise TypeError(f"describe_table({name}) returned no Table document")
                evidence = {"encryption": "observed"}
                try:
                    backups = client.describe_continuous_backups(
                        TableName=name
                    ).get("ContinuousBackupsDescription", {}) or {}
                    table["_PitrStatus"] = (
                        backups.get("PointInTimeRecoveryDescription", {}) or {}
                    ).get("PointInTimeRecoveryStatus")
                    evidence["point_in_time_recovery"] = "observed"
                except ClientError as exc:
                    table["_PitrStatus"] = None
                    evidence["point_in_time_recovery"] = _client_error_evidence(exc)
                table["_Evidence"] = evidence
                tables.append(table)
            return tables

        return self._collect_detailed(
            "aws.dynamodb.table", "dynamodb", "ListTables+DescribeTable",
            regions, available_services, fetch,
        )

    def _collect_guardduty_detectors(
        self, regions: list[str], available_services: set[str]
    ) -> list[RawResource]:
        """A region with threat detection switched off has no detector at all,
        so absence is itself the finding — see rule_guardduty_not_enabled."""
        def fetch(client: Any, _region: str) -> list[dict[str, Any]]:
            ids: list[str] = []
            for page in client.get_paginator("list_detectors").paginate(
                PaginationConfig={"MaxItems": _MAX_ITEMS_PER_OP}
            ):
                ids.extend(str(d) for d in page.get("DetectorIds", []) or [])
            detectors: list[dict[str, Any]] = []
            for detector_id in ids[:_MAX_ITEMS_PER_OP]:
                detector = client.get_detector(DetectorId=detector_id)
                detector.pop("ResponseMetadata", None)
                detector["DetectorId"] = detector_id
                detector["_Evidence"] = {"detector_status": "observed"}
                detectors.append(detector)
            return detectors

        return self._collect_detailed(
            "aws.guardduty.detector", "guardduty", "ListDetectors+GetDetector",
            regions, available_services, fetch,
        )

    def _collect_iam_account_settings(
        self, available_services: set[str]
    ) -> list[RawResource]:
        """The account-wide IAM controls (root credentials, password policy)
        that CIS section 1 checks. They belong to no resource, so they become a
        single global pseudo-asset rules can attach findings to."""
        def fetch(client: Any, _region: str) -> list[dict[str, Any]]:
            summary = client.get_account_summary().get("SummaryMap", {}) or {}
            evidence = {"account_summary": "observed"}
            try:
                password_policy = client.get_account_password_policy().get(
                    "PasswordPolicy", {}
                ) or {}
                evidence["password_policy"] = "observed"
            except ClientError as exc:
                password_policy = {}
                evidence["password_policy"] = _client_error_evidence(
                    exc, absent_codes=("NoSuchEntity", "NoSuchEntityException")
                )
            return [{
                "AccountId": self.account_id(),
                "SummaryMap": summary,
                "PasswordPolicy": password_policy,
                "_Evidence": evidence,
            }]

        return self._collect_detailed(
            "aws.iam.account_settings", "iam",
            "GetAccountSummary+GetAccountPasswordPolicy",
            ["global"], available_services, fetch,
        )

    def _collect_dynamic(self, regions: list[str]) -> list[RawResource]:
        """Exhaustive sweep: every no-arg describe_/list_ across all services and
        all regions, minus the billing/firehose denylists. Inherently slow + heavy
        — breadth over latency. Client creation is serial (not thread-safe); only
        the calls are parallel. Global services are enumerated once."""
        available = sorted(set(self.session.get_available_services()))
        logger.info("Dynamic ALL-services sweep: %d services × %d region(s).",
                    len(available), len(regions))
        work: list[tuple] = []
        for service_name in available:
            if service_name in SKIP_SERVICES:
                continue
            op_regions = ["global"] if service_name in GLOBAL_SERVICES else regions
            global_ok = self._global_safe_ops(service_name)
            for region in op_regions:
                client_region = self.region if region == "global" else region
                try:
                    client = self._get_client(service_name, client_region)
                except Exception as e:
                    logger.error("Skip service %s@%s (client init): %s", service_name, region, e)
                    self.collection_errors.append(CollectionError(
                        source_type=f"aws.{service_name}.*",
                        operation=f"{service_name}.client",
                        region=None if region == "global" else region,
                        message=f"client initialization failed: {e}",
                    ))
                    continue
                sm = client.meta.service_model
                for snake_op, pascal_op in client.meta.method_to_api_mapping.items():
                    if not snake_op.startswith(("describe_", "list_")):
                        continue
                    if snake_op in DYNAMIC_SKIP_OPS:
                        continue
                    if service_name in GLOBAL_SERVICES and snake_op not in global_ok:
                        continue
                    # Skip ops needing params we can't supply (no resource ID to guess).
                    om = sm.operation_model(pascal_op)
                    if om.input_shape and om.input_shape.required_members:
                        continue
                    work.append((client, service_name, snake_op,
                                 f"aws.{service_name}.{snake_op}", {}, region))
        logger.info("Dynamic scan: %d operations, %d workers.", len(work), self.max_workers)
        return self._run_parallel(work)

    def _run_parallel(self, work: list[tuple]) -> list[RawResource]:
        # Network-bound work scales near-linearly with threads until AWS throttles
        # (absorbed by adaptive retry). Results extended on the main thread — no
        # shared mutable state across workers.
        out: list[RawResource] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futs = {
                pool.submit(self._fetch_operation, c, s, sn, st, kw, rg): (s, sn, st, rg)
                for (c, s, sn, st, kw, rg) in work
            }
            for fut in as_completed(futs):
                s, sn, source_type, rg = futs[fut]
                scope_region = None if rg == "global" else rg
                try:
                    resources, complete = fut.result()
                    out.extend(resources)
                    if complete:
                        self.authoritative_scopes.add((source_type, scope_region))
                    else:
                        self.collection_errors.append(CollectionError(
                            source_type=source_type,
                            operation=f"{s}.{sn}",
                            region=scope_region,
                            message=f"result exceeded the {_MAX_ITEMS_PER_OP}-item safety limit",
                        ))
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "")
                    if code not in _QUIET_CODES:
                        logger.debug("Failed %s.%s@%s: %s", s, sn, rg, e)
                    self.collection_errors.append(CollectionError(
                        source_type=source_type,
                        operation=f"{s}.{sn}",
                        region=scope_region,
                        message=f"{code or 'ClientError'}: {e}",
                    ))
                except Exception as e:  # endpoint-unreachable, parse errors, etc.
                    logger.debug("Failed %s.%s@%s: %s", s, sn, rg, e)
                    self.collection_errors.append(CollectionError(
                        source_type=source_type,
                        operation=f"{s}.{sn}",
                        region=scope_region,
                        message=str(e),
                    ))
        return out

    def _global_safe_ops(self, service_name: str) -> set[str]:
        """Return specific global ops we want to run even if service is global."""
        if service_name == "iam":
            return {"list_roles", "list_users", "list_groups", "list_policies"}
        if service_name == "s3":
            return {"list_buckets"}
        return set()

    def _fetch_operation(
        self, client: Any, service_name: str, snake_op: str, source_type: str,
        kwargs: Optional[dict[str, Any]] = None, region: Optional[str] = None,
    ) -> tuple[list[RawResource], bool]:
        out: list[RawResource] = []
        items_seen = 0
        kwargs = kwargs or {}
        # "global" for region-less services; the swept region otherwise.
        region = region or ("global" if service_name in GLOBAL_SERVICES else self.region)

        try:
            if client.can_paginate(snake_op):
                paginator = client.get_paginator(snake_op)
                # Bound pagination — stop following NextToken past MAX_ITEMS.
                pages = paginator.paginate(
                    PaginationConfig={"MaxItems": _MAX_ITEMS_PER_OP}, **kwargs)
            else:
                pages = [getattr(client, snake_op)(**kwargs)]

            for page in pages:
                items = self._extract_items(page, snake_op)
                items_seen += len(items)
                for index, item in enumerate(items):
                    if not isinstance(item, dict):
                        raise TypeError(
                            f"{snake_op} returned a non-object resource at index "
                            f"{index}: {type(item).__name__}"
                        )
                    # Drop dead EC2 instances early. Only instances model State
                    # as an object — volumes/snapshots/VPCs use a plain string,
                    # so the isinstance guard is what keeps this from raising
                    # AttributeError and losing the whole operation.
                    state = item.get("State")
                    if (service_name == "ec2" and isinstance(state, dict)
                            and state.get("Name") in {"terminated", "shutting-down"}):
                        continue
                    item["Region"] = region
                    enrichment_method = ENRICHMENT_TARGETS.get(source_type)
                    if enrichment_method and hasattr(self, enrichment_method):
                        try:
                            # Returning False vetoes the item (e.g. an AWS
                            # service-linked role — in the API, but not posture).
                            if getattr(self, enrichment_method)(item, client) is False:
                                continue
                        except Exception as e:  # noqa: BLE001 — enrichment is best-effort:
                            # never drop the asset (or its siblings) over one bad facet.
                            logger.debug("enrich %s failed for %s: %s", enrichment_method, source_type, e)
                    out.append((source_type, item))
        except ClientError:
            raise # Handled by the caller for logging
        # Exactly-at-limit is conservatively non-authoritative: the paginator
        # may have stopped with more results available, and stale inventory is
        # safer than falsely deleting real cloud assets.
        return out, items_seen < _MAX_ITEMS_PER_OP

    @staticmethod
    def _extract_items(page: dict[str, Any], snake_op: str) -> list[Any]:
        """Pull the resource dicts out of an API page. EC2 nests instances under
        Reservations[].Instances[]; everything else is a flat list-of-dicts, so we
        use the curated result key when known and a conservative fallback for
        dynamically discovered operations."""
        if not isinstance(page, dict):
            raise TypeError(f"{snake_op} returned {type(page).__name__}, expected object")
        if snake_op == "describe_instances":
            return [i for r in page.get("Reservations", []) for i in r.get("Instances", [])]
        result_key = _RESULT_KEYS.get(snake_op)
        if result_key is not None:
            value = page.get(result_key, [])
            if value is None:
                return []
            if not isinstance(value, list):
                raise TypeError(
                    f"{snake_op}.{result_key} returned {type(value).__name__}, expected list"
                )
            return value
        lists = [value for value in page.values() if isinstance(value, list)]
        for value in lists:
            if value and isinstance(value[0], dict):
                return value
        # A non-empty scalar list is intentionally returned to the caller so it
        # becomes a non-authoritative scope instead of a false empty success.
        for value in lists:
            if value:
                return value
        for value in page.values():
            if isinstance(value, list):
                return value
        return []

    # -- Enrichment Logic -----------------------------------------
    
    def _s3_regional(self, region: str) -> Any:
        """An S3 client pinned to the bucket's own region, so per-bucket get_bucket_*
        calls don't 301-redirect into a silent false negative (a missed public bucket
        is the one mistake a CSPM can't afford). Cached per region."""
        key = f"s3@{region}"
        if key not in self._client_cache:
            self._client_cache[key] = self.session.client("s3", region_name=region, config=_RETRY)
        return self._client_cache[key]

    @staticmethod
    def _list_iam_values(
        client: Any,
        operation: str,
        result_key: str,
        **kwargs: Any,
    ) -> list[Any]:
        """Read every page of an IAM list operation.

        Identity policies are security evidence, so silently stopping at IAM's
        first page would create false least-privilege conclusions.
        """
        if client.can_paginate(operation):
            pages = client.get_paginator(operation).paginate(**kwargs)
        else:
            pages = [getattr(client, operation)(**kwargs)]
        values: list[Any] = []
        for page in pages:
            page_values = page.get(result_key, [])
            if isinstance(page_values, list):
                values.extend(page_values)
        return values

    def _managed_policy_document(self, iam_client: Any, policy_arn: str) -> Any:
        if policy_arn in self._managed_policy_document_cache:
            return self._managed_policy_document_cache[policy_arn]
        policy = iam_client.get_policy(PolicyArn=policy_arn).get("Policy", {})
        version_id = policy.get("DefaultVersionId")
        document = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id,
        ).get("PolicyVersion", {}).get("Document", {})
        self._managed_policy_document_cache[policy_arn] = document
        return document

    def _managed_policy_entries(
        self,
        iam_client: Any,
        attached_policies: list[Any],
        *,
        source_type: str,
        inherited: bool = False,
        group_name: str = "",
    ) -> tuple[list[dict[str, Any]], bool]:
        entries: list[dict[str, Any]] = []
        complete = True
        for policy in attached_policies:
            if not isinstance(policy, dict):
                complete = False
                continue
            policy_arn = str(policy.get("PolicyArn") or "")
            if not policy_arn:
                complete = False
                continue
            try:
                document = self._managed_policy_document(iam_client, policy_arn)
            except ClientError:
                complete = False
                continue
            entries.append({
                "document": document,
                "source_type": source_type,
                "source_name": str(policy.get("PolicyName") or policy_arn.rsplit("/", 1)[-1]),
                "source_arn": policy_arn,
                "inherited": inherited,
                "group_name": group_name,
            })
        return entries, complete

    def _permissions_boundary(
        self,
        identity: dict[str, Any],
        iam_client: Any,
    ) -> tuple[str, Any | None, str]:
        boundary = identity.get("PermissionsBoundary") or {}
        boundary_arn = str(boundary.get("PermissionsBoundaryArn") or "")
        if not boundary_arn:
            return "", None, "not_configured"
        try:
            return (
                boundary_arn,
                self._managed_policy_document(iam_client, boundary_arn),
                "observed",
            )
        except ClientError as exc:
            return boundary_arn, None, _client_error_evidence(exc)

    def _enrich_s3_bucket(self, bucket: dict[str, Any], s3_client: Any) -> None:
        """Assemble the per-bucket posture ``list_buckets`` omits: real region,
        public-access block, policy IsPublic status, ACL grants, default encryption,
        versioning, policy presence, tags. Each call is independently guarded — a
        bucket missing a facet (no policy / no encryption / no PAB) just keeps that
        facet's safe default rather than dropping the whole bucket."""
        name = bucket.get("Name", "")
        evidence: dict[str, str] = {}
        bucket["_Evidence"] = evidence
        region = "us-east-1"
        try:
            region = s3_client.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            evidence["location"] = "observed"
        except ClientError as exc:
            evidence["location"] = _client_error_evidence(exc)
        bucket["Region"] = region  # override the injected "global" with the true region
        try:
            c = self._s3_regional(region)
        except Exception:  # noqa: BLE001 — odd/legacy LocationConstraint; reuse caller's client
            c = s3_client

        try:
            bucket["PublicAccessBlock"] = c.get_public_access_block(
                Bucket=name).get("PublicAccessBlockConfiguration", {})
            evidence["public_access_block"] = "observed"
        except ClientError as exc:
            bucket["PublicAccessBlock"] = {}
            evidence["public_access_block"] = _client_error_evidence(
                exc, absent_codes=("NoSuchPublicAccessBlockConfiguration",)
            )
        try:
            bucket["PolicyStatus"] = c.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
            evidence["policy_status"] = "observed"
        except ClientError as exc:
            bucket["PolicyStatus"] = {}
            evidence["policy_status"] = _client_error_evidence(exc)
        try:
            bucket["Acl"] = c.get_bucket_acl(Bucket=name)
            evidence["acl"] = "observed"
        except ClientError as exc:
            bucket["Acl"] = {}
            evidence["acl"] = _client_error_evidence(exc)
        try:
            enc = c.get_bucket_encryption(Bucket=name).get("ServerSideEncryptionConfiguration", {})
            alg = (enc.get("Rules") or [{}])[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
            bucket["Encryption"] = {"enabled": bool(alg), "algorithm": alg}
            evidence["encryption"] = "observed"
        except ClientError as exc:
            bucket["Encryption"] = {"enabled": False, "algorithm": None}
            evidence["encryption"] = _client_error_evidence(
                exc, absent_codes=("ServerSideEncryptionConfigurationNotFoundError",)
            )
        try:
            bucket["Versioning"] = c.get_bucket_versioning(Bucket=name).get("Status")
            evidence["versioning"] = "observed"
        except ClientError as exc:
            bucket["Versioning"] = None
            evidence["versioning"] = _client_error_evidence(exc)
        try:
            logging_config = c.get_bucket_logging(Bucket=name)
            bucket["LoggingEnabled"] = bool(logging_config.get("LoggingEnabled"))
            evidence["logging"] = "observed"
        except ClientError as exc:
            bucket["LoggingEnabled"] = None
            evidence["logging"] = _client_error_evidence(exc)
        try:
            bucket["Policy"] = bool(c.get_bucket_policy(Bucket=name).get("Policy"))
            evidence["policy"] = "observed"
        except ClientError as exc:
            bucket["Policy"] = False
            evidence["policy"] = _client_error_evidence(
                exc, absent_codes=("NoSuchBucketPolicy",)
            )
        try:
            ts = c.get_bucket_tagging(Bucket=name).get("TagSet", [])
            bucket["Tags"] = {t["Key"]: t["Value"] for t in ts if "Key" in t}
            evidence["tags"] = "observed"
        except ClientError as exc:
            bucket.setdefault("Tags", {})
            evidence["tags"] = _client_error_evidence(exc, absent_codes=("NoSuchTagSet",))

    def _enrich_iam_role(self, role: dict[str, Any], iam_client: Any) -> Optional[bool]:
        """Attach has_admin / admin_reason / privesc_actions using shared analyzers.
        Returns False to veto AWS service-linked roles (not customer posture)."""
        name = role.get("RoleName", "")
        if role.get("Path", "/").startswith("/aws-service-role/"):
            return False  # AWS-managed service-linked role: not customer posture, drop it

        policy_documents: list[dict[str, Any]] = []
        policy_analysis_complete = True

        try:
            attached = self._list_iam_values(
                iam_client,
                "list_attached_role_policies",
                "AttachedPolicies",
                RoleName=name,
            )
            entries, complete = self._managed_policy_entries(
                iam_client,
                attached,
                source_type="role_managed",
            )
            policy_documents.extend(entries)
            policy_analysis_complete = policy_analysis_complete and complete
        except ClientError:
            policy_analysis_complete = False

        try:
            inline_names = self._list_iam_values(
                iam_client,
                "list_role_policies",
                "PolicyNames",
                RoleName=name,
            )
            for pol_name in inline_names:
                try:
                    document = iam_client.get_role_policy(
                        RoleName=name,
                        PolicyName=pol_name,
                    ).get("PolicyDocument", {})
                    policy_documents.append({
                        "document": document,
                        "source_type": "role_inline",
                        "source_name": str(pol_name),
                    })
                except ClientError:
                    policy_analysis_complete = False
        except ClientError:
            policy_analysis_complete = False

        boundary_arn, boundary_document, boundary_state = self._permissions_boundary(
            role, iam_client,
        )
        if boundary_arn and boundary_state != "observed":
            policy_analysis_complete = False
        role.update(analyze_identity_policies(
            policy_documents,
            boundary_document=boundary_document,
            boundary_arn=boundary_arn,
            boundary_state=boundary_state,
            analysis_complete=policy_analysis_complete,
        ))

        # Preserve the trust side of AssumeRole as well as the permission side.
        # The account id is intrinsic to the role ARN, so this works after the
        # scanner has assumed a customer role and does not depend on ambient STS.
        trust = role.get("AssumeRolePolicyDocument") or {}
        arn = str(role.get("Arn") or "")
        arn_parts = arn.split(":")
        role_account = arn_parts[4] if len(arn_parts) > 4 else None
        assumable_by_ec2, trust_external, principals = AwsCollector._analyze_trust(
            trust, role_account
        )
        role["assumable_by_ec2"] = assumable_by_ec2
        role["trust_external"] = trust_external
        role["trust_principals"] = principals

        # Dormancy: RoleLastUsed (get_role only — list_roles omits it) + age.
        try:
            lu = iam_client.get_role(RoleName=name).get("Role", {}) \
                .get("RoleLastUsed", {}).get("LastUsedDate")
            role["last_used_days"] = _age_days(lu) if lu is not None else None
        except ClientError:
            role["last_used_days"] = None
        created = role.get("CreateDate")
        role["age_days"] = _age_days(created) if created is not None else None

    def _enrich_iam_user(self, user: dict[str, Any], iam_client: Any) -> None:
        """Attach has_admin / privesc_actions / access-key age + MFA for an IAM
        user. Users are the leaked-credential path roles aren't: a role hands out
        temporary STS creds, a user carries long-lived access keys. A privileged
        user with an old, active key is the classic account-takeover primitive."""
        name = user.get("UserName", "")
        policy_documents: list[dict[str, Any]] = []
        policy_analysis_complete = True
        group_names: list[str] = []
        group_arns: list[str] = []

        try:
            attached = self._list_iam_values(
                iam_client,
                "list_attached_user_policies",
                "AttachedPolicies",
                UserName=name,
            )
            entries, complete = self._managed_policy_entries(
                iam_client,
                attached,
                source_type="user_managed",
            )
            policy_documents.extend(entries)
            policy_analysis_complete = policy_analysis_complete and complete
        except ClientError:
            policy_analysis_complete = False

        try:
            inline_names = self._list_iam_values(
                iam_client,
                "list_user_policies",
                "PolicyNames",
                UserName=name,
            )
            for pol_name in inline_names:
                try:
                    document = iam_client.get_user_policy(
                        UserName=name,
                        PolicyName=pol_name,
                    ).get("PolicyDocument", {})
                    policy_documents.append({
                        "document": document,
                        "source_type": "user_inline",
                        "source_name": str(pol_name),
                    })
                except ClientError:
                    policy_analysis_complete = False
        except ClientError:
            policy_analysis_complete = False

        # IAM group policies are inherited identity grants. Omitting them makes
        # a privileged user look least-privileged and breaks role/data edges.
        try:
            groups = self._list_iam_values(
                iam_client,
                "list_groups_for_user",
                "Groups",
                UserName=name,
            )
            for group in groups:
                if not isinstance(group, dict):
                    policy_analysis_complete = False
                    continue
                group_name = str(group.get("GroupName") or "")
                if not group_name:
                    policy_analysis_complete = False
                    continue
                group_names.append(group_name)
                if group.get("Arn"):
                    group_arns.append(str(group["Arn"]))

                try:
                    attached = self._list_iam_values(
                        iam_client,
                        "list_attached_group_policies",
                        "AttachedPolicies",
                        GroupName=group_name,
                    )
                    entries, complete = self._managed_policy_entries(
                        iam_client,
                        attached,
                        source_type="group_managed",
                        inherited=True,
                        group_name=group_name,
                    )
                    policy_documents.extend(entries)
                    policy_analysis_complete = policy_analysis_complete and complete
                except ClientError:
                    policy_analysis_complete = False

                try:
                    group_inline_names = self._list_iam_values(
                        iam_client,
                        "list_group_policies",
                        "PolicyNames",
                        GroupName=group_name,
                    )
                    for policy_name in group_inline_names:
                        try:
                            document = iam_client.get_group_policy(
                                GroupName=group_name,
                                PolicyName=policy_name,
                            ).get("PolicyDocument", {})
                            policy_documents.append({
                                "document": document,
                                "source_type": "group_inline",
                                "source_name": str(policy_name),
                                "inherited": True,
                                "group_name": group_name,
                            })
                        except ClientError:
                            policy_analysis_complete = False
                except ClientError:
                    policy_analysis_complete = False
        except ClientError:
            policy_analysis_complete = False

        boundary_arn, boundary_document, boundary_state = self._permissions_boundary(
            user, iam_client,
        )
        if boundary_arn and boundary_state != "observed":
            policy_analysis_complete = False
        user.update(analyze_identity_policies(
            policy_documents,
            boundary_document=boundary_document,
            boundary_arn=boundary_arn,
            boundary_state=boundary_state,
            analysis_complete=policy_analysis_complete,
        ))
        user["group_names"] = sorted(set(group_names))
        user["group_arns"] = sorted(set(group_arns))

        # Access keys: is any active, and how old is the oldest active one.
        active = False
        max_age = 0
        last_used_days: Optional[int] = None
        try:
            for k in iam_client.list_access_keys(UserName=name).get("AccessKeyMetadata", []):
                if k.get("Status") != "Active":
                    continue
                active = True
                created = k.get("CreateDate")
                if created is not None:
                    max_age = max(max_age, _age_days(created))
                try:
                    lu = iam_client.get_access_key_last_used(
                        AccessKeyId=k.get("AccessKeyId", "")
                    ).get("AccessKeyLastUsed", {}).get("LastUsedDate")
                    if lu is not None:
                        d = _age_days(lu)
                        last_used_days = d if last_used_days is None else min(last_used_days, d)
                except ClientError:
                    pass
        except ClientError:
            pass

        # Console access + MFA (no login profile ⇒ programmatic-only user).
        console = False
        try:
            iam_client.get_login_profile(UserName=name)
            console = True
        except ClientError:
            console = False
        mfa = False
        try:
            mfa = bool(iam_client.list_mfa_devices(UserName=name).get("MFADevices"))
        except ClientError:
            pass

        user["access_key_active"] = active
        user["access_key_max_age_days"] = max_age
        user["access_key_last_used_days"] = last_used_days
        user["console_enabled"] = console
        user["mfa_enabled"] = mfa

        # Dormancy: most-recent of key use + console login (PasswordLastUsed is
        # on the list_users record already) + age.
        pw = user.get("PasswordLastUsed")
        pw_days = _age_days(pw) if pw is not None else None
        activity = [d for d in (last_used_days, pw_days) if d is not None]
        user["last_used_days"] = min(activity) if activity else None
        created = user.get("CreateDate")
        user["age_days"] = _age_days(created) if created is not None else None

    def _enrich_lambda(self, fn: dict[str, Any], lam_client: Any) -> None:
        """Attach FunctionUrlAuthType, PublicPolicy and the ARNs of the services
        allowed to invoke the function.

        A function with no URL and no wildcard principal is not therefore
        unreachable: the common shape is an API Gateway integration, which shows
        up here as a statement granting apigateway.amazonaws.com with the API's
        ARN in the SourceArn condition. Recording those lets the reachability
        layer follow internet -> API Gateway -> Lambda instead of calling the
        function contained.
        """
        name = fn.get("FunctionName", "")
        evidence = fn.setdefault("_Evidence", {})
        try:
            cfg = lam_client.get_function_url_config(FunctionName=name)
            fn["FunctionUrlAuthType"] = cfg.get("AuthType")
        except ClientError:
            fn["FunctionUrlAuthType"] = None

        try:
            policy = json.loads(lam_client.get_policy(FunctionName=name).get("Policy", "{}"))
            fn["PublicPolicy"] = _has_unconditional_wildcard_principal(policy)
            fn["TriggerSourceArns"] = _service_trigger_source_arns(policy)
            evidence["resource_policy"] = "observed"
        except ClientError as exc:
            fn["PublicPolicy"] = False
            fn["TriggerSourceArns"] = []
            # No policy at all is a proven absence; anything else (denied,
            # throttled) is a gap, and the two must not read the same. Without
            # this the reachability layer's evidence gate never opened and every
            # Lambda stayed permanently unverified.
            code = (exc.response or {}).get("Error", {}).get("Code")
            evidence["resource_policy"] = (
                "absent" if code == "ResourceNotFoundException" else "denied"
            )

    def _enrich_cloudtrail(self, trail: dict[str, Any], ct_client: Any) -> None:
        """describe_trails already carries IsMultiRegionTrail, KmsKeyId,
        LogFileValidationEnabled, CloudWatchLogsLogGroupArn, S3BucketName —
        only whether the trail is *currently* logging needs an extra call."""
        name = trail.get("TrailARN") or trail.get("Name", "")
        evidence = trail.setdefault("_Evidence", {})
        try:
            status = ct_client.get_trail_status(Name=name)
            trail["IsLogging"] = bool(status.get("IsLogging"))
            evidence["logging"] = "observed"
        except ClientError as exc:
            trail["IsLogging"] = False
            evidence["logging"] = _client_error_evidence(exc)

        # describe_trails omits tags. They are control context here: the
        # onboarding template marks its regional delivery trail explicitly so
        # tuning does not confuse it with a customer's forensic audit trail.
        list_tags = getattr(ct_client, "list_tags", None)
        if callable(list_tags) and name:
            try:
                tagged = list_tags(ResourceIdList=[name]).get("ResourceTagList", [])
                matching = next(
                    (item for item in tagged if item.get("ResourceId") in {name, trail.get("TrailARN")}),
                    {},
                )
                trail["Tags"] = matching.get("TagsList", []) or []
                evidence["tags"] = "observed"
            except ClientError as exc:
                evidence["tags"] = _client_error_evidence(exc)

    def _enrich_config_recorder(self, recorder: dict[str, Any], config_client: Any) -> None:
        """describe_configuration_recorders returns the recorder's config, not
        whether it's actively recording — that's a separate status call."""
        name = recorder.get("name", "")
        evidence = recorder.setdefault("_Evidence", {})
        try:
            statuses = config_client.describe_configuration_recorder_status(
                ConfigurationRecorderNames=[name] if name else []
            ).get("ConfigurationRecordersStatus", [])
            recorder["_IsRecording"] = bool(statuses[0].get("recording")) if statuses else False
            evidence["recording_status"] = "observed"
        except ClientError as exc:
            recorder["_IsRecording"] = False
            evidence["recording_status"] = _client_error_evidence(exc)

    def _enrich_kms_key(self, key: dict[str, Any], kms_client: Any) -> None:
        """Attach KeyState/KeyManager/KeySpec (list_keys returns only KeyId/KeyArn)
        and, for enabled customer-managed symmetric keys, rotation status —
        get_key_rotation_status raises for AWS-managed/asymmetric/HMAC keys, so
        that call is best-effort and only marks the result 'checked' on success."""
        key_id = key.get("KeyId", "")
        try:
            meta = kms_client.describe_key(KeyId=key_id).get("KeyMetadata", {})
        except ClientError:
            meta = {}
        key["KeyState"] = meta.get("KeyState")
        key["KeyManager"] = meta.get("KeyManager")
        key["KeySpec"] = meta.get("KeySpec") or meta.get("CustomerMasterKeySpec")

        key["RotationEnabled"] = False
        key["RotationChecked"] = False
        if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeyState") == "Enabled":
            try:
                rot = kms_client.get_key_rotation_status(KeyId=key_id)
                key["RotationEnabled"] = bool(rot.get("KeyRotationEnabled"))
                key["RotationChecked"] = True
            except ClientError:
                pass  # asymmetric/HMAC keys don't support rotation — leave unchecked

    def _enrich_ecr_repository(self, repository: dict[str, Any], ecr_client: Any) -> None:
        """Attach repository-policy and lifecycle-policy posture to ECR records.

        ``DescribeRepositories`` already provides encryption, tag mutability and
        scan-on-push configuration. Missing policies are evidence of
        configuration; access denials remain coverage gaps and never fire rules.
        """
        name = repository.get("repositoryName", "")
        evidence = repository.setdefault("_Evidence", {})

        try:
            response = ecr_client.get_repository_policy(repositoryName=name)
            policy = json.loads(response.get("policyText") or "{}")
            repository["UnrestrictedRepositoryPolicy"] = _has_unconditional_wildcard_principal(policy)
            evidence["resource_policy"] = "observed"
        except ClientError as exc:
            repository["UnrestrictedRepositoryPolicy"] = False
            evidence["resource_policy"] = _client_error_evidence(
                exc, absent_codes=("RepositoryPolicyNotFoundException",)
            )
        except json.JSONDecodeError:
            repository["UnrestrictedRepositoryPolicy"] = False
            evidence["resource_policy"] = "error"

        try:
            ecr_client.get_lifecycle_policy(repositoryName=name)
            repository["LifecyclePolicyPresent"] = True
            evidence["lifecycle_policy"] = "observed"
        except ClientError as exc:
            repository["LifecyclePolicyPresent"] = False
            evidence["lifecycle_policy"] = _client_error_evidence(
                exc, absent_codes=("LifecyclePolicyNotFoundException",)
            )

    def _enrich_ebs_snapshot(self, snapshot: dict[str, Any], ec2_client: Any) -> None:
        """Resolve whether the snapshot is shared with everyone.

        ``describe_snapshots`` reports encryption but not sharing. A snapshot
        whose createVolumePermission includes the ``all`` group can be copied by
        any AWS account — the classic silent data-exfiltration path.

        ponytail: one extra call per snapshot. Fine up to the 5k cap; batch by
        snapshot id only if a real account makes this the scan's long pole.
        """
        evidence = snapshot.setdefault("_Evidence", {})
        try:
            perms = ec2_client.describe_snapshot_attribute(
                SnapshotId=snapshot.get("SnapshotId", ""),
                Attribute="createVolumePermission",
            ).get("CreateVolumePermissions", []) or []
            snapshot["IsPublic"] = any(
                isinstance(p, dict) and p.get("Group") == "all" for p in perms
            )
            snapshot["SharedWithAccounts"] = [
                p["UserId"] for p in perms
                if isinstance(p, dict) and p.get("UserId")
            ]
            evidence["share_permissions"] = "observed"
        except ClientError as exc:
            snapshot["IsPublic"] = False
            snapshot["SharedWithAccounts"] = []
            evidence["share_permissions"] = _client_error_evidence(exc)

    def _enrich_vpc(self, vpc: dict[str, Any], ec2_client: Any) -> None:
        """Attach flow-log coverage. ``describe_vpcs`` never carries it, so an
        un-enriched VPC would look identical whether logging is on or off."""
        evidence = vpc.setdefault("_Evidence", {})
        try:
            flow_logs = ec2_client.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc.get("VpcId", "")]}]
            ).get("FlowLogs", []) or []
            vpc["_FlowLogsActive"] = [
                fl for fl in flow_logs
                if isinstance(fl, dict) and fl.get("FlowLogStatus") == "ACTIVE"
            ]
            evidence["flow_logs"] = "observed"
        except ClientError as exc:
            vpc["_FlowLogsActive"] = []
            evidence["flow_logs"] = _client_error_evidence(exc)

    def _enrich_efs_file_system(self, fs: dict[str, Any], efs_client: Any) -> None:
        """Attach the EFS resource policy. A file system with no policy falls
        back to VPC-level access control, which is a real (absent) state — not
        the same as a policy we were denied."""
        evidence = fs.setdefault("_Evidence", {})
        try:
            doc = efs_client.describe_file_system_policy(
                FileSystemId=fs.get("FileSystemId", "")
            ).get("Policy") or "{}"
            fs["PublicPolicy"] = _has_unconditional_wildcard_principal(json.loads(doc))
            evidence["resource_policy"] = "observed"
        except ClientError as exc:
            fs["PublicPolicy"] = False
            evidence["resource_policy"] = _client_error_evidence(
                exc, absent_codes=("PolicyNotFound",)
            )
        except json.JSONDecodeError:
            fs["PublicPolicy"] = False
            evidence["resource_policy"] = "error"

    def _enrich_sns_topic(self, topic: dict[str, Any], sns_client: Any) -> None:
        """``list_topics`` returns only an ARN — every posture field (policy,
        KMS key) comes from get_topic_attributes."""
        evidence = topic.setdefault("_Evidence", {})
        try:
            attrs = sns_client.get_topic_attributes(
                TopicArn=topic.get("TopicArn", "")
            ).get("Attributes", {}) or {}
            topic["Attributes"] = attrs
            topic["KmsMasterKeyId"] = attrs.get("KmsMasterKeyId")
            topic["PublicPolicy"] = _has_unconditional_wildcard_principal(
                json.loads(attrs.get("Policy") or "{}")
            )
            evidence["attributes"] = "observed"
            evidence["resource_policy"] = "observed"
        except ClientError as exc:
            state = _client_error_evidence(exc)
            topic["Attributes"] = {}
            topic["PublicPolicy"] = False
            evidence["attributes"] = state
            evidence["resource_policy"] = state
        except json.JSONDecodeError:
            topic["PublicPolicy"] = False
            evidence["resource_policy"] = "error"

    def _enrich_rest_api(self, api: dict[str, Any], apigw_client: Any) -> None:
        """Attach stages. The API record carries no logging, TLS or cache
        configuration — those are per-stage, and a stage is what is actually
        deployed and reachable."""
        evidence = api.setdefault("_Evidence", {})
        try:
            api["_Stages"] = [
                s for s in apigw_client.get_stages(
                    restApiId=api.get("id", "")
                ).get("item", []) or []
                if isinstance(s, dict)
            ]
            evidence["stages"] = "observed"
        except ClientError as exc:
            api["_Stages"] = []
            evidence["stages"] = _client_error_evidence(exc)

    def _enrich_secret(self, secret: dict[str, Any], secrets_client: Any) -> None:
        """Attach PublicPolicy to Secrets Manager secrets."""
        evidence = secret.setdefault("_Evidence", {})
        try:
            resp = secrets_client.get_resource_policy(SecretId=secret.get("ARN") or secret.get("Name", ""))
            policy = json.loads(resp.get("ResourcePolicy") or "{}")
            secret["PublicPolicy"] = _has_unconditional_wildcard_principal(policy)
            evidence["resource_policy"] = "observed"
        except ClientError as exc:
            secret["PublicPolicy"] = False
            evidence["resource_policy"] = _client_error_evidence(exc)


if __name__ == "__main__":
    # Offline self-check (no AWS; boto3.client() construction here only reads
    # the local botocore JSON model, no network/credentials). Guards three
    # invariants that bit us:
    #  1. every registry op emits a source_type that has a normalizer, else
    #     persist_scan errors it as "no normalizer registered";
    #  2. EC2 instances are flattened out of Reservations (not handed up raw);
    #  3. every service name is a real botocore client and every op name is a
    #     real operation on it — a typo here (e.g. "configservice" instead of
    #     "config") doesn't raise, it just silently vanishes from every future
    #     scan via the `if service_name not in available: continue` guard.
    import boto3 as _boto3

    from odineyes.inventory.normalizers import NORMALIZERS
    seen = set()
    for service, op, kwargs, source_type in OPERATIONS:
        assert isinstance(kwargs, dict), f"{op}: kwargs must be a dict"
        assert source_type in NORMALIZERS, f"{source_type}: no normalizer registered"
        assert (service, op) not in seen, f"duplicate ({service}, {op})"
        seen.add((service, op))
        client = _boto3.client(service, region_name="us-east-1")
        assert hasattr(client, op), f"'{service}' has no operation '{op}' (wrong botocore client name?)"

    _page = {"Reservations": [{"Instances": [{"InstanceId": "i-1"}, {"InstanceId": "i-2"}]}]}
    assert [i["InstanceId"] for i in AwsRawCollector._extract_items(_page, "describe_instances")] == ["i-1", "i-2"]
    assert AwsRawCollector._extract_items({"Buckets": [{"Name": "b"}]}, "list_buckets") == [{"Name": "b"}]
    # Guard the regression this file just fixed: S3 buckets MUST carry a per-bucket
    # enrichment, or every bucket normalizes to is_public=False (public buckets missed).
    assert "aws.s3.bucket" in ENRICHMENT_TARGETS, "S3 buckets need posture enrichment"
    print(f"registry OK: {len(OPERATIONS)} ops, all normalizable, EC2 flatten + S3 enrichment wired")
