"""Alert tuning — the layers between "a rule fired" and "wake someone up".

Every rule in ``rules.py`` answers one question: is this configuration state
present? That is necessary and not sufficient. A private database behind an
open security group, a bucket AWS created for its own CloudFormation plumbing,
a DMZ subnet that is public *by design*, an unencrypted log group holding
nothing but startup text — all four are true detections and none of them are
worth an alert. Shipping them anyway is how a CSPM teaches its users to ignore
it.

Five independent filters, each answering a different reason a true detection is
still not actionable:

  path      the node is misconfigured but the graph path to it is broken.
            Decided at source in ``rules.rule_world_open_sensitive_port``,
            which is where the topology and the attachment map already live.
  managed   the resource is AWS-created plumbing the customer cannot change.
  intent    a tag declares the state deliberate — a DMZ subnet IS public.
  design    the state is topology evidence, not an independently exploitable
            condition. The graph raises the affected workload instead.
  data      the control only earns its cost when sensitive data is present.

Two rules hold throughout:

*Nothing is deleted.* A tuned finding keeps its place in the list with
``suppressed_by`` set, so "why did Odineyes not tell me about this" has an
answer. ``rules.evaluate`` filters them out of the alerting set; the suppressed
set stays queryable.

*Heuristics defer, operators decide.* The managed-resource list is a guess
about AWS's naming conventions, so it never touches a critical finding or a
public-exposure rule — an AWS-created bucket that is world-readable is still a
breach. An explicit ``Odineyes:Suppress`` tag is not a guess, so it is honoured
in full.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Optional, Protocol

# ── layer 2: AWS-managed resources ─────────────────────────────
# Names AWS generates for its own plumbing. The customer did not create these
# and in most cases cannot reconfigure them, so a hygiene finding on one is
# pure noise. Anchored at the start deliberately: a *customer* bucket named
# "prod-cf-templates-backup" is not AWS's and must still be reported.
AWS_MANAGED_NAMES: dict[str, tuple[re.Pattern[str], ...]] = {
    "aws.s3.bucket": (
        re.compile(r"^cf-templates-"),                 # CloudFormation artifacts
        re.compile(r"^elasticbeanstalk-"),             # Beanstalk deployments
        re.compile(r"^aws-athena-query-results-"),     # Athena scratch space
        re.compile(r"^aws-cloudtrail-logs-\d{12}-"),   # AWS-managed trail buckets
        re.compile(r"^aws-glue-assets-"),
        re.compile(r"^aws-sam-cli-managed-"),
        re.compile(r"^amplify-"),
    ),
    "aws.cloudwatch.log_group": (
        re.compile(r"^/aws/lambda/cspm-"),             # Odineyes' own infrastructure
        re.compile(r"^/aws/lambda/odineyes-"),
        re.compile(r"^/aws/lambda/"),                  # unless tagged sensitive — see below
        re.compile(r"^/aws/codebuild/"),
        re.compile(r"^/aws/apigateway/welcome$"),
    ),
}

# Rules that report something reachable from the internet. A managed *name* is
# never a reason to stay quiet about one: AWS naming its bucket does not make
# the bucket's contents less public.
ALWAYS_ALERT = frozenset({
    "PUBLIC_BUCKET", "S3_PUBLIC_ACCESS_BLOCK_INCOMPLETE", "CLOUDTRAIL_S3_PUBLIC",
    "EBS_SNAPSHOT_PUBLIC", "SECRET_PUBLIC_POLICY", "EFS_PUBLIC_POLICY",
    "SNS_TOPIC_PUBLIC_POLICY", "SQS_QUEUE_PUBLIC_POLICY", "PUBLIC_LAMBDA_URL",
    "ECR_UNRESTRICTED_REPOSITORY_POLICY", "PUBLIC_ADMIN_ROLE", "PUBLIC_WAREHOUSE",
})

# ── layer 3: tag-declared intent ───────────────────────────────
SUPPRESS_TAG = "odineyes:suppress"
SENSITIVE_TAG = "odineyes:sensitive"
_TRUE = {"true", "yes", "1", "on"}

# Design-level facts remain in the immutable evidence ledger while staying out
# of the active and network-hygiene queues.
DESIGN_SUPPRESSED_RULES: dict[str, str] = {
    "SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED": (
        "subnet auto-assignment is retained as network topology evidence; it is not "
        "proof that a workload is internet reachable. Graph-backed workload and data "
        "exposure findings carry the actionable risk"
    ),
}

# The onboarding templates tag this dedicated, regional, write-only CloudTrail
# stream. It feeds EventBridge and is not the customer's forensic audit trail.
_ODINEYES_REALTIME_TRAIL = re.compile(r"^odineyes-realtime-\d{12}-[a-z0-9-]+$")
_PIPELINE_TRAIL_RULES = frozenset({"CLOUDTRAIL_NO_CLOUDWATCH", "CLOUDTRAIL_NOT_ENCRYPTED"})
_PIPELINE_TRAIL_REASON = (
    "Odineyes realtime delivery trail - suppressed by design because EventBridge consumes "
    "the regional write-management stream directly. KMS CMK and CloudWatch Logs delivery "
    "would add cost without strengthening this pipeline; evaluate those controls on the "
    "customer's primary audit trail instead"
)

# ── layer 1b: unoccupied subnets ───────────────────────────────
# AWS creates a default VPC in every enabled region and puts three or four
# subnets in each with MapPublicIpOnLaunch already true. A brand new, entirely
# empty account therefore arrives with 50+ of these findings, in regions the
# customer has never used. Nothing launches there, so nothing receives a public
# address, so the risk is zero — and a user who opens Odineyes to 28 alerts for
# regions they do not operate in stops believing the other 200.
#
# Occupancy is deliberately restricted to workloads, data services and active
# network interfaces. Network control-plane resources also carry subnet/VPC
# ids (a default NACL is associated with every default subnet), but topology is
# not a tenant. Counting it as occupancy caused empty default subnets to become
# actionable again as soon as NACL collection was added.
_SUBNET_KEYS = ("subnet_id", "subnet_ids")
_VPC_KEYS = ("vpc_id", "vpc_ids")
_NON_OCCUPANT_TYPES = frozenset({
    "aws.ec2.vpc",
    "aws.ec2.subnet",
    "aws.ec2.security_group",
    "aws.ec2.route_table",
    "aws.ec2.network_acl",
    "aws.ec2.internet_gateway",
})
_TERMINAL_STATES = frozenset({"deleted", "deleting", "terminated", "shutting-down"})


def _is_active_occupant(asset: Any) -> bool:
    """Whether an asset represents something that can currently use a VPC.

    An ENI is the provider-level source of truth for service-managed consumers
    such as NAT gateways, VPC endpoints and Lambda. Unattached ``available``
    ENIs do not make a subnet operational. Other collected workloads count
    unless AWS says they are in a terminal state; stopped instances/databases
    remain occupants because they can start without a network change.
    """
    asset_type = str(getattr(asset, "asset_type", "") or "")
    if asset_type in _NON_OCCUPANT_TYPES:
        return False
    properties = getattr(asset, "properties", {}) or {}
    state = str(properties.get("status") or properties.get("state") or "").lower()
    if asset_type == "aws.ec2.network_interface":
        return state == "in-use"
    return state not in _TERMINAL_STATES


def occupied_subnets(assets: Iterable[Any]) -> set[str]:
    """Subnet ids something is actually running in.

    EC2, RDS, Lambda-in-VPC and load balancers publish their subnets directly.
    Active ENIs cover service-managed consumers such as NAT gateways and VPC
    endpoints without teaching this function every AWS service type.
    """
    out: set[str] = set()
    for asset in assets:
        if not _is_active_occupant(asset):
            continue
        properties = getattr(asset, "properties", {}) or {}
        for key in _SUBNET_KEYS:
            value = properties.get(key)
            for item in ([value] if isinstance(value, str) else value or []):
                if item:
                    out.add(str(item))
    return out


def occupied_vpcs(assets: Iterable[Any]) -> set[str]:
    """VPC ids containing an active workload, data service or in-use ENI."""
    out: set[str] = set()
    for asset in assets:
        if not _is_active_occupant(asset):
            continue
        properties = getattr(asset, "properties", {}) or {}
        for key in _VPC_KEYS:
            value = properties.get(key)
            for item in ([value] if isinstance(value, str) else value or []):
                if item:
                    out.add(str(item))
    return out


def _vpc_id(asset: Any, resource_id: str) -> str:
    """vpc-0abc from either the asset name or the ARN tail."""
    name = str(getattr(asset, "name", "") or "")
    if name.startswith("vpc-"):
        return name
    return resource_id.rsplit("/", 1)[-1]

# Tag values that mark a resource sensitive regardless of what DSPM found.
SENSITIVE_TAG_VALUES = frozenset({"pii", "phi", "pci", "confidential", "restricted", "secret"})
_CLASSIFICATION_TAGS = ("dataclassification", "data-classification", "classification", "sensitivity")

# ── layer 4: DSPM correlation ──────────────────────────────────
# Taxonomies that justify the cost of a customer-managed key. Generic
# application logs do not.
REGULATED_TAXONOMIES = frozenset({"PII", "PHI", "PCI"})

# rule_id -> the severity it drops to when DSPM proves no regulated data is
# present. Downgraded, never dropped: the control gap is real, its urgency is
# not. ponytail: one entry today; the table is here so the second one is a line
# rather than a refactor.
DSPM_GATED_RULES: dict[str, str] = {
    "LOG_GROUP_NOT_ENCRYPTED": "info",
}


class FindingLike(Protocol):
    rule_id: str
    severity: str
    resource_id: str
    asset_type: str
    why: str
    suppressed_by: str
    suppressed_why: str


def _normalize_tags(asset: Any) -> dict[str, str]:
    """Tag keys and values lowercased for comparison.

    AWS tag keys are case-sensitive and humans are not consistent: ``Tier``,
    ``tier`` and ``TIER`` all mean the same thing to the person who typed them.
    Matching case-sensitively here would silently switch this layer off for
    half of real accounts.
    """
    tags = getattr(asset, "tags", None) or {}
    if not isinstance(tags, dict):
        return {}
    return {str(k).strip().lower(): str(v).strip().lower() for k, v in tags.items()}


def _asset_name(asset: Any, resource_id: str) -> str:
    """The name a suppression pattern is written against.

    Not ``rules._short_name``: that splits on ``/`` to pull a role name out of
    an ARN path, which would turn the log group ``/aws/lambda/cspm-api`` into
    ``cspm-api`` and stop every ``^/aws/`` pattern from ever matching.
    """
    name = str(getattr(asset, "name", "") or "")
    if name:
        return name
    # arn:aws:logs:eu-west-1:1:log-group:/aws/lambda/x -> /aws/lambda/x
    if ":log-group:" in resource_id:
        return resource_id.split(":log-group:", 1)[1]
    return resource_id.rsplit(":", 1)[-1]


def is_aws_managed(asset_type: str, name: str) -> bool:
    """Whether a resource name matches AWS's own generated-resource conventions."""
    return any(p.search(name) for p in AWS_MANAGED_NAMES.get(asset_type, ()))


def is_tagged_sensitive(tags: Mapping[str, str]) -> bool:
    """An explicit sensitivity tag, which overrides every heuristic below it."""
    if tags.get(SENSITIVE_TAG, "") in _TRUE:
        return True
    return any(tags.get(key, "") in SENSITIVE_TAG_VALUES for key in _CLASSIFICATION_TAGS)


def is_odineyes_realtime_trail(asset: Any, tags: Mapping[str, str]) -> bool:
    """Recognise only the explicitly tagged Odineyes delivery trail.

    A name check alone is unsafe: a customer could create a lookalike trail.
    A generic tag alone is unsafe too. Both values are emitted by the
    onboarding template and required before a control is tuned.
    """
    return (
        str(getattr(asset, "asset_type", "") or "") == "aws.cloudtrail.trail"
        and bool(_ODINEYES_REALTIME_TRAIL.fullmatch(str(getattr(asset, "name", "") or "")))
        and tags.get("managedby") == "cspm-g3"
        and tags.get("purpose") == "odineyesrealtimecloudtrail"
    )


def _suppress(finding: FindingLike, layer: str, why: str) -> None:
    finding.suppressed_by = layer
    finding.suppressed_why = why


# ── layer 3b: dormant-region suppression ─────────────────────────
# Region-hygiene controls (flow logs, default-VPC subnet posture, ...) are
# meaningless in a region the account has never used. The whole point of the
# global sweep is that dormant regions are safe *because nothing is in them*,
# so a finding there is noise three times over: the region is empty, the
# finding cannot be acted on independently (it is topology evidence), and it
# teaches the operator to ignore every other finding.
#
# The occupancy rule is a strict superset of the existing default-VPC rule
# below, but each layer keeps its own reason so the audit trail stays precise.
REGION_HYGIENE_RULES = frozenset({
    # Default-VPC subnet posture + flow logs are the region-hygiene controls
    # that fire most in empty enabled regions; add to this set only controls
    # whose risk is activity-dependent, never identity/global or exposure rules.
    "SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED",
    "VPC_FLOW_LOGS_DISABLED",
})

# Asset types that themselves count as region activity. Network control-plane
# nodes (default VPC/subnet/NACL/route table/IGW) are the *default* scaffolding
# AWS ships in every empty enabled region, so they must not count — otherwise
# every region looks occupied and the tripwire blindfolds itself.
ACTIVITY_ASSET_TYPES = frozenset({
    "aws.ec2.instance",
    "aws.ec2.network_interface",      # attached/available ENIs
    "aws.rds.db_instance",
    "aws.rds.db_cluster",
    "aws.lambda.function",
    "aws.elasticloadbalancingv2.load_balancer",
    "aws.secretsmanager.secret",
    "aws.redshift.cluster",
    "aws.neptune.db_cluster",
    "aws.docdb.db_cluster",
    "aws.ecs.cluster",                # cluster existence = intent to run tasks
    "aws.ecs.service",
    "aws.config.recorder",            # Config recorder presence = active use
    "aws.kms.key",
    "aws.logs.log_group",
    "aws.s3.bucket",                  # regional via BucketRegion, not sweep-set
    "aws.ec2.volume",
    "aws.ecr.repository",
    "aws.sqs.queue",
    "aws.dynamodb.table",
    "aws.ec2.nat_gateway",
    "aws.ec2.vpc_endpoint",
    "aws.ecs.task_definition",
    "aws.autoscaling.group",
})

# Non-hygiene rules keep ambient-hygiene default-VPC findings in completely
# empty regions suppressed. The "ambient" adjectives are the noise markers;
# every remaining hygiene/network finding (e.g. a real open security group,
# even on an empty VPC) still alerts.
DORMANT_SUPPRESSED_RULES = REGION_HYGIENE_RULES | frozenset({
    "SECURITY_GROUP_OPEN_TO_WORLD",   # wildcard exposure always alerts if real
})


def _asset_region(asset: Any) -> str:
    """Region of an asset: the normalized Region property, else the region
    embedded in its ARN, else ''."""
    region = str(getattr(asset, "region", "") or "").strip()
    if not region:
        properties = getattr(asset, "properties", {}) or {}
        region = str(properties.get("Region", "") or "").strip()
    if not region:
        resource_id = str(getattr(asset, "resource_id", "") or "")
        # arn:aws:logs:eu-west-1:1:log-group:/x -> eu-west-1
        parts = resource_id.split(":")
        if len(parts) >= 4 and parts[0] == "arn":
            region = parts[3]
    return region


def dormant_regions(assets: Iterable[Any]) -> set[str]:
    """Regions with no active compute/data activity.

    A region is dormant when every asset in it is network control-plane
    scaffolding (the default VPC and its subnets/routes/NACLs) or a CloudTrail
    trail. Those are the only things AWS puts into a region the account has
    never used.
    """
    # Two passes, order-independent. A running asset anywhere in a region wins
    # no matter where it sits in the list: the earlier one-pass version let a
    # scaffolding asset iterated *after* an instance re-add the region to the
    # dormant set, which silently re-suppressed findings in the account's
    # busiest regions. Dormancy decides suppression, so it must be a fact,
    # not an iteration accident.
    seen: set[str] = set()
    active: set[str] = set()
    for asset in assets:
        region = _asset_region(asset)
        # "global" (and the empty string) is the pseudo-region for
        # region-independent services - IAM, S3 in the global sense, CloudTrail
        # trails. It is not a real enabled region, so it can never be dormant
        # and must not colour any real region's dormancy: a lone IAM role must
        # not invent an "af-south-1 is in use" or "global is dormant" signal.
        if not region or region == "global":
            continue
        ac = str(getattr(asset, "asset_type", "") or "")
        # CloudTrail trails are neither activity nor scaffolding: they carry
        # no region of their own and a multi-region trail does not prove a
        # region hosts anything. Ignore them entirely.
        if ac == "aws.cloudtrail.trail":
            continue
        seen.add(region)
        if ac in ACTIVITY_ASSET_TYPES:
            active.add(region)
    return seen - active


def apply_tuning(
    findings: Iterable[FindingLike],
    assets: Iterable[Any] = (),
    *,
    dspm_taxonomies: Optional[Mapping[str, Iterable[str]]] = None,
) -> list[FindingLike]:
    """Mark noisy findings in place and return the same list.

    ``dspm_taxonomies`` maps ``finding_risk.store_key`` to the taxonomies the
    DSPM scanner proved present (``{"app-logs": ["PII"]}``). Absent, layer 4
    treats every store as unclassified, which is the honest reading: nothing
    proved regulated data is there, so nothing justifies the alert.
    """
    findings = list(findings)
    assets = list(assets)
    by_id = {str(getattr(a, "resource_id", "")): a for a in assets}
    occupied_networks = occupied_vpcs(assets)
    dormants = dormant_regions(assets)
    trail_assets = [a for a in assets if str(getattr(a, "asset_type", "") or "") == "aws.cloudtrail.trail"]
    only_realtime_pipeline_trails = bool(trail_assets) and all(
        is_odineyes_realtime_trail(a, _normalize_tags(a)) for a in trail_assets
    )
    taxonomies = {
        str(k): {str(t).upper() for t in (v or ())}
        for k, v in (dspm_taxonomies or {}).items()
    }

    for finding in findings:
        if finding.suppressed_by:      # layer 1 already decided at source
            continue

        design_reason = DESIGN_SUPPRESSED_RULES.get(finding.rule_id)
        if design_reason:
            # Keep the raw subnet state for topology and audits. It is not an
            # attacker path by itself, and RDS does not consume this EC2 launch
            # default. Graph-backed workload exposure carries the active risk.
            if finding.severity in {"critical", "high"}:
                finding.severity = "medium"
            _suppress(finding, "design", design_reason)
            continue

        asset = by_id.get(finding.resource_id)
        tags = _normalize_tags(asset) if asset is not None else {}
        name = _asset_name(asset, finding.resource_id) if asset is not None else ""
        sensitive = is_tagged_sensitive(tags)

        if asset is not None and is_odineyes_realtime_trail(asset, tags):
            if finding.rule_id in _PIPELINE_TRAIL_RULES:
                _suppress(finding, "design", _PIPELINE_TRAIL_REASON)
                continue
            if finding.rule_id == "CLOUDTRAIL_NOT_MULTIREGION" and only_realtime_pipeline_trails:
                context = (
                    " The observed Odineyes trail is a regional realtime delivery pipeline, "
                    "not a replacement for a customer-managed multi-region forensic audit trail."
                )
                if context not in finding.why:
                    finding.why += context

        # ── layer 3a: the explicit operator override ──
        # Not a heuristic — someone typed this on purpose, so it outranks
        # everything, including our own severity opinion.
        if tags.get(SUPPRESS_TAG, "") in _TRUE:
            _suppress(finding, "intent", f"{SUPPRESS_TAG} tag is set on the resource")
            continue

        # ── layer 3b: dormant-region suppression ──
        # A hygiene/ambient finding in an entirely unused region is noise: the
        # region is safe because nothing lives there, the finding cannot be
        # acted on independently, and an alert here teaches the operator to
        # ignore every other finding. A sudden non-scaffolding resource in a
        # dormant region is exactly the tripwire the global sweep exists for —
        # and it makes the region non-dormant by construction.
        if (
            asset is not None
            and finding.rule_id in DORMANT_SUPPRESSED_RULES
            and _asset_region(asset) in dormants
        ):
            _suppress(
                finding,
                "path",
                "region is dormant - no active workload, data service or in-use "
                "network interface has ever been collected there; the finding "
                "would be noise until a resource proves the region is in use",
            )
            continue

        # AWS creates one default VPC in each enabled region. Requiring flow
        # logs on an untouched VPC with no active workload, data service or ENI
        # spends money without preserving any traffic evidence. Customer-made
        # VPCs and occupied default VPCs remain actionable.
        if (finding.rule_id == "VPC_FLOW_LOGS_DISABLED"
                and asset is not None
                and bool((getattr(asset, "properties", {}) or {}).get("is_default"))
                and _vpc_id(asset, finding.resource_id) not in occupied_networks):
            _suppress(
                finding,
                "path",
                "empty default VPC - no active workload, data service or in-use network "
                "interface can generate traffic here",
            )
            continue

        # ── layer 2: AWS-managed plumbing ──
        if (finding.rule_id not in ALWAYS_ALERT
                and finding.severity != "critical"
                and not sensitive
                and name and is_aws_managed(finding.asset_type, name)):
            _suppress(finding, "managed",
                      f"'{name}' matches an AWS-generated resource name the customer does not control")
            continue

        # ── layer 4: DSPM correlation ──
        floor = DSPM_GATED_RULES.get(finding.rule_id)
        if floor and not sensitive:
            from odineyes.inventory.finding_risk import store_key

            found = taxonomies.get(store_key(finding.resource_id), set())
            if not (found & REGULATED_TAXONOMIES):
                finding.severity = floor
                finding.why += (
                    " No PII, PHI or PCI has been classified in this store, so the"
                    " encryption gap is recorded for completeness rather than raised"
                    " as an alert — a customer-managed key carries real cost and"
                    " earns it only where regulated data actually flows."
                )

    return findings


def dspm_taxonomies_for_account(session: Any, account_id: int) -> dict[str, list[str]]:
    """Load persisted DSPM taxonomies for one account, keyed for ``store_key``.

    Sibling of ``reachability_layers.data_labels_for_account``: that one answers
    "how sensitive", this one answers "which regime". Layer 4 needs the second —
    a MEDIUM label does not tell you whether a regulator cares.
    """
    from odineyes.db.models import DspmFinding
    from odineyes.inventory.finding_risk import store_key

    rows = session.query(DspmFinding.store_id, DspmFinding.taxonomies).filter(
        DspmFinding.account_id == account_id
    ).all()
    return {store_key(store_id): list(taxonomies or []) for store_id, taxonomies in rows}


if __name__ == "__main__":
    # Offline self-check: the boundary each layer must not cross.
    from dataclasses import dataclass, field

    @dataclass
    class _F:
        rule_id: str
        severity: str
        resource_id: str
        asset_type: str
        why: str = ""
        suppressed_by: str = ""
        suppressed_why: str = ""

    @dataclass
    class _A:
        resource_id: str
        name: str = ""
        tags: dict = field(default_factory=dict)
        asset_type: str = ""
        properties: dict = field(default_factory=dict)

    def _run(finding, asset=None, extra=(), **kw):
        assets = ([asset] if asset else []) + list(extra)
        return apply_tuning([finding], assets, **kw)[0]

    def _occupant(subnet: str):
        """An EC2 instance, so the subnet under test is not read as empty."""
        return _A(f"i-{subnet}", asset_type="aws.ec2.instance",
                  properties={"subnet_id": subnet})

    # Layer 2 mutes AWS plumbing...
    bucket = _A("arn:aws:s3:::cf-templates-1x2y3z-eu-west-1", "cf-templates-1x2y3z-eu-west-1")
    muted = _run(_F("S3_VERSIONING_DISABLED", "low", bucket.resource_id, "aws.s3.bucket"), bucket)
    assert muted.suppressed_by == "managed", muted

    # ...but never a public-exposure finding on the same bucket.
    loud = _run(_F("PUBLIC_BUCKET", "high", bucket.resource_id, "aws.s3.bucket"), bucket)
    assert loud.suppressed_by == "", loud
    # ...nor anything critical, whatever the rule id.
    crit = _run(_F("S3_VERSIONING_DISABLED", "critical", bucket.resource_id, "aws.s3.bucket"), bucket)
    assert crit.suppressed_by == ""

    # A customer bucket that merely contains the pattern is still reported.
    mine = _A("arn:aws:s3:::prod-cf-templates-backup", "prod-cf-templates-backup")
    assert _run(_F("S3_VERSIONING_DISABLED", "low", mine.resource_id, "aws.s3.bucket"),
                mine).suppressed_by == ""

    # Log group names survive ARN parsing with their leading path intact.
    lg_arn = "arn:aws:logs:eu-west-1:123456789012:log-group:/aws/lambda/cspm-api"
    assert _asset_name(_A(lg_arn), lg_arn) == "/aws/lambda/cspm-api"
    lg = _A(lg_arn, "/aws/lambda/cspm-api")
    assert _run(_F("LOG_GROUP_NO_RETENTION", "low", lg_arn, "aws.cloudwatch.log_group"),
                lg).suppressed_by == "managed"
    # ...unless it is tagged sensitive, which switches the heuristic off.
    lg.tags = {"DataClassification": "PHI"}
    assert _run(_F("LOG_GROUP_NO_RETENTION", "low", lg_arn, "aws.cloudwatch.log_group"),
                lg).suppressed_by == ""

    # Layer 1b: an empty subnet hands a public address to nothing. This is the
    # default-VPC case — AWS ships 3-4 such subnets in every enabled region.
    empty = _A("subnet-empty", "subnet-empty", {}, "aws.ec2.subnet",
               {"map_public_ip_on_launch": True, "default_for_az": True})
    muted_subnet = _run(_F("SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED", "medium",
                           "subnet-empty", "aws.ec2.subnet"), empty)
    assert muted_subnet.suppressed_by == "design", muted_subnet
    assert "topology evidence" in muted_subnet.suppressed_why
    # Occupancy does not promote subnet tissue into an active threat.
    assert _run(_F("SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED", "medium", "subnet-empty",
                   "aws.ec2.subnet"), empty,
                extra=[_occupant("subnet-empty")]).suppressed_by == "design"
    # RDS ignores MapPublicIpOnLaunch, so a database subnet group cannot change
    # the outcome either; RDS exposure uses PubliclyAccessible plus graph reachability.
    rds = _A("db-1", asset_type="aws.rds.db_instance",
             properties={"subnet_ids": ["subnet-empty", "subnet-b"]})
    assert _run(_F("SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED", "medium", "subnet-empty",
                   "aws.ec2.subnet"), empty, extra=[rds]).suppressed_by == "design"

    # Design layer: subnet state stays as audit evidence regardless of tags or
    # occupancy; graph-backed workload exposure fires separately.
    dmz = _A("subnet-dmz", "subnet-dmz", {"Tier": "Public"})
    assert _run(_F("SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED", "medium", "subnet-dmz",
                   "aws.ec2.subnet"), dmz,
                extra=[_occupant("subnet-dmz")]).suppressed_by == "design"
    dbnet = _A("subnet-db", "subnet-db", {"Tier": "Database"})
    escalated = _run(_F("SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED", "medium", "subnet-db",
                        "aws.ec2.subnet"), dbnet, extra=[_occupant("subnet-db")])
    assert escalated.severity == "medium" and escalated.suppressed_by == "design"
    # An untagged occupied subnet follows the same persistence invariant.
    bare = _A("subnet-x", "subnet-x")
    bare_finding = _run(_F("SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED", "medium", "subnet-x",
                           "aws.ec2.subnet"), bare, extra=[_occupant("subnet-x")])
    assert bare_finding.severity == "medium" and bare_finding.suppressed_by == "design"

    # Layer 4: encryption on a log group is only urgent where regulated data is.
    app_arn = "arn:aws:logs:eu-west-1:1:log-group:/prod/app"
    app = _A(app_arn, "/prod/app")
    quiet = _run(_F("LOG_GROUP_NOT_ENCRYPTED", "medium", app_arn, "aws.cloudwatch.log_group"), app)
    assert quiet.severity == "info" and quiet.suppressed_by == ""
    kept = _run(_F("LOG_GROUP_NOT_ENCRYPTED", "medium", app_arn, "aws.cloudwatch.log_group"),
                app, dspm_taxonomies={"app": ["PII"]})
    assert kept.severity == "medium", kept
    # A non-regulated classification does not hold the severity up.
    other = _run(_F("LOG_GROUP_NOT_ENCRYPTED", "medium", app_arn, "aws.cloudwatch.log_group"),
                 app, dspm_taxonomies={"app": ["SOURCE_CODE"]})
    assert other.severity == "info"

    # The explicit operator tag outranks every heuristic, including severity.
    tagged = _A("arn:aws:s3:::accepted", "accepted", {"Odineyes:Suppress": "true"})
    assert _run(_F("PUBLIC_BUCKET", "critical", tagged.resource_id, "aws.s3.bucket"),
                tagged).suppressed_by == "intent"

    # Layer 3b: global sweep + dormant regions. An entirely innocent region
    # (nothing but default VPC/subnet/route scaffolding) mutes hygiene findings
    # because an empty region cannot have an actionable flow-log gap. But the
    # tripwire logic must not silence public exposure, and a single active
    # workload re-arms a region so its findings become actionable again.
    dormant_vpc = _A("vpc-dormant", "vpc-dormant", {}, "aws.ec2.vpc",
                     {"is_default": True, "Region": "ap-northeast-3"})
    dormant_flow = _F("VPC_FLOW_LOGS_DISABLED", "medium", "vpc-dormant", "aws.ec2.vpc")
    muted = _run(dormant_flow, dormant_vpc,
                 extra=[_A("subnet-1", asset_type="aws.ec2.subnet",
                           properties={"Region": "ap-northeast-3"})])
    assert muted.suppressed_by == "path", muted
    assert "dormant" in muted.suppressed_why
    # An EC2 instance in that region makes it non-dormant -> findings become
    # actionable again (the tripwire fires). Use a customer (non-default) VPC
    # so only the dormancy layer governs the outcome — a default VPC would be
    # suppressed by the empty-default-VPC rule regardless of dormancy.
    active_vpc = _A("vpc-customer", "vpc-customer", {}, "aws.ec2.vpc",
                    {"is_default": False, "Region": "ap-northeast-3"})
    instance = _A("i-abc", asset_type="aws.ec2.instance",
                  properties={"state": "running", "Region": "ap-northeast-3"})
    rearmed = _run(_F("VPC_FLOW_LOGS_DISABLED", "medium", "vpc-customer", "aws.ec2.vpc"),
                   active_vpc,
                   extra=[_A("subnet-1", asset_type="aws.ec2.subnet",
                             properties={"Region": "ap-northeast-3"}), instance])
    assert rearmed.suppressed_by == "", rearmed
    # Public exposure is never silenced by dormancy.
    open_sg = _A("sg-open", "sg-open", {}, "aws.ec2.security_group",
                 {"Region": "ap-northeast-3"})
    assert _run(_F("SECURITY_GROUP_OPEN_TO_WORLD", "critical", "sg-open", "aws.ec2.security_group"),
                open_sg).suppressed_by == ""

    print("tuning self-check OK")
