"""Dormant-region tuning: the alert-fatigue side of the global sweep.

The product collects every enabled region on purpose - attackers spin up
miners and exfil relays in regions the victim never uses, so an unused region
is a tripwire, not a blind spot. But it makes no sense to page an operator
about missing VPC flow logs in a region the account has never touched: the
region is safe precisely because nothing is in it.

The tuning tested here is that line:
  - hygienic-only rules are silenced in a region whose whole asset population
    is AWS default scaffolding (default VPC, subnets, NACLs, route tables);
  - the appearance of any real workload, data service or in-use interface
    wakes the region up in the same pass and rearms every finding there;
  - dormancy never outranks a data-exposure or global control: public buckets
    and IAM root findings keep alerting in dormant regions and even with no
    region at all;
  - dormancy is a fact about the asset set, not an iteration accident
    (a scaffolding asset listed after an instance must not re-suppress the
    region the instance occupies).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from odineyes.inventory.rules import evaluate
from odineyes.inventory.schema import NormalizedAsset
from odineyes.inventory.tuning import (
    DESIGN_SUPPRESSED_RULES,
    DORMANT_SUPPRESSED_RULES,
    apply_tuning,
    dormant_regions,
)

ACCOUNT = "123456789012"
DORMANT = "af-south-1"


def _asset(asset_type: str, resource_id: str, properties: dict, **kwargs) -> NormalizedAsset:
    return NormalizedAsset(
        resource_id=resource_id, cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type=asset_type, properties=properties, **kwargs,
    )


# ── scaffolding: exactly what AWS ships into a region nobody ever used ──

def _scaffolding(region: str) -> list[NormalizedAsset]:
    return [
        _asset("aws.ec2.vpc", f"arn:aws:ec2:{region}:{ACCOUNT}:vpc/vpc-0default", {
            "is_default": True, "flow_logs_enabled": False,
            "collection_evidence": {"flow_logs": "observed"}, "state": "available",
        }, region=region, name="vpc-0default"),
        _asset("aws.ec2.subnet", f"arn:aws:ec2:{region}:{ACCOUNT}:subnet/subnet-0one", {
            "map_public_ip_on_launch": True, "vpc_id": "vpc-0default", "state": "available",
        }, region=region),
        _asset("aws.ec2.network_acl", f"arn:aws:ec2:{region}:{ACCOUNT}:network-acl/acl-0one", {
            "is_default": True, "vpc_id": "vpc-0default",
        }, region=region),
        _asset("aws.ec2.route_table", f"arn:aws:ec2:{region}:{ACCOUNT}:route-table/rtb-0one", {
            "vpc_id": "vpc-0default",
        }, region=region),
    ]


def _running_instance(region: str, *, name: str = "i-0tenant") -> NormalizedAsset:
    """An EC2 tenant that both wakes the region up and occupies the default VPC."""
    return _asset("aws.ec2.instance", f"arn:aws:ec2:{region}:{ACCOUNT}:instance/{name}", {
        "state": "running", "vpc_id": "vpc-0default", "subnet_id": "subnet-0one",
    }, region=region)


@dataclass
class _Finding:
    rule_id: str
    severity: str
    resource_id: str
    asset_type: str
    why: str = ""
    suppressed_by: str = ""
    suppressed_why: str = ""


@dataclass
class _Stub:
    """Minimal asset stand-in: everything tuning.py touches, nothing more.

    ``_normalize_tags`` / ``_asset_name`` reach them through ``getattr`` and
    fall back gracefully when absent, so only the region-bearing fields are
    declared.
    """
    resource_id: str
    asset_type: str = ""
    region: str = ""
    properties: dict = field(default_factory=dict)


# ── region classification ────────────────────────────────────────────────


def test_scaffolding_only_region_is_dormant():
    assert dormant_regions(_scaffolding(DORMANT)) == {DORMANT}


def test_any_activity_asset_wakes_the_region():
    assets = _scaffolding(DORMANT) + [_running_instance(DORMANT)]
    assert dormant_regions(assets) == set()


def test_dormancy_is_independent_of_asset_order():
    """Regression: the one-pass classifier let a scaffolding asset iterated
    after an instance re-add the region to the dormant set, silently
    re-suppressing findings in the account's busiest region."""
    active_first = [_running_instance(DORMANT)] + _scaffolding(DORMANT)
    scaffolding_first = _scaffolding(DORMANT) + [_running_instance(DORMANT)]
    assert dormant_regions(active_first) == set()
    assert dormant_regions(scaffolding_first) == set()


def test_cloudtrail_trail_counts_as_neither_activity_nor_scaffolding():
    trail = _asset("aws.cloudtrail.trail", "arn:aws:cloudtrail:us-east-1:123:trail/t", {})
    assert dormant_regions([trail]) == set()  # global trail reports no region
    assert dormant_regions(_scaffolding(DORMANT) + [trail]) == {DORMANT}


# ── suppression and tripwire rearm, end to end through the rule engine ───


def _flow_log_finding(findings):
    return next((f for f in findings if f.rule_id == "VPC_FLOW_LOGS_DISABLED"), None)


def test_hygiene_findings_are_silenced_in_a_scaffolding_only_region():
    """The alert-fatigue cut: fifty empty enabled regions must not produce
    fifty flow-log pages. Suppressed with a path reason, never deleted."""
    muted = _flow_log_finding(evaluate(_scaffolding(DORMANT), include_suppressed=True))
    assert muted is not None
    assert muted.suppressed_by == "path"
    assert "dormant" in muted.suppressed_why


def test_the_same_region_alerts_the_moment_a_workload_appears():
    """The tripwire rearm: a tenant in the region proves it is in use, so the
    hygiene finding becomes actionable in the very same pass."""
    alert = _flow_log_finding(evaluate(_scaffolding(DORMANT) + [_running_instance(DORMANT)]))
    assert alert is not None and alert.suppressed_by == ""


def test_a_running_instance_listed_first_splits_the_same_way():
    """Same scenario, scaffolding listed after the tenant - must be identical."""
    alert = _flow_log_finding(evaluate([_running_instance(DORMANT)] + _scaffolding(DORMANT)))
    assert alert is not None and alert.suppressed_by == ""


# ── the lines dormancy must not cross ────────────────────────────────────


def test_data_exposure_still_alerts_in_a_dormant_region():
    bucket = _asset("aws.s3.bucket", "arn:aws:s3:::exfil-dormant-region", {
        "collection_evidence": {"public_access_block": "observed"},
        "block_public_access": {},
    }, region=DORMANT, is_public=True)
    public = [f for f in evaluate(_scaffolding(DORMANT) + [bucket]) if f.rule_id == "PUBLIC_BUCKET"]
    assert public and public[0].suppressed_by == ""


def test_a_regionless_global_finding_is_never_dormancy_suppressed():
    """IAM root access keys carry no region. Direct tuning proves dormancy
    cannot reach findings whose asset reports no region at all."""
    root_key = _Stub(
        resource_id=f"arn:aws:iam::{ACCOUNT}:root",
        asset_type="aws.iam.credential_report",
        region="",
        properties={},
    )
    finding = _Finding(
        rule_id="IAM_ROOT_ACCESS_KEY",
        severity="critical",
        resource_id=root_key.resource_id,
        asset_type=root_key.asset_type,
    )
    apply_tuning([finding], [root_key, *_scaffolding(DORMANT)])
    assert finding.suppressed_by == ""


def test_every_dormant_suppressed_rule_is_still_marked_not_dropped():
    """Each rule in the dormant set is silenced with an auditable reason -
    suppression is a mark so the operator can see why it went quiet. Some
    rules (e.g. subnet auto-assign) are also design-suppressed and silenced by
    that higher layer regardless of region; both layers must leave a reason."""
    vpc = _scaffolding(DORMANT)[0]
    design = DESIGN_SUPPRESSED_RULES
    for rule in sorted(DORMANT_SUPPRESSED_RULES):
        finding = _Finding(
            rule_id=rule,
            severity="medium",
            resource_id=vpc.resource_id,
            asset_type="aws.ec2.vpc",
        )
        apply_tuning([finding], _scaffolding(DORMANT))
        # Silenced, never dropped.
        assert finding.suppressed_by, rule
        assert finding.suppressed_why, rule
        # Rules not covered by a higher-priority layer must be silenced by
        # dormancy itself, with a dormant reason.
        if rule not in design:
            assert finding.suppressed_by == "path", (rule, finding.suppressed_by)
            assert "dormant" in finding.suppressed_why, rule