"""Alert tuning: the four layers that decide whether a true detection alerts.

The module self-check already covers layers 2–4 in isolation. What is tested
here is the behaviour that only exists once tuning is wired into the engine:
that the private-database false positive actually stops, that suppression is a
mark rather than a delete, and — the part most likely to regress — that none of
the noise reduction quietly mutes a real public exposure.
"""

from __future__ import annotations

from odineyes.inventory.rules import evaluate, finding_signal
from odineyes.inventory.schema import NormalizedAsset
from odineyes.inventory.tuning import apply_tuning

ACCOUNT = "123456789012"
SG_ARN = f"arn:aws:ec2:eu-west-1:{ACCOUNT}:security-group/sg-db"


def _asset(asset_type: str, resource_id: str, properties: dict, **kwargs) -> NormalizedAsset:
    return NormalizedAsset(
        resource_id=resource_id, cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type=asset_type, properties=properties, **kwargs,
    )


def _open_sg() -> NormalizedAsset:
    """A security group that lets the world reach PostgreSQL — the loose rule
    that produced the original false positive."""
    return _asset("aws.ec2.security_group", SG_ARN, {
        "open_ports": [5432],
        "world_open_ingress": [
            {"cidr": "0.0.0.0/0", "protocol": "tcp", "from_port": 5432, "to_port": 5432}
        ],
    })


def _database(*, public: bool) -> NormalizedAsset:
    return _asset(
        "aws.rds.db_instance",
        f"arn:aws:rds:eu-west-1:{ACCOUNT}:db:tracs-analytics-sbx-db",
        {
            "publicly_accessible": public,
            "port": 5432,
            "vpc_id": "vpc-1",
            "subnet_ids": ["subnet-a"],
            "security_group_ids": ["sg-db"],
            "engine": "postgres",
        },
        name="tracs-analytics-sbx-db",
        is_public=public,
        encryption_enabled=True,
    )


def _sg_finding(findings):
    return next((f for f in findings if f.rule_id == "WORLD_OPEN_SENSITIVE_PORT"), None)


def test_private_database_behind_an_open_security_group_does_not_alert():
    """The headline false positive: a loose group in front of a database that
    nothing on the internet can route to."""
    assets = [_open_sg(), _database(public=False)]

    assert _sg_finding(evaluate(assets)) is None

    # Suppressed, not deleted — the loose rule is still on the record.
    muted = _sg_finding(evaluate(assets, include_suppressed=True))
    assert muted is not None
    assert muted.suppressed_by == "path"
    assert "no internet path" in muted.suppressed_why


def test_the_same_group_alerts_again_once_the_database_has_a_public_endpoint():
    """Suppression follows the path, not the resource type. Flip the one fact
    that opens the path and the finding must come back.

    It comes back as medium rather than high because this fixture has no route
    tables, gateways or network ACLs, so the path is unverified rather than
    proven — which is precisely the line that must not collapse into "blocked".
    """
    alert = _sg_finding(evaluate([_open_sg(), _database(public=True)]))
    assert alert is not None and alert.suppressed_by == ""
    assert alert.severity == "medium"


def test_an_unverifiable_workload_is_not_treated_as_a_broken_path():
    """The distinction the whole engine rests on: 'we proved there is no path'
    and 'we could not tell' must not produce the same answer."""
    unknown = _asset("aws.elasticache.cluster", "arn:aws:elasticache:eu-west-1:1:cluster:c", {
        "security_group_ids": ["sg-db"],
    })
    alert = _sg_finding(evaluate([_open_sg(), unknown]))
    assert alert is not None, "an unevaluatable attached workload must keep the finding"
    assert alert.severity == "medium"


def test_aws_managed_bucket_is_muted_but_never_when_it_is_public():
    managed = {"name": "cf-templates-1x2y3z-eu-west-1"}
    hygiene = _asset("aws.s3.bucket", "arn:aws:s3:::cf-templates-1x2y3z-eu-west-1", {
        "versioning_enabled": False,
        "collection_evidence": {"versioning": "observed", "public_access_block": "observed"},
        "block_public_access": {"BlockPublicAcls": True},
    }, **managed)
    findings = evaluate([hygiene], include_suppressed=True)
    versioning = [f for f in findings if f.rule_id == "S3_VERSIONING_DISABLED"]
    assert versioning and versioning[0].suppressed_by == "managed"

    # Same bucket, now world-readable. AWS having named it changes nothing.
    exposed = _asset("aws.s3.bucket", "arn:aws:s3:::cf-templates-1x2y3z-eu-west-1", {
        "collection_evidence": {"public_access_block": "observed"},
        "block_public_access": {},
    }, is_public=True, **managed)
    public = [f for f in evaluate([exposed]) if f.rule_id == "PUBLIC_BUCKET"]
    assert public and public[0].suppressed_by == ""


def test_subnet_auto_assign_is_persisted_but_never_an_active_threat():
    def subnet(name: str, tags: dict) -> NormalizedAsset:
        return _asset("aws.ec2.subnet", f"arn:aws:ec2:eu-west-1:{ACCOUNT}:subnet/{name}",
                      {"map_public_ip_on_launch": True}, name=name, tags=tags)

    def occupant(subnet_id: str) -> NormalizedAsset:
        """Occupancy is checked before intent, so each subnet needs a tenant for
        the tag logic to be what is under test here."""
        return _asset("aws.ec2.instance", f"arn:aws:ec2:eu-west-1:{ACCOUNT}:instance/i-{subnet_id}",
                      {"subnet_id": subnet_id}, name=f"i-{subnet_id}")

    def only_subnet_findings(assets, **kw):
        return [f for f in evaluate(assets, **kw)
                if f.rule_id == "SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED"]

    dmz = only_subnet_findings(
        [subnet("subnet-dmz", {"Tier": "Public"}), occupant("subnet-dmz")],
        include_suppressed=True)
    assert dmz and dmz[0].suppressed_by == "design"

    # Private intent makes the drift more meaningful, but it remains a
    # preventative subnet control. Reachability findings carry actual exposure.
    db = only_subnet_findings(
        [subnet("subnet-db", {"Tier": "Database"}), occupant("subnet-db")],
        include_suppressed=True,
    )
    assert db and db[0].severity == "medium" and db[0].suppressed_by == "design"

    # No tag is not consent.
    bare = only_subnet_findings(
        [subnet("subnet-x", {}), occupant("subnet-x")], include_suppressed=True
    )
    assert bare and bare[0].severity == "medium" and bare[0].suppressed_by == "design"


def test_network_hygiene_rules_are_not_presented_as_active_threats():
    assert finding_signal("SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED") == "network_hygiene"
    assert finding_signal("VPC_FLOW_LOGS_DISABLED") == "network_hygiene"
    assert finding_signal("UNUSED_SECURITY_GROUP") == "network_hygiene"
    assert finding_signal("PUBLIC_BUCKET") == "active_threat"


def test_log_group_encryption_is_graded_by_what_flows_through_it():
    arn = f"arn:aws:logs:eu-west-1:{ACCOUNT}:log-group:/prod/payments"
    log_group = _asset("aws.cloudwatch.log_group", arn, {"kms_key_id": None, "retention_days": 30},
                       name="/prod/payments", encryption_enabled=False)

    quiet = [f for f in evaluate([log_group]) if f.rule_id == "LOG_GROUP_NOT_ENCRYPTED"]
    assert quiet and quiet[0].severity == "info"

    loud = [f for f in evaluate([log_group], dspm_taxonomies={"payments": ["PCI"]})
            if f.rule_id == "LOG_GROUP_NOT_ENCRYPTED"]
    assert loud and loud[0].severity == "medium"


def test_tagged_odineyes_realtime_trail_suppresses_only_pipeline_hygiene_rules():
    trail = _asset(
        "aws.cloudtrail.trail",
        f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/odineyes-realtime-{ACCOUNT}-us-east-1",
        {
            "is_multi_region": False,
            "is_logging": True,
            "log_file_validation": True,
            "kms_encrypted": False,
            "cloudwatch_logs_arn": None,
        },
        name=f"odineyes-realtime-{ACCOUNT}-us-east-1",
        tags={"ManagedBy": "CSPM-G3", "Purpose": "OdineyesRealtimeCloudTrail"},
    )
    findings = evaluate([trail], include_suppressed=True)
    by_rule = {finding.rule_id: finding for finding in findings}

    assert by_rule["CLOUDTRAIL_NO_CLOUDWATCH"].suppressed_by == "design"
    assert by_rule["CLOUDTRAIL_NOT_ENCRYPTED"].suppressed_by == "design"
    assert by_rule["CLOUDTRAIL_NOT_MULTIREGION"].suppressed_by == ""
    assert "not a replacement" in by_rule["CLOUDTRAIL_NOT_MULTIREGION"].why


def test_lookalike_cloudtrail_name_without_platform_tags_is_never_suppressed():
    trail = _asset(
        "aws.cloudtrail.trail",
        f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/odineyes-realtime-{ACCOUNT}-us-east-1",
        {"kms_encrypted": False, "cloudwatch_logs_arn": None},
        name=f"odineyes-realtime-{ACCOUNT}-us-east-1",
    )
    findings = evaluate([trail], include_suppressed=True)
    by_rule = {finding.rule_id: finding for finding in findings}

    assert by_rule["CLOUDTRAIL_NO_CLOUDWATCH"].suppressed_by == ""
    assert by_rule["CLOUDTRAIL_NOT_ENCRYPTED"].suppressed_by == ""


def test_multiregion_context_is_not_overstated_when_customer_has_other_trails():
    pipeline = _asset(
        "aws.cloudtrail.trail",
        f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/odineyes-realtime-{ACCOUNT}-us-east-1",
        {"is_multi_region": False, "is_logging": True},
        name=f"odineyes-realtime-{ACCOUNT}-us-east-1",
        tags={"ManagedBy": "CSPM-G3", "Purpose": "OdineyesRealtimeCloudTrail"},
    )
    customer_trail = _asset(
        "aws.cloudtrail.trail",
        f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/customer-regional-audit",
        {"is_multi_region": False, "is_logging": True},
        name="customer-regional-audit",
    )
    finding = next(
        f for f in evaluate([pipeline, customer_trail], include_suppressed=True)
        if f.rule_id == "CLOUDTRAIL_NOT_MULTIREGION"
    )
    assert "not a replacement" not in finding.why


def test_tuning_never_reorders_or_loses_a_finding_it_did_not_touch():
    """apply_tuning returns the same objects it was given — a filter, not a
    rebuild. If it ever starts copying, severity edits stop propagating."""
    before = evaluate([_open_sg(), _database(public=True)], include_suppressed=True)
    after = apply_tuning(before, [])
    assert after == before
    assert all(a is b for a, b in zip(after, before))


# ── the default-VPC noise floor ────────────────────────────────

def _subnet(name: str, *, default_vpc: bool = True, tags: dict | None = None) -> NormalizedAsset:
    return _asset(
        "aws.ec2.subnet", f"arn:aws:ec2:eu-north-1:{ACCOUNT}:subnet/{name}",
        {"map_public_ip_on_launch": True, "default_for_az": default_vpc, "vpc_id": "vpc-def"},
        name=name, tags=tags or {},
    )


def test_empty_default_vpc_subnets_do_not_alert():
    """AWS creates a default VPC per region with MapPublicIpOnLaunch already on,
    so an untouched account arrives with dozens of these. Nothing runs in them,
    so nothing receives a public address."""
    subnets = [_subnet(f"subnet-{i}") for i in range(4)]
    assert evaluate(subnets) == []

    muted = evaluate(subnets, include_suppressed=True)
    assert len(muted) == 4
    assert {f.suppressed_by for f in muted} == {"design"}
    assert "topology evidence" in muted[0].suppressed_why


def test_one_instance_does_not_promote_subnet_tissue_into_a_threat():
    subnet = _subnet("subnet-live")
    instance = _asset("aws.ec2.instance", f"arn:aws:ec2:eu-north-1:{ACCOUNT}:instance/i-1",
                      {"subnet_id": "subnet-live", "vpc_id": "vpc-def"}, name="i-1")
    assert evaluate([subnet, instance]) == []
    findings = [f for f in evaluate([subnet, instance], include_suppressed=True)
                if f.rule_id == "SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED"]
    assert findings and findings[0].suppressed_by == "design"


def test_occupancy_counts_lambda_and_load_balancers_not_only_ec2():
    """Workloads count, while network topology cannot invent occupancy."""
    from odineyes.inventory.tuning import occupied_subnets

    fn = _asset("aws.lambda.function", "arn:fn", {"subnet_ids": ["subnet-a", "subnet-b"]})
    lb = _asset("aws.elbv2.load_balancer", "arn:lb", {"subnet_ids": ["subnet-c"]})
    ec2 = _asset("aws.ec2.instance", "arn:i", {"subnet_id": "subnet-d"})
    # A subnet must not count itself as its own occupant.
    itself = _asset("aws.ec2.subnet", "arn:sn", {"subnet_id": "subnet-z"}, name="subnet-z")
    # Every default subnet is associated to a default NACL. That relationship
    # is the regression that brought all 24 empty-subnet findings back.
    acl = _asset("aws.ec2.network_acl", "arn:acl", {
        "vpc_id": "vpc-def", "subnet_ids": ["subnet-z"], "is_default": True,
    })
    assert occupied_subnets([fn, lb, ec2, itself, acl]) == {
        "subnet-a", "subnet-b", "subnet-c", "subnet-d"}


def _vpc(name: str = "vpc-def", *, default: bool = True) -> NormalizedAsset:
    return _asset(
        "aws.ec2.vpc", f"arn:aws:ec2:eu-north-1:{ACCOUNT}:vpc/{name}",
        {
            "is_default": default,
            "flow_logs_enabled": False,
            "collection_evidence": {"flow_logs": "observed"},
        },
        name=name,
    )


def _flow_log_findings(assets, **kwargs):
    return [
        finding for finding in evaluate(assets, **kwargs)
        if finding.rule_id == "VPC_FLOW_LOGS_DISABLED"
    ]


def test_empty_default_vpc_flow_log_gap_is_suppressed():
    vpc = _vpc()
    assert _flow_log_findings([vpc]) == []
    suppressed = _flow_log_findings([vpc], include_suppressed=True)
    assert len(suppressed) == 1
    assert suppressed[0].suppressed_by == "path"
    assert "empty default VPC" in suppressed[0].suppressed_why


def test_network_controls_do_not_make_a_default_vpc_occupied():
    vpc = _vpc()
    acl = _asset("aws.ec2.network_acl", "arn:acl", {
        "vpc_id": "vpc-def", "subnet_ids": ["subnet-a"], "is_default": True,
    })
    route = _asset("aws.ec2.route_table", "arn:route", {"vpc_id": "vpc-def"})
    assert _flow_log_findings([vpc, acl, route]) == []


def test_in_use_eni_makes_vpc_actionable_but_subnet_stays_evidence():
    vpc = _vpc()
    subnet = _subnet("subnet-live")
    eni = _asset("aws.ec2.network_interface", "arn:eni", {
        "vpc_id": "vpc-def", "subnet_id": "subnet-live", "status": "in-use",
    })
    findings = evaluate([vpc, subnet, eni])
    assert "VPC_FLOW_LOGS_DISABLED" in {finding.rule_id for finding in findings}
    assert "SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED" not in {
        finding.rule_id for finding in findings
    }
    suppressed = evaluate([vpc, subnet, eni], include_suppressed=True)
    subnet_finding = next(
        finding for finding in suppressed
        if finding.rule_id == "SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED"
    )
    assert subnet_finding.suppressed_by == "design"


def test_unattached_eni_does_not_create_fake_occupancy():
    vpc = _vpc()
    eni = _asset("aws.ec2.network_interface", "arn:eni", {
        "vpc_id": "vpc-def", "subnet_id": "subnet-empty", "status": "available",
    })
    assert _flow_log_findings([vpc, eni]) == []


def test_customer_created_vpc_without_flow_logs_remains_actionable_when_empty():
    findings = _flow_log_findings([_vpc("vpc-customer", default=False)])
    assert len(findings) == 1
    assert findings[0].suppressed_by == ""


def test_network_interface_normalizer_preserves_occupancy_evidence():
    from odineyes.inventory.normalizers import normalize_ec2_network_interface

    eni = normalize_ec2_network_interface({
        "NetworkInterfaceId": "eni-123",
        "Region": "eu-north-1",
        "VpcId": "vpc-def",
        "SubnetId": "subnet-a",
        "Status": "in-use",
        "RequesterManaged": True,
        "Attachment": {"InstanceId": "i-123", "Status": "attached", "DeviceIndex": 1},
        "Groups": [{"GroupId": "sg-123", "GroupName": "app"}],
    }, ACCOUNT)

    assert eni.asset_type == "aws.ec2.network_interface"
    assert eni.properties["vpc_id"] == "vpc-def"
    assert eni.properties["subnet_id"] == "subnet-a"
    assert eni.properties["status"] == "in-use"
    assert {relationship["type"] for relationship in eni.relationships} >= {
        "ATTACHED_TO", "USES_SECURITY_GROUP",
    }
