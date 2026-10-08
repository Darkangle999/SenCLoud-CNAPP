"""Phase 2 rules engine coverage — runs over NormalizedAsset fixtures, offline.

Each rule is asserted in isolation plus the full evaluate() ordering and the
toxic-combination linkage. The DB adapter (evaluate_account) shares evaluate()'s
logic, so it is exercised once end to end against a sqlite-persisted asset set.
"""

from __future__ import annotations

from odineyes.inventory.rules import (
    Finding,
    evaluate,
    evaluate_account,
    rule_public_admin_role,
    rule_public_bucket,
    rule_public_compute_to_admin,
    rule_public_unencrypted_db,
    rule_world_open_sensitive_port,
)
from odineyes.inventory.schema import NormalizedAsset

ACCOUNT = "123456789012"


def role(public: bool, admin: bool, name="r") -> NormalizedAsset:
    return NormalizedAsset(
        resource_id=f"arn:aws:iam::{ACCOUNT}:role/{name}", cloud_provider="aws",
        account_identifier=ACCOUNT, asset_type="aws.iam.role", name=name,
        is_public=public, properties={"has_admin": admin, "admin_reason": "AdministratorAccess"},
    )


def sg(ports: list[int]) -> NormalizedAsset:
    return NormalizedAsset(
        resource_id="arn:sg-1", cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type="aws.ec2.security_group", is_public=bool(ports),
        properties={"open_ports": ports},
    )


def rds(public: bool, encrypted) -> NormalizedAsset:
    return NormalizedAsset(
        resource_id="arn:db-1", cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type="aws.rds.db_instance", is_public=False, encryption_enabled=encrypted,
        properties={"publicly_accessible": public},
    )


def ec2(public: bool, profile: bool) -> NormalizedAsset:
    return NormalizedAsset(
        resource_id="arn:i-1", cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type="aws.ec2.instance", is_public=public,
        properties={"iam_instance_profile": "arn:profile" if profile else None},
    )


def bucket(public: bool) -> NormalizedAsset:
    return NormalizedAsset(
        resource_id="arn:aws:s3:::b", cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type="aws.s3.bucket", is_public=public,
    )


# ── single-asset rules ─────────────────────────────────────────

def test_public_admin_role_fires_critical():
    f = rule_public_admin_role(role(public=True, admin=True))
    assert f is not None and f.severity == "critical"
    assert f.compliance["NIST"]  # compliance attached


def test_admin_role_not_public_no_finding():
    assert rule_public_admin_role(role(public=False, admin=True)) is None


def test_public_role_without_admin_no_finding():
    assert rule_public_admin_role(role(public=True, admin=False)) is None


def _ec2(*, sg_id="sg-1", public=False, profile=None, name="i-1"):
    return NormalizedAsset(
        resource_id=f"arn:aws:ec2:us-east-1:1:instance/{name}", cloud_provider="aws",
        account_identifier=ACCOUNT, asset_type="aws.ec2.instance", is_public=public,
        properties={
            "security_group_ids": [sg_id],
            "iam_instance_profile": profile,
            "public_ip": "203.0.113.10" if public else None,
            "vpc_id": "vpc-1",
            "subnet_id": "subnet-1",
        },
    )


def _sg_named(ports, short="sg-1"):
    return NormalizedAsset(
        resource_id=f"arn:aws:ec2:us-east-1:1:security-group/{short}",
        cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type="aws.ec2.security_group", is_public=False,
        properties={
            "open_ports": ports,
            "world_open_ingress": [
                {
                    "cidr": "0.0.0.0/0",
                    "protocol": "-1" if port == 0 else "tcp",
                    "from_port": None if port == 0 else port,
                    "to_port": None if port == 0 else port,
                }
                for port in ports
            ],
        },
    )


def _public_network():
    common = {
        "cloud_provider": "aws",
        "account_identifier": ACCOUNT,
        "region": "us-east-1",
    }
    return [
        NormalizedAsset(
            resource_id="arn:aws:ec2:us-east-1:1:route-table/rtb-1",
            asset_type="aws.ec2.route_table",
            properties={
                "vpc_id": "vpc-1",
                "associations": [{"subnet_id": "subnet-1", "main": False}],
                "routes": [{
                    "destination_cidr_block": "0.0.0.0/0",
                    "gateway_id": "igw-1",
                    "state": "active",
                }],
            },
            **common,
        ),
        NormalizedAsset(
            resource_id="arn:aws:ec2:us-east-1:1:internet-gateway/igw-1",
            asset_type="aws.ec2.internet_gateway",
            properties={"attached_vpc_ids": ["vpc-1"]},
            **common,
        ),
        NormalizedAsset(
            resource_id="arn:aws:ec2:us-east-1:1:network-acl/acl-1",
            asset_type="aws.ec2.network_acl",
            properties={
                "vpc_id": "vpc-1",
                "subnet_ids": ["subnet-1"],
                "entries": [
                    {
                        "rule_number": 100, "protocol": "-1", "rule_action": "allow",
                        "egress": False, "cidr_block": "0.0.0.0/0",
                        "from_port": None, "to_port": None,
                    },
                    {
                        "rule_number": 100, "protocol": "-1", "rule_action": "allow",
                        "egress": True, "cidr_block": "0.0.0.0/0",
                        "from_port": None, "to_port": None,
                    },
                ],
            },
            **common,
        ),
    ]


def _world_open(assets):
    return next(
        (f for f in rule_world_open_sensitive_port(assets)
         if f.rule_id == "WORLD_OPEN_SENSITIVE_PORT"),
        None,
    )


def test_world_open_ssh_severity_follows_what_is_behind_the_port():
    """The same 0.0.0.0/0 -> 22 rule is not the same risk on an unattached
    group, a private instance, and a public instance with a role."""
    sg_asset = _sg_named([22])
    assert _world_open([sg_asset]).severity == "low"
    assert _world_open([sg_asset, _ec2(public=False)]).severity == "medium"
    # A public-IP flag without route/IGW/NACL evidence is not enough.
    assert _world_open([sg_asset, _ec2(public=True)]).severity == "medium"
    assert _world_open([sg_asset, _ec2(public=True), *_public_network()]).severity == "high"
    # An instance profile does not turn the isolated SSH control into critical.
    assert _world_open([
        sg_asset, _ec2(public=True, profile="arn:aws:iam::1:instance-profile/app"),
        *_public_network(),
    ]).severity == "high"


def test_world_open_ssh_still_fires_when_unattached():
    """Severity drops, the finding does not disappear — 0.0.0.0/0 to SSH is a
    CIS 5.2 failure whatever is behind it."""
    finding = _world_open([_sg_named([22])])
    assert finding is not None
    assert finding.compliance["CIS"] == ["5.2"]
    assert "no collected resource uses it" in finding.why


def test_world_open_finding_names_the_exposed_workload():
    finding = _world_open([
        _sg_named([22]), _ec2(public=True, name="i-web"), *_public_network(),
    ])
    assert "i-web" in finding.why
    assert finding.title == "Internet can reach SSH on attached EC2 instance"
    assert finding.related == ["arn:aws:ec2:us-east-1:1:instance/i-web"]


def test_world_open_all_ports_outranks_a_single_port():
    """All ports still cannot outrank missing attachment or path evidence."""
    assert _world_open([_sg_named([0])]).severity == "low"
    assert _world_open([_sg_named([0]), _ec2(public=False)]).severity == "medium"
    assert _world_open([
        _sg_named([0]), _ec2(public=True), *_public_network(),
    ]).severity == "high"


def test_world_open_database_without_path_proof_is_not_critical():
    db = NormalizedAsset(
        resource_id="arn:aws:rds:us-east-1:1:db:prod", cloud_provider="aws",
        account_identifier=ACCOUNT, asset_type="aws.rds.db_instance", is_public=True,
        properties={"security_group_ids": ["sg-1"]},
    )
    assert _world_open([_sg_named([3306]), db]).severity == "medium"


def test_world_open_http_only_produces_no_finding():
    # 80 is not in SENSITIVE_PORTS, so an http-only SG produces no finding
    assert _world_open([_sg_named([80]), _ec2(public=True)]) is None


def test_public_unencrypted_db_is_high_configuration_risk():
    assert rule_public_unencrypted_db(rds(public=True, encrypted=False)).severity == "high"


def test_public_encrypted_db_no_unencrypted_finding():
    assert rule_public_unencrypted_db(rds(public=True, encrypted=True)) is None


def test_public_bucket_high():
    assert rule_public_bucket(bucket(public=True)).severity == "high"


def test_private_bucket_clean():
    assert rule_public_bucket(bucket(public=False)) is None


def test_overly_permissive_cidr_fires():
    sg_wide = NormalizedAsset(
        resource_id="arn:sg-wide", cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type="aws.ec2.security_group", is_public=True,
        properties={"open_ports": [], "wide_open_cidrs": [{"cidr": "13.0.0.0/8", "prefix": 8, "port": 22}]},
    )
    ids = {f.rule_id for f in evaluate([sg_wide])}
    assert ids == {"OVERLY_PERMISSIVE_CIDR"}


def test_unused_security_group_flagged():
    def _sg(short):
        return NormalizedAsset(
            resource_id=f"arn:aws:ec2:us-east-1:1:security-group/{short}",
            cloud_provider="aws", account_identifier=ACCOUNT,
            asset_type="aws.ec2.security_group", is_public=False,
            properties={"open_ports": []},
        )
    used, free = _sg("sg-used"), _sg("sg-free")
    ec2 = NormalizedAsset(
        resource_id="arn:aws:ec2:us-east-1:1:instance/i-1", cloud_provider="aws",
        account_identifier=ACCOUNT, asset_type="aws.ec2.instance", is_public=False,
        properties={"security_group_ids": ["sg-used"]},
    )
    hits = {(f.rule_id, f.resource_id) for f in evaluate([used, free, ec2])}
    assert ("UNUSED_SECURITY_GROUP", free.resource_id) in hits
    assert ("UNUSED_SECURITY_GROUP", used.resource_id) not in hits  # referenced by ec2


# ── rds rule mutual-exclusion ──────────────────────────────────

def test_public_unencrypted_db_does_not_double_count():
    findings = evaluate([rds(public=True, encrypted=False)])
    ids = {f.rule_id for f in findings}
    assert ids == {"RDS_PUBLIC_ENDPOINT_UNENCRYPTED"}


def test_public_encrypted_db_is_just_public():
    ids = {f.rule_id for f in evaluate([rds(public=True, encrypted=True)])}
    assert ids == {"RDS_PUBLIC_ENDPOINT_CONFIGURED"}


def test_private_unencrypted_db_is_unencrypted_only():
    ids = {f.rule_id for f in evaluate([rds(public=False, encrypted=False)])}
    assert ids == {"UNENCRYPTED_DATABASE"}


# ── combination rule ───────────────────────────────────────────

def test_toxic_public_compute_to_admin():
    assets = [ec2(public=True, profile=True), role(public=False, admin=True, name="admin")]
    findings = rule_public_compute_to_admin(assets)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "PUBLIC_COMPUTE_TO_ADMIN" and f.severity == "critical"
    assert f.related == [f"arn:aws:iam::{ACCOUNT}:role/admin"]


def test_no_toxic_combo_without_admin_role():
    assets = [ec2(public=True, profile=True), role(public=False, admin=False)]
    assert rule_public_compute_to_admin(assets) == []


def test_no_toxic_combo_for_private_compute():
    assets = [ec2(public=False, profile=True), role(public=False, admin=True)]
    assert rule_public_compute_to_admin(assets) == []


def test_no_toxic_combo_without_instance_profile():
    assets = [ec2(public=True, profile=False), role(public=False, admin=True)]
    assert rule_public_compute_to_admin(assets) == []


# ── engine ordering ────────────────────────────────────────────

def test_evaluate_sorts_critical_first():
    findings = evaluate([bucket(public=True), role(public=True, admin=True)])
    assert findings[0].severity == "critical"      # admin role
    assert findings[-1].severity == "high"         # public bucket
    assert all(isinstance(f, Finding) for f in findings)


# ── DB adapter end to end ──────────────────────────────────────

def test_evaluate_account_over_persisted_assets(tmp_path):
    from odineyes.db.base import session_scope
    from odineyes.inventory.service import InventoryService

    url = f"sqlite:///{tmp_path}/rules.db"
    svc = InventoryService(database_url=url)
    svc.persist_normalized("aws", ACCOUNT, [
        bucket(public=True),
        role(public=True, admin=True, name="exposed"),
        rds(public=True, encrypted=False),
    ])
    with session_scope(url) as session:
        findings = evaluate_account(session)
    rule_ids = {f.rule_id for f in findings}
    assert {"PUBLIC_BUCKET", "PUBLIC_ADMIN_ROLE", "RDS_PUBLIC_ENDPOINT_UNENCRYPTED"} <= rule_ids
    assert findings[0].severity == "critical"  # sorted
