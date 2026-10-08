"""Pure normalizer coverage — raw AWS API dict → NormalizedAsset.

Every normalizer is pure (no cloud calls), so these run offline against
hand-built raw fixtures shaped like describe_*/list_* output. Asserts the
standard fields the Phase 2 rules engine depends on, plus the registry lookup.
"""

from __future__ import annotations

import pytest

from odineyes.inventory.normalizers import (
    get_normalizer,
    normalize_ec2_internet_gateway,
    normalize_ec2_network_acl,
    normalize_ec2_route_table,
    normalize_ec2_instance,
    normalize_iam_role,
    normalize_rds_instance,
    normalize_security_group,
)

ACCOUNT = "123456789012"


# ── EC2 ────────────────────────────────────────────────────────

def test_ec2_public_instance():
    raw = {
        "InstanceId": "i-0abc",
        "InstanceType": "t3.micro",
        "State": {"Name": "running"},
        "PublicIpAddress": "1.2.3.4",
        "PrivateIpAddress": "10.0.0.5",
        "VpcId": "vpc-1",
        "SubnetId": "subnet-1",
        "ImageId": "ami-1",
        "Placement": {"AvailabilityZone": "us-east-1a"},
        "SecurityGroups": [{"GroupId": "sg-1"}, {"GroupId": "sg-2"}],
        "IamInstanceProfile": {"Arn": "arn:aws:iam::123456789012:instance-profile/p"},
        "Tags": [{"Key": "Name", "Value": "web"}, {"Key": "env", "Value": "prod"}],
    }
    a = normalize_ec2_instance(raw, ACCOUNT)
    assert a.asset_type == "aws.ec2.instance"
    assert a.resource_id == "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc"
    assert a.region == "us-east-1"          # derived from AZ
    assert a.name == "web"                  # from Name tag
    assert a.is_public is True
    assert a.network_exposure == "public"
    assert a.tags == {"Name": "web", "env": "prod"}
    rel_types = {r["type"] for r in a.relationships}
    assert {"BELONGS_TO", "USES_SECURITY_GROUP", "USES_INSTANCE_PROFILE"} <= rel_types
    assert a.properties["security_group_ids"] == ["sg-1", "sg-2"]


def test_ec2_private_instance_no_public_ip():
    raw = {"InstanceId": "i-priv", "Placement": {"AvailabilityZone": "eu-west-1b"}}
    a = normalize_ec2_instance(raw, ACCOUNT)
    assert a.is_public is False
    assert a.network_exposure == "vpc"
    assert a.name == "i-priv"               # no Name tag → falls back to id
    assert a.region == "eu-west-1"


def test_ec2_missing_id_raises():
    with pytest.raises(ValueError):
        normalize_ec2_instance({}, ACCOUNT)


# ── Security Group ─────────────────────────────────────────────

def test_sg_internet_open_ssh():
    raw = {
        "GroupId": "sg-1",
        "GroupName": "web",
        "VpcId": "vpc-1",
        "Region": "us-east-1",
        "IpPermissions": [
            {"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        ],
    }
    a = normalize_security_group(raw, ACCOUNT)
    assert a.asset_type == "aws.ec2.security_group"
    # A security group has no address and nothing routes to it. The open rule
    # is recorded as configuration; the exposure belongs to whatever attaches.
    assert a.is_public is False
    assert a.network_exposure == "vpc"
    assert a.properties["world_open"] is True
    assert a.properties["open_ports"] == [22]      # 443 is internal-only, excluded
    assert a.properties["open_port_labels"] == ["SSH"]
    assert a.properties["wide_open_cidrs"] == []   # 10.0.0.0/8 is private, not exposure


def test_sg_wide_public_cidr_flagged():
    raw = {"GroupId": "sg-wide", "IpPermissions": [
        {"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "13.0.0.0/8"}]},      # public /8 → flag
        {"FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "203.0.113.5/32"}]},  # single host → skip
    ]}
    a = normalize_security_group(raw, ACCOUNT)
    wide = a.properties["wide_open_cidrs"]
    assert [w["cidr"] for w in wide] == ["13.0.0.0/8"]
    assert wide[0]["prefix"] == 8 and wide[0]["port"] == 22


def test_sg_all_ports_via_null_portrange():
    raw = {
        "GroupId": "sg-all",
        "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],  # no From/To = all
    }
    a = normalize_security_group(raw, ACCOUNT)
    assert a.properties["open_ports"] == [0]
    assert a.properties["open_port_labels"] == ["ALL"]


def test_sg_ipv6_world_open():
    raw = {"GroupId": "sg-6", "IpPermissions": [
        {"FromPort": 3389, "ToPort": 3389, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]}
    a = normalize_security_group(raw, ACCOUNT)
    assert a.properties["open_ports"] == [3389]
    assert a.properties["world_open"] is True
    assert a.is_public is False


def test_sg_no_world_exposure_is_private():
    raw = {"GroupId": "sg-int", "IpPermissions": [
        {"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}
    a = normalize_security_group(raw, ACCOUNT)
    assert a.is_public is False
    assert a.properties["world_open"] is False
    assert a.network_exposure == "vpc"
    assert a.properties["open_ports"] == []


# ── IAM role ───────────────────────────────────────────────────

def test_iam_role_publicly_assumable():
    raw = {
        "RoleName": "open-role",
        "Arn": "arn:aws:iam::123456789012:role/open-role",
        "Path": "/",
        "AssumeRolePolicyDocument": {
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]
        },
        "has_admin": True,
        "admin_reason": "managed policy AdministratorAccess",
        "privesc_actions": ["iam:PassRole"],
        "assume_role_resources": ["arn:aws:iam::123456789012:role/data-role"],
        "s3_read_resources": ["arn:aws:s3:::customer-data/*"],
        "policy_analysis_complete": True,
    }
    a = normalize_iam_role(raw, ACCOUNT)
    assert a.asset_type == "aws.iam.role"
    assert a.region == "global"
    assert a.is_public is True
    assert a.network_exposure == "public"
    assert a.properties["publicly_assumable"] is True
    assert a.properties["trust_external"] is True
    assert a.properties["has_admin"] is True
    assert a.properties["privesc_actions"] == ["iam:PassRole"]
    assert a.properties["assume_role_resources"] == ["arn:aws:iam::123456789012:role/data-role"]
    assert a.properties["s3_read_resources"] == ["arn:aws:s3:::customer-data/*"]
    assert a.properties["policy_analysis_complete"] is True


def test_iam_role_federated_oidc_captured():
    gha = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    raw = {
        "RoleName": "gha-deploy",
        "AssumeRolePolicyDocument": {
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": gha},
                "Action": "sts:AssumeRoleWithWebIdentity",
            }]
        },
    }
    a = normalize_iam_role(raw, ACCOUNT)
    assert a.properties["trust_federated"] == [gha]
    # an OIDC federation is not a wildcard AWS trust
    assert a.properties["publicly_assumable"] is False


def test_iam_role_scoped_trust_is_private():
    raw = {
        "RoleName": "svc-role",
        "AssumeRolePolicyDocument": {
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]
        },
    }
    a = normalize_iam_role(raw, ACCOUNT)
    assert a.is_public is False
    assert a.network_exposure == "private"
    # arn synthesized when not supplied
    assert a.resource_id == "arn:aws:iam::123456789012:role/svc-role"


def test_iam_role_trust_doc_as_json_string():
    raw = {
        "RoleName": "str-trust",
        "AssumeRolePolicyDocument": '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"}}]}',
    }
    a = normalize_iam_role(raw, ACCOUNT)
    assert a.is_public is True


def test_iam_role_wildcard_principal_string_is_public():
    raw = {
        "RoleName": "open-string-principal",
        "AssumeRolePolicyDocument": {
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
        },
    }
    a = normalize_iam_role(raw, ACCOUNT)
    assert a.is_public is True
    assert a.properties["publicly_assumable"] is True


# ── RDS ────────────────────────────────────────────────────────

def test_rds_public_unencrypted():
    raw = {
        "DBInstanceIdentifier": "prod-db",
        "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:prod-db",
        "Engine": "postgres",
        "Endpoint": {"Address": "prod-db.abc.rds.amazonaws.com", "Port": 5432},
        "DBSubnetGroup": {"VpcId": "vpc-1", "Subnets": [{"SubnetIdentifier": "subnet-db"}]},
        "PubliclyAccessible": True,
        "StorageEncrypted": False,
    }
    a = normalize_rds_instance(raw, ACCOUNT)
    assert a.asset_type == "aws.rds.db_instance"
    # PubliclyAccessible is endpoint configuration. It is not a proven packet
    # path until the graph has SG, route, IGW and NACL evidence.
    assert a.is_public is False
    assert a.encryption_enabled is False
    assert a.network_exposure == "vpc"
    assert a.properties["publicly_accessible"] is True
    assert a.properties["subnet_ids"] == ["subnet-db"]
    assert a.properties["port"] == 5432
    assert a.resource_id == "arn:aws:rds:us-east-1:123456789012:db:prod-db"


def test_rds_private_encrypted_synth_arn():
    raw = {"DBInstanceIdentifier": "int-db", "Region": "eu-west-1",
           "PubliclyAccessible": False, "StorageEncrypted": True}
    a = normalize_rds_instance(raw, ACCOUNT)
    assert a.is_public is False
    assert a.encryption_enabled is True
    assert a.network_exposure == "vpc"
    assert a.resource_id == "arn:aws:rds:eu-west-1:123456789012:db:int-db"


def test_network_topology_normalizers_keep_reachability_evidence():
    route_table = normalize_ec2_route_table({
        "RouteTableId": "rtb-1", "Region": "us-east-1", "VpcId": "vpc-1",
        "Associations": [{"SubnetId": "subnet-1"}],
        "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1", "State": "active"}],
    }, ACCOUNT)
    network_acl = normalize_ec2_network_acl({
        "NetworkAclId": "acl-1", "Region": "us-east-1", "VpcId": "vpc-1", "IsDefault": True,
        "Associations": [{"SubnetId": "subnet-1"}],
        "Entries": [{"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "Egress": False,
                     "CidrBlock": "0.0.0.0/0"}],
    }, ACCOUNT)
    gateway = normalize_ec2_internet_gateway({
        "InternetGatewayId": "igw-1", "Region": "us-east-1",
        "Attachments": [{"VpcId": "vpc-1", "State": "available"}],
    }, ACCOUNT)

    assert route_table.properties["routes"][0]["gateway_id"] == "igw-1"
    assert route_table.properties["associations"][0]["subnet_id"] == "subnet-1"
    assert network_acl.properties["entries"][0]["rule_action"] == "allow"
    assert gateway.properties["attached_vpc_ids"] == ["vpc-1"]


# ── Registry ───────────────────────────────────────────────────

@pytest.mark.parametrize("source_type,expected", [
    ("ec2:instance", normalize_ec2_instance),
    ("aws.ec2.instance", normalize_ec2_instance),
    ("ec2:security-group", normalize_security_group),
    ("aws.ec2.security_group", normalize_security_group),
    ("iam:role", normalize_iam_role),
    ("aws.iam.role", normalize_iam_role),
    ("rds:instance", normalize_rds_instance),
    ("aws.rds.db_instance", normalize_rds_instance),
])
def test_registry_resolves(source_type, expected):
    assert get_normalizer(source_type) is expected


def test_registry_unknown_returns_none():
    assert get_normalizer("aws.unknown.thing") is None
