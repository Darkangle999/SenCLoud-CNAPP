"""Network-reachability proof coverage.

The three cases that matter most here are the ones a single-subnet fixture set
cannot express: a multi-AZ DB subnet group, a network ACL whose egress range is
tighter than the AWS default, and an address family that is open on the security
group but not on the route.
"""

from __future__ import annotations

import pytest

from odineyes.inventory.reachability import (
    assess_ec2_internet_reachability,
    assess_rds_internet_reachability,
)
from odineyes.inventory.schema import NormalizedAsset

ACCOUNT = "123456789012"
PORT = 5432
VPC = "vpc-1"


def _asset(asset_type: str, resource_id: str, properties: dict, relationships=None):
    return NormalizedAsset(
        resource_id=resource_id, cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type=asset_type, properties=properties, relationships=relationships or [],
    )


def sg(*, cidr="0.0.0.0/0", port=PORT, legacy_ports=None, sg_id="sg-1"):
    properties: dict = {}
    if legacy_ports is None:
        properties["world_open_ingress"] = [
            {"cidr": cidr, "protocol": "tcp", "from_port": port, "to_port": port}
        ]
    else:
        properties["open_ports"] = legacy_ports
    return _asset(
        "aws.ec2.security_group",
        f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/{sg_id}",
        properties,
    )


def igw(gateway_id="igw-1", attached=VPC):
    return _asset(
        "aws.ec2.internet_gateway",
        f"arn:aws:ec2:us-east-1:{ACCOUNT}:internet-gateway/{gateway_id}",
        {"attached_vpc_ids": [attached] if attached else []},
    )


def route_table(rtb_id, subnet_id, *, routes):
    return _asset(
        "aws.ec2.route_table",
        f"arn:aws:ec2:us-east-1:{ACCOUNT}:route-table/{rtb_id}",
        {"vpc_id": VPC, "associations": [{"subnet_id": subnet_id}], "routes": routes},
    )


def default_route(destination="0.0.0.0/0", gateway_id="igw-1"):
    return {"destination_cidr_block": destination, "state": "active", "gateway_id": gateway_id}


def nacl(acl_id, subnet_ids, entries):
    return _asset(
        "aws.ec2.network_acl",
        f"arn:aws:ec2:us-east-1:{ACCOUNT}:network-acl/{acl_id}",
        {"vpc_id": VPC, "subnet_ids": subnet_ids, "is_default": False, "entries": entries},
    )


def entry(*, egress, action="allow", number=100, cidr="0.0.0.0/0",
          protocol="-1", from_port=None, to_port=None):
    return {
        "rule_number": number, "protocol": protocol, "rule_action": action,
        "egress": egress, "cidr_block": cidr,
        "from_port": from_port, "to_port": to_port,
    }


def open_nacl(acl_id="acl-1", subnet_ids=("subnet-a",)):
    return nacl(acl_id, list(subnet_ids), [entry(egress=False), entry(egress=True)])


def database(subnet_ids=("subnet-a",), *, public=True, port=PORT, sg_ids=("sg-1",)):
    return _asset(
        "aws.rds.db_instance", f"arn:aws:rds:us-east-1:{ACCOUNT}:db:prod",
        {"publicly_accessible": public, "port": port, "vpc_id": VPC,
         "subnet_ids": list(subnet_ids)},
        [{"type": "USES_SECURITY_GROUP", "target_id": sg_id} for sg_id in sg_ids],
    )


def _assess(db, assets):
    return assess_rds_internet_reachability(db, assets)


# ── the baseline the contract describes ───────────────────────


def instance(*, public=True, sg_ids=("sg-1",)):
    return _asset(
        "aws.ec2.instance",
        f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-web",
        {
            "public_ip": "203.0.113.10" if public else None,
            "vpc_id": VPC,
            "subnet_id": "subnet-a",
            "security_group_ids": list(sg_ids),
        },
        [{"type": "USES_SECURITY_GROUP", "target_id": sg_id} for sg_id in sg_ids],
    )


def test_ec2_complete_path_is_reachable():
    result = assess_ec2_internet_reachability(instance(), 22, [
        sg(port=22), igw(),
        route_table("rtb-pub", "subnet-a", routes=[default_route()]),
        open_nacl(),
    ])
    assert result.status == "reachable"
    assert {item["source"] for item in result.evidence} == {
        "ec2:DescribeInstances", "ec2:DescribeSecurityGroups",
        "ec2:DescribeInternetGateways", "ec2:DescribeRouteTables",
        "ec2:DescribeNetworkAcls",
    }


def test_ec2_public_ip_without_route_evidence_is_unverified():
    result = assess_ec2_internet_reachability(instance(), 22, [
        sg(port=22), igw(), open_nacl(),
    ])
    assert result.status == "unverified"
    assert "EC2 route tables" in result.missing


def test_ec2_private_instance_is_not_applicable():
    assert assess_ec2_internet_reachability(
        instance(public=False), 22, []
    ).status == "not_applicable"


def test_complete_ipv4_path_is_reachable():
    result = _assess(database(), [
        sg(), igw(), route_table("rtb-pub", "subnet-a", routes=[default_route()]), open_nacl(),
    ])
    assert result.status == "reachable"
    assert result.missing == [] and result.blockers == []
    assert set(result.as_dict()) == {"status", "evidence", "missing", "blockers"}
    sources = {item["source"] for item in result.evidence}
    assert sources == {
        "rds:DescribeDBInstances", "ec2:DescribeSecurityGroups",
        "ec2:DescribeInternetGateways", "ec2:DescribeRouteTables", "ec2:DescribeNetworkAcls",
    }


def test_private_endpoint_is_not_applicable():
    assert _assess(database(public=False), []).status == "not_applicable"


def test_closed_security_group_blocks_before_any_network_lookup():
    result = _assess(database(), [sg(port=3306), igw(), open_nacl()])
    assert result.status == "blocked"
    assert "no attached security group allows the world to TCP port 5432" in result.blockers


def test_missing_route_tables_is_unverified_not_blocked():
    result = _assess(database(), [sg(), igw(), open_nacl()])
    assert result.status == "unverified"
    assert "EC2 route tables" in result.missing


def test_unattached_internet_gateway_blocks():
    result = _assess(database(), [
        sg(), igw(attached=None),
        route_table("rtb-pub", "subnet-a", routes=[default_route()]), open_nacl(),
    ])
    assert result.status == "blocked"
    assert result.blockers == ["internet gateway igw-1 is not attached to vpc-1"]


# ── bug 1: one proven subnet is enough ────────────────────────


def test_public_subnet_wins_over_a_private_sibling_subnet():
    """A DB subnet group spans AZs. One public subnet makes the database
    reachable — the private sibling does not undo that."""
    result = _assess(database(("subnet-a", "subnet-b")), [
        sg(), igw(),
        route_table("rtb-pub", "subnet-a", routes=[default_route()]),
        route_table("rtb-priv", "subnet-b", routes=[]),
        open_nacl(subnet_ids=("subnet-a", "subnet-b")),
    ])
    assert result.status == "reachable"
    # The unusable sibling stays visible as evidence, not as a veto.
    assert result.blockers == [
        "subnet-b (ipv4) has no active default route to an internet gateway"
    ]


def test_subnet_order_does_not_change_the_verdict():
    assets = [
        sg(), igw(),
        route_table("rtb-pub", "subnet-a", routes=[default_route()]),
        route_table("rtb-priv", "subnet-b", routes=[]),
        open_nacl(subnet_ids=("subnet-a", "subnet-b")),
    ]
    forward = _assess(database(("subnet-a", "subnet-b")), assets)
    reverse = _assess(database(("subnet-b", "subnet-a")), assets)
    assert forward.status == reverse.status == "reachable"


def test_all_subnets_private_is_blocked():
    result = _assess(database(("subnet-a", "subnet-b")), [
        sg(), igw(),
        route_table("rtb-priv-a", "subnet-a", routes=[]),
        route_table("rtb-priv-b", "subnet-b", routes=[]),
        open_nacl(subnet_ids=("subnet-a", "subnet-b")),
    ])
    assert result.status == "blocked"
    assert len(result.blockers) == 2


def test_missing_evidence_on_one_subnet_outranks_a_blocker_on_another():
    """An unevaluable subnet may be the open one. Never call that blocked."""
    result = _assess(database(("subnet-a", "subnet-b")), [
        sg(), igw(),
        route_table("rtb-priv", "subnet-a", routes=[]),
        route_table("rtb-pub", "subnet-b", routes=[default_route(gateway_id="igw-missing")]),
        open_nacl(subnet_ids=("subnet-a", "subnet-b")),
    ])
    assert result.status == "unverified"
    assert result.missing == ["internet gateway igw-missing"]


# ── bug 2: ephemeral return traffic is a range ────────────────


@pytest.mark.parametrize("low,high", [(1024, 65535), (32768, 65535), (49152, 65535)])
def test_tightened_nacl_egress_ranges_still_permit_the_response(low, high):
    result = _assess(database(), [
        sg(), igw(), route_table("rtb-pub", "subnet-a", routes=[default_route()]),
        nacl("acl-1", ["subnet-a"], [
            entry(egress=False, protocol="tcp", from_port=PORT, to_port=PORT),
            entry(egress=True, protocol="tcp", from_port=low, to_port=high),
        ]),
    ])
    assert result.status == "reachable"


def test_nacl_egress_outside_the_ephemeral_range_blocks():
    result = _assess(database(), [
        sg(), igw(), route_table("rtb-pub", "subnet-a", routes=[default_route()]),
        nacl("acl-1", ["subnet-a"], [
            entry(egress=False, protocol="tcp", from_port=PORT, to_port=PORT),
            entry(egress=True, protocol="tcp", from_port=80, to_port=443),
        ]),
    ])
    assert result.status == "blocked"
    assert "blocks return traffic to ephemeral ports 1024-65535" in result.blockers[0]


def test_low_numbered_partial_deny_does_not_hide_a_broader_allow():
    """A deny on 1024-2000 leaves 2001-65535 undecided; the later allow wins."""
    result = _assess(database(), [
        sg(), igw(), route_table("rtb-pub", "subnet-a", routes=[default_route()]),
        nacl("acl-1", ["subnet-a"], [
            entry(egress=False, protocol="tcp", from_port=PORT, to_port=PORT),
            entry(egress=True, action="deny", number=50, protocol="tcp",
                  from_port=1024, to_port=2000),
            entry(egress=True, action="allow", number=100, protocol="tcp",
                  from_port=1024, to_port=65535),
        ]),
    ])
    assert result.status == "reachable"


def test_low_numbered_full_deny_beats_a_later_allow():
    result = _assess(database(), [
        sg(), igw(), route_table("rtb-pub", "subnet-a", routes=[default_route()]),
        nacl("acl-1", ["subnet-a"], [
            entry(egress=False, protocol="tcp", from_port=PORT, to_port=PORT),
            entry(egress=True, action="deny", number=50),
            entry(egress=True, action="allow", number=100),
        ]),
    ])
    assert result.status == "blocked"


def test_inbound_deny_on_the_database_port_blocks():
    result = _assess(database(), [
        sg(), igw(), route_table("rtb-pub", "subnet-a", routes=[default_route()]),
        nacl("acl-1", ["subnet-a"], [
            entry(egress=False, action="deny", number=50, protocol="tcp",
                  from_port=PORT, to_port=PORT),
            entry(egress=False, action="allow", number=100),
            entry(egress=True),
        ]),
    ])
    assert result.status == "blocked"
    assert "blocks world ingress to port 5432" in result.blockers[0]


# ── bug 3: address families must match end to end ─────────────


def test_ipv6_security_group_with_only_an_ipv4_route_is_not_reachable():
    result = _assess(database(), [
        sg(cidr="::/0"), igw(),
        route_table("rtb-pub", "subnet-a", routes=[default_route()]),
        open_nacl(),
    ])
    assert result.status == "blocked"
    assert result.blockers == [
        "subnet-a (ipv6) has no active default route to an internet gateway"
    ]


def test_ipv6_path_proves_when_every_hop_is_ipv6():
    result = _assess(database(), [
        sg(cidr="::/0"), igw(),
        route_table("rtb-pub", "subnet-a", routes=[default_route(destination="::/0")]),
        nacl("acl-1", ["subnet-a"], [
            entry(egress=False, cidr="::/0"), entry(egress=True, cidr="::/0"),
        ]),
    ])
    assert result.status == "reachable"


def test_egress_only_gateway_does_not_carry_inbound_ipv6():
    result = _assess(database(), [
        sg(cidr="::/0"), igw(),
        route_table("rtb-pub", "subnet-a",
                    routes=[default_route(destination="::/0", gateway_id="eigw-1")]),
        nacl("acl-1", ["subnet-a"], [
            entry(egress=False, cidr="::/0"), entry(egress=True, cidr="::/0"),
        ]),
    ])
    assert result.status == "blocked"


def test_dual_stack_proves_through_whichever_family_completes():
    ipv6_only_sg = _asset(
        "aws.ec2.security_group", f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/sg-1",
        {"world_open_ingress": [
            {"cidr": "0.0.0.0/0", "protocol": "tcp", "from_port": PORT, "to_port": PORT},
            {"cidr": "::/0", "protocol": "tcp", "from_port": PORT, "to_port": PORT},
        ]},
    )
    result = _assess(database(), [
        ipv6_only_sg, igw(),
        # Only the IPv6 default route exists.
        route_table("rtb-pub", "subnet-a", routes=[default_route(destination="::/0")]),
        nacl("acl-1", ["subnet-a"], [
            entry(egress=False, cidr="::/0"), entry(egress=True, cidr="::/0"),
        ]),
    ])
    assert result.status == "reachable"


def test_legacy_open_ports_evidence_asserts_ipv4_only():
    """The pre-migration projection carries no address family, so it must not be
    used to claim an IPv6 path."""
    result = _assess(database(), [
        sg(legacy_ports=[PORT]), igw(),
        route_table("rtb-pub", "subnet-a", routes=[default_route(destination="::/0")]),
        nacl("acl-1", ["subnet-a"], [
            entry(egress=False, cidr="::/0"), entry(egress=True, cidr="::/0"),
        ]),
    ])
    assert result.status == "blocked"
    assert result.blockers == [
        "subnet-a (ipv4) has no active default route to an internet gateway"
    ]


# ── route-table association semantics ─────────────────────────


def test_unassociated_subnet_falls_back_to_the_main_route_table():
    main = _asset(
        "aws.ec2.route_table", f"arn:aws:ec2:us-east-1:{ACCOUNT}:route-table/rtb-main",
        {"vpc_id": VPC, "associations": [{"main": True}], "routes": [default_route()]},
    )
    result = _assess(database(), [sg(), igw(), main, open_nacl()])
    assert result.status == "reachable"


def test_inactive_default_route_does_not_count():
    result = _assess(database(), [
        sg(), igw(),
        route_table("rtb-pub", "subnet-a", routes=[
            {"destination_cidr_block": "0.0.0.0/0", "state": "blackhole", "gateway_id": "igw-1"},
        ]),
        open_nacl(),
    ])
    assert result.status == "blocked"


# ── topology index ────────────────────────────────────────────


def test_prebuilt_topology_matches_the_per_call_form():
    """The index is a performance change only — same inputs, same verdict."""
    from odineyes.inventory.reachability import build_network_topology

    assets = [
        sg(), igw(), route_table("rtb-pub", "subnet-a", routes=[default_route()]), open_nacl(),
    ]
    db = database()
    inline = assess_rds_internet_reachability(db, assets)
    indexed = assess_rds_internet_reachability(db, topology=build_network_topology(assets))
    assert inline.as_dict() == indexed.as_dict()


def test_topology_indexes_every_network_asset_type_once():
    from odineyes.inventory.reachability import build_network_topology

    topology = build_network_topology([
        sg(), igw(),
        route_table("rtb-pub", "subnet-a", routes=[default_route()]),
        open_nacl(),
        _asset("aws.ec2.instance", "arn:i-1", {}),
    ])
    assert set(topology.security_groups) == {"sg-1"}
    assert set(topology.gateways) == {"igw-1"}
    assert set(topology.route_table_by_subnet) == {(VPC, "subnet-a")}
    assert set(topology.acl_by_subnet) == {(VPC, "subnet-a")}
    assert topology.has_route_tables and topology.has_network_acls


def test_topology_indexes_the_main_route_table_and_default_acl_separately():
    from odineyes.inventory.reachability import build_network_topology

    main = _asset(
        "aws.ec2.route_table", f"arn:aws:ec2:us-east-1:{ACCOUNT}:route-table/rtb-main",
        {"vpc_id": VPC, "associations": [{"main": True}], "routes": [default_route()]},
    )
    default = _asset(
        "aws.ec2.network_acl", f"arn:aws:ec2:us-east-1:{ACCOUNT}:network-acl/acl-def",
        {"vpc_id": VPC, "subnet_ids": [], "is_default": True, "entries": []},
    )
    topology = build_network_topology([main, default])
    assert topology.route_table_by_subnet == {}
    assert topology.main_route_table[VPC] is main
    assert topology.default_acl[VPC] is default
