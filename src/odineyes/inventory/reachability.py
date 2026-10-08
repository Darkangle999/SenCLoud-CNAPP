"""Evidence-conservative AWS network reachability checks.

The inventory flag ``PubliclyAccessible`` means that RDS has a public endpoint
configuration. It does *not* prove a packet can arrive from the internet. This
module keeps the two facts separate and only returns ``reachable`` when the
collected security group, route table, internet gateway and network ACL evidence
prove one complete path.

One proven path is enough. A DB subnet group normally spans several availability
zones, and a database sitting in a public subnet is internet-reachable even when
its sibling subnets are private — so subnets are evaluated independently and the
verdict is the best proven path, not the worst.

Address families are proven end to end: an IPv6-only security group rule cannot
be combined with an IPv4 default route to claim reachability. Private CIDRs,
Transit Gateway paths, firewalls, VPC endpoints and service network policies are
reported as unverified rather than guessed.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Optional

_WORLD_CIDR = {"ipv4": "0.0.0.0/0", "ipv6": "::/0"}
# The source port a client picks. AWS documents 1024-65535 as the ephemeral
# range to open on a NACL; Linux and NLB actually draw from 32768-65535. A
# stateless ACL only has to permit *some* of that range for the response to get
# back, so this is an overlap test, not a membership test for one port.
_RETURN_PORTS = (1024, 65535)
_MAX_PORT = 65535
_TCP_PROTOCOLS = {"-1", "6", "tcp"}


@dataclass(frozen=True)
class ReachabilityAssessment:
    """A conclusion and the exact evidence used to reach it.

    There is deliberately no ``confidence`` field. ``status`` plus the length of
    ``missing`` already say everything a confidence label could: a verdict with
    nothing missing is proven, and one with gaps is ``unverified`` by
    construction. A second, hand-set score would only be able to disagree.
    """

    status: str  # reachable | blocked | unverified | not_applicable
    evidence: list[dict[str, str]] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class NetworkTopology:
    """Account network evidence, indexed once.

    Building this per database made the evaluator O(assets x databases): four
    full scans of the asset set for every database assessed. On a 26k-asset
    account with 500 public databases that measured 14.4s; hoisting it makes
    the scans happen once.
    """

    security_groups: dict[str, Any] = field(default_factory=dict)
    gateways: dict[str, Any] = field(default_factory=dict)
    # (vpc_id, subnet_id) -> the explicitly associated route table / ACL, with a
    # per-VPC fallback for the main route table and the default ACL, which is
    # what an unassociated subnet actually uses.
    route_table_by_subnet: dict[tuple[str, str], Any] = field(default_factory=dict)
    main_route_table: dict[str, Any] = field(default_factory=dict)
    acl_by_subnet: dict[tuple[str, str], Any] = field(default_factory=dict)
    default_acl: dict[str, Any] = field(default_factory=dict)
    has_route_tables: bool = False
    has_network_acls: bool = False


def build_network_topology(assets: Iterable[Any]) -> NetworkTopology:
    """Index the network assets once for reuse across every database."""
    topology = NetworkTopology()
    for asset in assets:
        asset_type = getattr(asset, "asset_type", "")
        properties = getattr(asset, "properties", {}) or {}
        if asset_type == "aws.ec2.security_group":
            topology.security_groups[_short_id(asset)] = asset
        elif asset_type == "aws.ec2.internet_gateway":
            topology.gateways[_short_id(asset)] = asset
        elif asset_type == "aws.ec2.route_table":
            object.__setattr__(topology, "has_route_tables", True)
            vpc_id = str(properties.get("vpc_id") or "")
            for association in properties.get("associations") or []:
                subnet_id = association.get("subnet_id")
                if subnet_id:
                    topology.route_table_by_subnet.setdefault((vpc_id, str(subnet_id)), asset)
                elif association.get("main"):
                    topology.main_route_table.setdefault(vpc_id, asset)
        elif asset_type == "aws.ec2.network_acl":
            object.__setattr__(topology, "has_network_acls", True)
            vpc_id = str(properties.get("vpc_id") or "")
            for subnet_id in properties.get("subnet_ids") or []:
                topology.acl_by_subnet.setdefault((vpc_id, str(subnet_id)), asset)
            if properties.get("is_default"):
                topology.default_acl.setdefault(vpc_id, asset)
    return topology


def public_endpoint_configured(asset: Any) -> bool:
    """RDS endpoint configuration, with compatibility for pre-migration rows."""
    props = getattr(asset, "properties", {}) or {}
    return bool(props.get("publicly_accessible", getattr(asset, "is_public", False)))


def assess_ec2_internet_reachability(
    instance: Any,
    port: int,
    assets: Iterable[Any] | None = None,
    *,
    topology: NetworkTopology | None = None,
) -> ReachabilityAssessment:
    """Prove or refuse an Internet-to-EC2 TCP path.

    A public IP and a world-open security-group rule are necessary but not
    sufficient. The subnet also needs an active route through an attached
    Internet gateway, and its stateless network ACL must permit the request and
    response.
    """
    if getattr(instance, "asset_type", "") != "aws.ec2.instance":
        return ReachabilityAssessment("not_applicable")

    properties = getattr(instance, "properties", {}) or {}
    public_ip = properties.get("public_ip")
    if not public_ip and not getattr(instance, "is_public", False):
        return ReachabilityAssessment("not_applicable")

    if topology is None:
        topology = build_network_topology(assets or [])

    vpc_id = str(properties.get("vpc_id") or "")
    subnet_id = str(properties.get("subnet_id") or "")
    sg_ids = _relation_ids(instance, "USES_SECURITY_GROUP") or [
        str(value) for value in properties.get("security_group_ids") or [] if value
    ]
    evidence = [_evidence(
        "ec2:DescribeInstances",
        f"PublicIpAddress = {public_ip or 'present in legacy inventory'}",
        "instance has a public IPv4 address",
    )]
    missing: list[str] = []

    if not sg_ids:
        missing.append("attached EC2 security groups")
    resolved_sgs = [
        topology.security_groups[sg_id]
        for sg_id in sg_ids
        if sg_id in topology.security_groups
    ]
    if sg_ids and len(resolved_sgs) != len(set(sg_ids)):
        missing.append("one or more attached EC2 security groups")
    if missing:
        return ReachabilityAssessment("unverified", evidence, sorted(set(missing)))

    open_families = _security_groups_allow_world_port(resolved_sgs, port)
    # PublicIpAddress proves IPv4 only. Never join it to an IPv6-only SG rule.
    ipv4_ingress = open_families.get("ipv4")
    if not ipv4_ingress:
        return ReachabilityAssessment(
            "blocked",
            evidence,
            blockers=[f"no attached security group allows the IPv4 world to TCP port {port}"],
        )
    evidence.append(ipv4_ingress)

    if not subnet_id:
        missing.append("EC2 subnet ID")
    if not vpc_id:
        missing.append("EC2 VPC ID")
    if not topology.has_route_tables:
        missing.append("EC2 route tables")
    if not topology.gateways:
        missing.append("internet gateways")
    if not topology.has_network_acls:
        missing.append("network ACLs")
    if missing:
        return ReachabilityAssessment("unverified", evidence, sorted(set(missing)))

    path = _assess_subnet_path(
        subnet_id=subnet_id,
        family="ipv4",
        vpc_id=vpc_id,
        port=port,
        topology=topology,
    )
    if path.evidence:
        return ReachabilityAssessment("reachable", evidence + path.evidence)
    if path.missing:
        return ReachabilityAssessment(
            "unverified", evidence, sorted(set(path.missing)), sorted(set(path.blockers))
        )
    return ReachabilityAssessment("blocked", evidence, blockers=sorted(set(path.blockers)))


def assess_rds_internet_reachability(
    database: Any,
    assets: Iterable[Any] | None = None,
    *,
    topology: NetworkTopology | None = None,
) -> ReachabilityAssessment:
    """Prove or refuse to prove a world-to-RDS network path.

    A `blocked` response is useful evidence, but never becomes an Internet graph
    edge. `unverified` is also intentionally not an edge: no collection gap is
    allowed to become an attack path.

    Pass ``topology`` when assessing more than one database over the same asset
    set; ``assets`` is the convenience form that indexes them for a single call.
    """
    if not public_endpoint_configured(database):
        return ReachabilityAssessment("not_applicable")

    if topology is None:
        topology = build_network_topology(assets or [])
    props = getattr(database, "properties", {}) or {}
    port = _as_int(props.get("port"))
    vpc_id = str(props.get("vpc_id") or "")
    subnet_ids = [str(value) for value in props.get("subnet_ids") or [] if value]
    sg_ids = _relation_ids(database, "USES_SECURITY_GROUP") or [
        str(value) for value in props.get("security_group_ids") or [] if value
    ]

    sg_by_id = topology.security_groups

    evidence = [
        _evidence("rds:DescribeDBInstances", "PubliclyAccessible = true", "public endpoint configured"),
    ]
    missing: list[str] = []
    blockers: list[str] = []

    if port is None:
        missing.append("RDS endpoint port")
    if not sg_ids:
        missing.append("attached RDS security groups")
    resolved_sgs = [sg_by_id[sg_id] for sg_id in sg_ids if sg_id in sg_by_id]
    if sg_ids and len(resolved_sgs) != len(set(sg_ids)):
        missing.append("one or more attached RDS security groups")

    if missing:
        return ReachabilityAssessment("unverified", evidence, missing, blockers)

    open_families = _security_groups_allow_world_port(resolved_sgs, port)
    if not open_families:
        blockers.append(f"no attached security group allows the world to TCP port {port}")
        evidence.append(_evidence(
            "ec2:DescribeSecurityGroups",
            f"attached groups: {', '.join(sorted(sg_ids))}; no world ingress to port {port}",
            "security group blocks public inbound traffic",
        ))
        return ReachabilityAssessment("blocked", evidence, missing, blockers)
    for family_evidence in open_families.values():
        evidence.append(family_evidence)

    if not subnet_ids:
        missing.append("RDS DB subnet group subnets")
    if not topology.has_route_tables:
        missing.append("EC2 route tables")
    if not topology.gateways:
        missing.append("internet gateways")
    if not topology.has_network_acls:
        missing.append("network ACLs")
    if not vpc_id:
        missing.append("RDS VPC ID")
    if missing:
        return ReachabilityAssessment("unverified", evidence, missing, blockers)

    # Each (subnet, address family) is an independent candidate path. One that
    # completes makes the database reachable regardless of what the others do.
    proven: Optional[list[dict[str, str]]] = None
    for subnet_id in subnet_ids:
        for family in sorted(open_families):
            path = _assess_subnet_path(
                subnet_id=subnet_id,
                family=family,
                vpc_id=vpc_id,
                port=port,
                topology=topology,
            )
            missing.extend(path.missing)
            blockers.extend(path.blockers)
            if path.evidence and proven is None:
                proven = path.evidence

    if proven is not None:
        return ReachabilityAssessment(
            "reachable", evidence + proven, [], sorted(set(blockers))
        )
    # No path completed. Missing evidence outranks a blocker: a path we could
    # not evaluate may well be open, and calling that "blocked" hides exposure.
    if missing:
        return ReachabilityAssessment(
            "unverified", evidence, sorted(set(missing)), sorted(set(blockers))
        )
    return ReachabilityAssessment("blocked", evidence, [], sorted(set(blockers)))


@dataclass(frozen=True)
class _SubnetPath:
    """One (subnet, family) candidate. ``evidence`` non-empty means proven."""

    evidence: list[dict[str, str]] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)


def _assess_subnet_path(
    *,
    subnet_id: str,
    family: str,
    vpc_id: str,
    port: int,
    topology: NetworkTopology,
) -> _SubnetPath:
    """Prove or refuse one subnet's path for one address family."""
    label = f"{subnet_id} ({family})"

    # An unassociated subnet uses the VPC's main route table.
    route_table = topology.route_table_by_subnet.get(
        (vpc_id, subnet_id), topology.main_route_table.get(vpc_id)
    )
    if route_table is None:
        return _SubnetPath(missing=[f"route-table association for {subnet_id}"])

    route = _active_igw_default_route(route_table, family)
    if route is None:
        return _SubnetPath(blockers=[
            f"{label} has no active default route to an internet gateway"
        ])

    gateway_id = str(route.get("gateway_id") or "")
    gateway = topology.gateways.get(gateway_id)
    if gateway is None:
        return _SubnetPath(missing=[f"internet gateway {gateway_id}"])

    attached_vpcs = set((getattr(gateway, "properties", {}) or {}).get("attached_vpc_ids") or [])
    if vpc_id not in attached_vpcs:
        return _SubnetPath(blockers=[f"internet gateway {gateway_id} is not attached to {vpc_id}"])

    # An unassociated subnet falls under the VPC's default ACL.
    nacl = topology.acl_by_subnet.get(
        (vpc_id, subnet_id), topology.default_acl.get(vpc_id)
    )
    if nacl is None:
        return _SubnetPath(missing=[f"network ACL association for {subnet_id}"])

    inbound = _nacl_allows_world(nacl, family, egress=False, ports=(port, port))
    outbound = _nacl_allows_world(nacl, family, egress=True, ports=_RETURN_PORTS)
    blockers: list[str] = []
    if not inbound:
        blockers.append(f"network ACL for {label} blocks world ingress to port {port}")
    if not outbound:
        low, high = _RETURN_PORTS
        blockers.append(
            f"network ACL for {label} blocks return traffic to ephemeral ports {low}-{high}"
        )
    if blockers:
        return _SubnetPath(blockers=blockers)

    nacl_name = getattr(nacl, "name", None) or _short_id(nacl)
    route_table_name = getattr(route_table, "name", None) or _short_id(route_table)
    low, high = _RETURN_PORTS
    return _SubnetPath(evidence=[
        _evidence(
            "ec2:DescribeInternetGateways",
            f"{gateway_id} is attached to {vpc_id}",
            "internet gateway is available for the route",
        ),
        _evidence(
            "ec2:DescribeRouteTables",
            f"{subnet_id} -> {gateway_id} via {route_table_name} ({family} default route)",
            "active default route to an attached internet gateway",
        ),
        _evidence(
            "ec2:DescribeNetworkAcls",
            f"{nacl_name} allows {family} world ingress to {port} and egress to {low}-{high}",
            "stateless network ACL permits request and response traffic",
        ),
    ])


def _evidence(source: str, observation: str, effect: str) -> dict[str, str]:
    return {"source": source, "observation": observation, "effect": effect}


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _family(cidr: Any) -> str:
    """IPv4 and IPv6 CIDRs share one normalized field; ':' is the discriminator."""
    return "ipv6" if ":" in str(cidr or "") else "ipv4"


def _short_id(asset: Any) -> str:
    resource_id = str(getattr(asset, "resource_id", ""))
    return resource_id.rsplit("/", 1)[-1]


def _relation_ids(asset: Any, relation_type: str) -> list[str]:
    return [
        str(relation["target_id"])
        for relation in (getattr(asset, "relationships", []) or [])
        if relation.get("type") == relation_type and relation.get("target_id")
    ]


def _security_groups_allow_world_port(
    groups: Iterable[Any], port: int
) -> dict[str, dict[str, str]]:
    """Address families whose world CIDR reaches the database port, with the
    evidence for each. A family absent here has no proven ingress, so no route
    in that family can complete a path."""
    found: dict[str, dict[str, str]] = {}
    for group in groups:
        properties = getattr(group, "properties", {}) or {}
        name = getattr(group, "name", None) or _short_id(group)
        matched = False
        for rule in properties.get("world_open_ingress") or []:
            cidr = rule.get("cidr")
            if cidr not in _WORLD_CIDR.values() or not _port_allowed(rule, port):
                continue
            matched = True
            found.setdefault(_family(cidr), _evidence(
                "ec2:DescribeSecurityGroups",
                f"{name}: {cidr} -> {rule.get('protocol')} "
                f"{rule.get('from_port')}-{rule.get('to_port')}",
                "security group permits world ingress to the database port",
            ))
        if matched:
            continue
        # Compatibility with inventory saved before structured SG evidence. The
        # legacy projection has no address family, so it can only assert IPv4.
        legacy = {_as_int(value) for value in properties.get("open_ports") or []}
        if 0 in legacy or port in legacy:
            found.setdefault("ipv4", _evidence(
                "ec2:DescribeSecurityGroups",
                f"{name}: legacy world-open port evidence includes {port}",
                "security group permits world ingress to the database port",
            ))
    return found


def _port_allowed(rule: dict[str, Any], port: int) -> bool:
    if str(rule.get("protocol") or "").lower() not in _TCP_PROTOCOLS:
        return False
    start, end = _as_int(rule.get("from_port")), _as_int(rule.get("to_port"))
    return start is None or end is None or start <= port <= end


def _active_igw_default_route(route_table: Any, family: str) -> dict[str, Any] | None:
    world = _WORLD_CIDR[family]
    for route in (getattr(route_table, "properties", {}) or {}).get("routes") or []:
        if route.get("destination_cidr_block") != world:
            continue
        if route.get("state") not in {None, "active", "Active"}:
            continue
        # Only a full internet gateway carries inbound traffic. An egress-only
        # gateway (eigw-) is outbound IPv6 and never completes this path.
        if str(route.get("gateway_id") or "").startswith("igw-"):
            return route
    return None


def _nacl_allows_world(
    nacl: Any, family: str, *, egress: bool, ports: tuple[int, int]
) -> bool:
    """Whether any port in ``ports`` is allowed for the world CIDR of ``family``.

    Network ACL rules are evaluated in rule-number order and the first match for
    a given port wins, so a low-numbered DENY only removes the ports it actually
    covers. Tracking the undecided ranges — instead of picking one "first" rule
    — is what lets a partial deny coexist with a broader allow.
    """
    world = _WORLD_CIDR[family]
    entries = [
        entry for entry in (getattr(nacl, "properties", {}) or {}).get("entries") or []
        if bool(entry.get("egress")) == egress
        and entry.get("cidr_block") == world
        and str(entry.get("protocol") or "").lower() in _TCP_PROTOCOLS
    ]
    entries.sort(key=lambda entry: _rule_number(entry))

    undecided = [ports]
    for entry in entries:
        start = _as_int(entry.get("from_port"))
        end = _as_int(entry.get("to_port"))
        rule_lo = 0 if start is None else start
        rule_hi = _MAX_PORT if end is None else end
        allows = str(entry.get("rule_action") or "").lower() == "allow"

        remaining: list[tuple[int, int]] = []
        for low, high in undecided:
            overlap_lo, overlap_hi = max(low, rule_lo), min(high, rule_hi)
            if overlap_lo > overlap_hi:
                remaining.append((low, high))
                continue
            if allows:
                return True
            if low < overlap_lo:
                remaining.append((low, overlap_lo - 1))
            if overlap_hi < high:
                remaining.append((overlap_hi + 1, high))
        undecided = remaining
        if not undecided:
            return False
    # No rule matched the remaining ports. The implicit final ACL entry denies.
    return False


def _rule_number(entry: dict[str, Any]) -> int:
    """Rule numbers order evaluation; the implicit catch-all sorts last."""
    number = _as_int(entry.get("rule_number"))
    return 32767 if number is None else number
