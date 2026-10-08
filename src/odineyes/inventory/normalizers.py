"""Raw cloud resource → NormalizedAsset translators.

Phase 1 build sequence starts with S3 to establish the pattern; the remaining
AWS types follow the same shape. A normalizer never calls the cloud API — it
only maps an already-collected raw dict, so it is pure and unit-testable.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any, Callable, Optional

from odineyes.inventory.schema import NormalizedAsset

# Ports that are high-signal when open to the world (kept in sync with the
# collector's labelling so reports read the same regardless of source).
_PORT_LABELS = {
    22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
    80: "HTTP", 443: "HTTPS", 21: "FTP", 23: "Telnet", 0: "ALL",
}


def _tags_to_dict(tags: Any) -> dict[str, Any]:
    """Accept either AWS's [{"Key","Value"}] list or an already-mapped dict."""
    if isinstance(tags, dict):
        return tags
    if isinstance(tags, list):
        return {t["Key"]: t.get("Value") for t in tags if "Key" in t}
    return {}


def _region_from_az(az: Optional[str]) -> Optional[str]:
    """us-east-1a -> us-east-1. Returns None if the AZ looks unusable."""
    if not az or len(az) < 2:
        return None
    return az[:-1] if az[-1].isalpha() else az


def _statements(doc: Any) -> list[dict[str, Any]]:
    """Flatten an IAM policy document's Statement block into a list."""
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except json.JSONDecodeError:
            return []
    stmts = doc.get("Statement", []) if isinstance(doc, dict) else []
    return stmts if isinstance(stmts, list) else [stmts]


def extract_trust_statement_evidence(trust: Any) -> list[dict[str, list[str]]]:
    """Return AWS principals and ExternalIds from Allow trust statements.

    IAM trust conditions are statement-scoped: an ExternalId only protects the
    principals in *that* statement. Retaining this small normalized slice lets
    the graph distinguish a verified Odineyes onboarding role from arbitrary
    cross-account trust without storing credentials or calling AWS during
    analysis.
    """
    evidence: list[dict[str, list[str]]] = []
    for statement in _statements(trust):
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal") or {}
        if principal == "*":
            principals = ["*"]
        elif isinstance(principal, dict):
            aws_principals = principal.get("AWS", [])
            principals = [aws_principals] if isinstance(aws_principals, str) else aws_principals
            principals = [str(value) for value in principals if value]
        else:
            principals = []

        external_ids: list[str] = []
        conditions = statement.get("Condition") or {}
        if isinstance(conditions, dict):
            for condition_values in conditions.values():
                if not isinstance(condition_values, dict):
                    continue
                for key, value in condition_values.items():
                    if str(key).lower() != "sts:externalid":
                        continue
                    values = [value] if isinstance(value, str) else value
                    if isinstance(values, list):
                        external_ids.extend(str(item) for item in values if item)
        evidence.append({
            "principals": sorted(set(principals)),
            "external_ids": sorted(set(external_ids)),
        })
    return evidence


def _bucket_is_public(raw: dict[str, Any]) -> bool:
    """A bucket counts as public if its policy status says so, or an ACL grant
    targets AllUsers / AuthenticatedUsers, unless a full public-access block is on."""
    pab = raw.get("PublicAccessBlock") or {}
    if pab and all(
        pab.get(k) is True
        for k in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")
    ):
        return False

    if (raw.get("PolicyStatus") or {}).get("IsPublic") is True:
        return True

    public_uris = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
    for grant in (raw.get("Acl") or {}).get("Grants", []):
        if (grant.get("Grantee") or {}).get("URI") in public_uris:
            return True
    return False


def normalize_s3_bucket(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    name = raw.get("Name") or raw.get("name")
    if not name:
        raise ValueError("S3 raw record missing bucket Name")

    region = raw.get("Region") or raw.get("region") or "global"
    encryption = raw.get("Encryption") or {}
    encryption_enabled = bool(encryption.get("enabled")) if encryption else False
    is_public = _bucket_is_public(raw)

    properties = {
        "versioning": raw.get("Versioning"),
        "encryption_algorithm": encryption.get("algorithm"),
        "block_public_access": raw.get("PublicAccessBlock") or {},
        "logging_enabled": raw.get("LoggingEnabled"),
        "has_bucket_policy": bool(raw.get("Policy")),
        "collection_evidence": raw.get("_Evidence") or {},
    }

    return NormalizedAsset(
        resource_id=f"arn:aws:s3:::{name}",
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.s3.bucket",
        name=name,
        region=region,
        tags=raw.get("Tags") or {},
        is_public=is_public,
        encryption_enabled=encryption_enabled,
        network_exposure="public" if is_public else "private",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
        resource_created_at=raw.get("CreationDate"),
    )


def normalize_ec2_instance(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    instance_id = raw.get("InstanceId") or raw.get("instance_id")
    if not instance_id:
        raise ValueError("EC2 raw record missing InstanceId")

    region = raw.get("Region") or _region_from_az(
        (raw.get("Placement") or {}).get("AvailabilityZone")
    ) or "global"
    public_ip = raw.get("PublicIpAddress")
    is_public = bool(public_ip)
    sg_ids = [g["GroupId"] for g in raw.get("SecurityGroups", []) if g.get("GroupId")]
    profile_arn = (raw.get("IamInstanceProfile") or {}).get("Arn")

    properties = {
        "instance_type": raw.get("InstanceType"),
        "state": (raw.get("State") or {}).get("Name"),
        "private_ip": raw.get("PrivateIpAddress"),
        "public_ip": public_ip,
        "vpc_id": raw.get("VpcId"),
        "subnet_id": raw.get("SubnetId"),
        "image_id": raw.get("ImageId"),
        "security_group_ids": sg_ids,
        "iam_instance_profile": profile_arn,
        "metadata_http_tokens": (raw.get("MetadataOptions") or {}).get("HttpTokens"),
        "metadata_endpoint": (raw.get("MetadataOptions") or {}).get("HttpEndpoint"),
        "detailed_monitoring": (raw.get("Monitoring") or {}).get("State") == "enabled",
    }

    relationships: list[dict[str, Any]] = [{"type": "BELONGS_TO", "target_id": account_identifier}]
    for sg in sg_ids:
        relationships.append({"type": "USES_SECURITY_GROUP", "target_id": sg})
    if profile_arn:
        relationships.append({"type": "USES_INSTANCE_PROFILE", "target_id": profile_arn})

    return NormalizedAsset(
        resource_id=f"arn:aws:ec2:{region}:{account_identifier}:instance/{instance_id}",
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.ec2.instance",
        name=_tags_to_dict(raw.get("Tags")).get("Name") or instance_id,
        region=region,
        tags=_tags_to_dict(raw.get("Tags")),
        is_public=is_public,
        encryption_enabled=None,  # instance-level n/a; EBS volumes track their own
        network_exposure="public" if is_public else "vpc",
        properties=properties,
        relationships=relationships,
        raw=raw,
        resource_created_at=raw.get("LaunchTime"),
    )


def _sg_world_open_ports(raw: dict[str, Any]) -> list[int]:
    """Ports reachable from 0.0.0.0/0 or ::/0. Port 0 means all-ports/all-protocols."""
    open_ports: set[int] = set()
    for rule in raw.get("IpPermissions", []):
        open_to_world = any(
            r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])
        ) or any(
            r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", [])
        )
        if not open_to_world:
            continue
        frm, to = rule.get("FromPort"), rule.get("ToPort")
        if frm is None and to is None:
            open_ports.add(0)
        else:
            open_ports.add(int(frm))
    return sorted(open_ports)


def _sg_world_open_ingress(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Preserve full world-open ingress ranges for port-aware reachability.

    ``open_ports`` remains a compact UI/rule projection. It cannot represent a
    port range such as 5000-6000, so graph proof uses this structured evidence.
    """
    result: list[dict[str, Any]] = []
    for rule in raw.get("IpPermissions", []):
        protocol = str(rule.get("IpProtocol") or "-1")
        from_port, to_port = rule.get("FromPort"), rule.get("ToPort")
        for cidr in rule.get("IpRanges", []):
            if cidr.get("CidrIp") == "0.0.0.0/0":
                result.append({
                    "cidr": "0.0.0.0/0", "protocol": protocol,
                    "from_port": from_port, "to_port": to_port,
                })
        for cidr in rule.get("Ipv6Ranges", []):
            if cidr.get("CidrIpv6") == "::/0":
                result.append({
                    "cidr": "::/0", "protocol": protocol,
                    "from_port": from_port, "to_port": to_port,
                })
    return result


# Public IPv4 ingress with a prefix this wide (or wider) is "overly permissive"
# even when it isn't the catch-all 0.0.0.0/0 — a /8 exposes ~16M addresses.
_WIDE_CIDR_MAX_PREFIX = 16


def _sg_wide_open_cidrs(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Public IPv4 ingress CIDRs broader than /16 but not 0.0.0.0/0 (that's the
    world-open case). RFC1918/loopback/link-local ranges are internal, not
    internet exposure, so they're excluded. Each: {cidr, prefix, port}."""
    out: list[dict[str, Any]] = []
    for rule in raw.get("IpPermissions", []):
        frm, to = rule.get("FromPort"), rule.get("ToPort")
        port = 0 if (frm is None and to is None) else int(frm)
        for r in rule.get("IpRanges", []):
            cidr = r.get("CidrIp")
            if not cidr or cidr == "0.0.0.0/0":
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if net.version != 4 or net.is_private or net.is_loopback or net.is_link_local:
                continue
            if net.prefixlen <= _WIDE_CIDR_MAX_PREFIX:
                out.append({"cidr": cidr, "prefix": net.prefixlen, "port": port})
    return out


def normalize_security_group(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    group_id = raw.get("GroupId") or raw.get("sg_id")
    if not group_id:
        raise ValueError("Security group raw record missing GroupId")

    region = raw.get("Region") or "global"
    open_ports = _sg_world_open_ports(raw)
    wide_cidrs = _sg_wide_open_cidrs(raw)
    is_exposed = bool(open_ports)

    # Filter out noise: AWS creates an empty "default" security group in every VPC.
    # Unless it has been explicitly modified to have open ports, it provides zero value
    # to the CSPM inventory and just clutters the UI.
    if raw.get("GroupName") == "default" and not is_exposed:
        return None

    properties = {
        "vpc_id": raw.get("VpcId"),
        "description": raw.get("Description"),
        "open_ports": open_ports,
        "open_port_labels": [_PORT_LABELS.get(p, str(p)) for p in open_ports],
        "world_open_ingress": _sg_world_open_ingress(raw),
        "wide_open_cidrs": wide_cidrs,
        "ingress_rule_count": len(raw.get("IpPermissions", [])),
        "world_open": is_exposed,
    }

    return NormalizedAsset(
        resource_id=f"arn:aws:ec2:{region}:{account_identifier}:security-group/{group_id}",
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.ec2.security_group",
        name=raw.get("GroupName") or group_id,
        region=region,
        tags=_tags_to_dict(raw.get("Tags")),
        # A security group is a rule set, not a network location. It has no
        # address and nothing routes to it, so it is never itself "public" —
        # what is exposed is whatever the group is attached to. Marking the
        # group public also double-counted in risk scoring: the rule severity
        # already encodes "open to the world", and the exposure multiplier then
        # multiplied the same fact again. The world_open property carries the
        # configuration; rules resolve the real exposure through attachments.
        is_public=False,
        encryption_enabled=None,
        network_exposure="vpc",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def _trust_allows_wildcard(trust: Any) -> bool:
    """True if any Allow statement trusts a `*` AWS principal (publicly assumable)."""
    for st in _statements(trust):
        if st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal") or {}
        if principal == "*":
            return True
        if not isinstance(principal, dict):
            continue
        aws_p = principal.get("AWS", [])
        aws_p = [aws_p] if isinstance(aws_p, str) else aws_p
        if "*" in aws_p:
            return True
    return False


def _federated_principals(trust: Any) -> list[str]:
    """Federated (OIDC/SAML) principals trusted by Allow statements — e.g. a
    GitHub Actions or GitLab OIDC provider that lets an external CI pipeline
    assume the role. Principal.Federated may be a string or a list."""
    out: list[str] = []
    for st in _statements(trust):
        if st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal") or {}
        if not isinstance(principal, dict):
            continue
        fed = principal.get("Federated", [])
        fed = [fed] if isinstance(fed, str) else fed
        out.extend(str(f) for f in fed)
    return out


def _service_principals(trust: Any) -> list[str]:
    """AWS services accepted by Allow statements in a role trust policy."""
    out: list[str] = []
    for statement in _statements(trust):
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal") or {}
        if not isinstance(principal, dict):
            continue
        services = principal.get("Service", [])
        services = [services] if isinstance(services, str) else services
        if isinstance(services, list):
            out.extend(str(service).lower() for service in services if service)
    return sorted(set(out))


def _identity_entitlement_properties(raw: dict[str, Any]) -> dict[str, Any]:
    """Shared CIEM evidence retained for roles and users."""
    return {
        "has_admin_grant": bool(
            raw.get("has_admin_grant")
            if "has_admin_grant" in raw
            else raw.get("has_admin")
        ),
        "effective_privesc_actions": (
            raw.get("effective_privesc_actions")
            if "effective_privesc_actions" in raw
            else raw.get("privesc_actions")
        ) or [],
        "policy_sources": raw.get("policy_sources") or [],
        "policy_grants": raw.get("policy_grants") or [],
        "grant_evidence_truncated": bool(raw.get("grant_evidence_truncated")),
        "policy_source_count": int(raw.get("policy_source_count") or 0),
        "direct_policy_count": int(raw.get("direct_policy_count") or 0),
        "inherited_policy_count": int(raw.get("inherited_policy_count") or 0),
        "allow_statement_count": int(raw.get("allow_statement_count") or 0),
        "explicit_deny_count": int(raw.get("explicit_deny_count") or 0),
        "conditional_statement_count": int(raw.get("conditional_statement_count") or 0),
        "wildcard_action_statement_count": int(
            raw.get("wildcard_action_statement_count") or 0
        ),
        "wildcard_resource_statement_count": int(
            raw.get("wildcard_resource_statement_count") or 0
        ),
        "permissions_boundary_arn": raw.get("permissions_boundary_arn") or "",
        "permissions_boundary_state": (
            raw.get("permissions_boundary_state") or "not_configured"
        ),
        "permissions_boundary_grants": raw.get("permissions_boundary_grants") or [],
        "boundary_restricts_admin": bool(raw.get("boundary_restricts_admin")),
        "authorization_scope": raw.get("authorization_scope") or "identity_policies",
        "effective_access_complete": bool(raw.get("effective_access_complete")),
        "unevaluated_policy_layers": raw.get("unevaluated_policy_layers") or [],
    }


def normalize_iam_role(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    name = raw.get("RoleName") or raw.get("role_name")
    if not name:
        raise ValueError("IAM role raw record missing RoleName")

    arn = raw.get("Arn") or f"arn:aws:iam::{account_identifier}:role/{name}"
    trust = raw.get("AssumeRolePolicyDocument") or {}
    publicly_assumable = _trust_allows_wildcard(trust)

    properties = {
        "path": raw.get("Path"),
        "has_admin": bool(raw.get("has_admin")),
        "admin_reason": raw.get("admin_reason"),
        "privesc_actions": raw.get("privesc_actions") or [],
        "assume_role_resources": raw.get("assume_role_resources") or [],
        "s3_read_resources": raw.get("s3_read_resources") or [],
        "policy_analysis_complete": bool(raw.get("policy_analysis_complete")),
        "assumable_by_ec2": bool(raw.get("assumable_by_ec2")),
        "trust_external": bool(raw.get("trust_external")) or publicly_assumable,
        "trust_principals": raw.get("trust_principals") or [],
        # Keep principal-to-ExternalId binding for the attack-path engine. This
        # lets it recognize a verified scanner onboarding connection rather
        # than turning it into a lateral-movement alert.
        "trust_statements": extract_trust_statement_evidence(trust),
        "trust_federated": _federated_principals(trust),
        "trust_services": _service_principals(trust),
        "publicly_assumable": publicly_assumable,
        "last_used_days": raw.get("last_used_days"),
        "age_days": raw.get("age_days"),
        **_identity_entitlement_properties(raw),
    }
    relationships = [{"type": "BELONGS_TO", "target_id": account_identifier}]
    boundary_arn = str(properties.get("permissions_boundary_arn") or "")
    if boundary_arn:
        relationships.append({"type": "BOUNDED_BY", "target_id": boundary_arn})

    return NormalizedAsset(
        resource_id=arn,
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.iam.role",
        name=name,
        region="global",  # IAM is a global service
        tags=_tags_to_dict(raw.get("Tags")),
        is_public=publicly_assumable,
        encryption_enabled=None,
        network_exposure="public" if publicly_assumable else "private",
        properties=properties,
        relationships=relationships,
        raw=raw,
        resource_created_at=raw.get("CreateDate"),
    )


def normalize_iam_user(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    name = raw.get("UserName") or raw.get("user_name")
    if not name:
        raise ValueError("IAM user raw record missing UserName")

    arn = raw.get("Arn") or f"arn:aws:iam::{account_identifier}:user/{name}"
    properties = {
        "path": raw.get("Path"),
        "has_admin": bool(raw.get("has_admin")),
        "admin_reason": raw.get("admin_reason"),
        "privesc_actions": raw.get("privesc_actions") or [],
        "assume_role_resources": raw.get("assume_role_resources") or [],
        "s3_read_resources": raw.get("s3_read_resources") or [],
        "policy_analysis_complete": bool(raw.get("policy_analysis_complete")),
        "access_key_active": bool(raw.get("access_key_active")),
        "access_key_max_age_days": int(raw.get("access_key_max_age_days") or 0),
        "access_key_last_used_days": raw.get("access_key_last_used_days"),
        "console_enabled": bool(raw.get("console_enabled")),
        "mfa_enabled": bool(raw.get("mfa_enabled")),
        "last_used_days": raw.get("last_used_days"),
        "age_days": raw.get("age_days"),
        "group_names": raw.get("group_names") or [],
        "group_arns": raw.get("group_arns") or [],
        **_identity_entitlement_properties(raw),
    }
    relationships = [{"type": "BELONGS_TO", "target_id": account_identifier}]
    relationships.extend(
        {"type": "MEMBER_OF", "target_id": str(group_arn)}
        for group_arn in properties["group_arns"]
    )
    boundary_arn = str(properties.get("permissions_boundary_arn") or "")
    if boundary_arn:
        relationships.append({"type": "BOUNDED_BY", "target_id": boundary_arn})

    return NormalizedAsset(
        resource_id=arn,
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.iam.user",
        name=name,
        region="global",  # IAM is a global service
        tags=_tags_to_dict(raw.get("Tags")),
        is_public=False,  # users aren't "public"; risk is key exposure, not reachability
        encryption_enabled=None,
        network_exposure="private",
        properties=properties,
        relationships=relationships,
        raw=raw,
        resource_created_at=raw.get("CreateDate"),
    )


def normalize_rds_instance(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    db_id = raw.get("DBInstanceIdentifier") or raw.get("db_id")
    if not db_id:
        raise ValueError("RDS raw record missing DBInstanceIdentifier")

    region = raw.get("Region") or "global"
    public_endpoint = bool(raw.get("PubliclyAccessible"))
    encrypted = bool(raw.get("StorageEncrypted"))
    endpoint = raw.get("Endpoint") or {}
    # Carry the attached SGs so the attack-path engine can prove real internet
    # reachability (SG open to 0.0.0.0/0 on the DB port), not just the public flag.
    sg_ids = [g.get("VpcSecurityGroupId") for g in raw.get("VpcSecurityGroups", [])
              if g.get("VpcSecurityGroupId")]

    properties = {
        "engine": raw.get("Engine"),
        "engine_version": raw.get("EngineVersion"),
        "endpoint": endpoint.get("Address"),
        "port": endpoint.get("Port"),
        "vpc_id": (raw.get("DBSubnetGroup") or {}).get("VpcId"),
        "multi_az": bool(raw.get("MultiAZ")),
        "publicly_accessible": public_endpoint,
        "backup_retention_days": raw.get("BackupRetentionPeriod"),
        "deletion_protection": bool(raw.get("DeletionProtection")),
        "auto_minor_version_upgrade": raw.get("AutoMinorVersionUpgrade"),
        "subnet_ids": [
            subnet.get("SubnetIdentifier")
            for subnet in (raw.get("DBSubnetGroup") or {}).get("Subnets", [])
            if subnet.get("SubnetIdentifier")
        ],
        "iam_auth_enabled": bool(raw.get("IAMDatabaseAuthenticationEnabled")),
        "security_group_ids": sg_ids,
    }

    relationships: list[dict[str, Any]] = [{"type": "BELONGS_TO", "target_id": account_identifier}]
    relationships += [{"type": "USES_SECURITY_GROUP", "target_id": s} for s in sg_ids]

    return NormalizedAsset(
        resource_id=raw.get("DBInstanceArn") or f"arn:aws:rds:{region}:{account_identifier}:db:{db_id}",
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.rds.db_instance",
        name=db_id,
        region=region,
        tags=_tags_to_dict(raw.get("TagList") or raw.get("Tags")),
        # A public endpoint configuration is not a proven public network path.
        # The graph promotes this only after SG + route + IGW + NACL evidence.
        is_public=False,
        encryption_enabled=encrypted,
        network_exposure="vpc",
        properties=properties,
        relationships=relationships,
        raw=raw,
        resource_created_at=raw.get("InstanceCreateTime"),
    )


def normalize_ec2_subnet(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    subnet_id = raw.get("SubnetId")
    if not subnet_id:
        raise ValueError("EC2 subnet raw record missing SubnetId")
    region = raw.get("Region") or "global"
    return NormalizedAsset(
        resource_id=f"arn:aws:ec2:{region}:{account_identifier}:subnet/{subnet_id}",
        cloud_provider="aws", account_identifier=account_identifier,
        asset_type="aws.ec2.subnet", name=subnet_id, region=region,
        tags=_tags_to_dict(raw.get("Tags")), is_public=False, network_exposure="vpc",
        properties={
            "vpc_id": raw.get("VpcId"),
            "availability_zone": raw.get("AvailabilityZone"),
            "map_public_ip_on_launch": bool(raw.get("MapPublicIpOnLaunch")),
            # AWS creates a default VPC in every region with MapPublicIpOnLaunch
            # already on, so this flag is what separates "someone did this" from
            # "this is how the account arrived".
            "default_for_az": bool(raw.get("DefaultForAz")),
            "available_ip_address_count": raw.get("AvailableIpAddressCount"),
        },
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}], raw=raw,
    )


def normalize_ec2_network_interface(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    interface_id = raw.get("NetworkInterfaceId")
    if not interface_id:
        raise ValueError("EC2 network interface raw record missing NetworkInterfaceId")
    region = raw.get("Region") or "global"
    attachment = raw.get("Attachment") or {}
    association = raw.get("Association") or {}
    security_group_ids = [
        str(group.get("GroupId")) for group in raw.get("Groups") or []
        if group.get("GroupId")
    ]
    private_addresses = [
        str(address.get("PrivateIpAddress")) for address in raw.get("PrivateIpAddresses") or []
        if address.get("PrivateIpAddress")
    ]
    relationships: list[dict[str, Any]] = [
        {"type": "BELONGS_TO", "target_id": account_identifier},
    ]
    if attachment.get("InstanceId"):
        relationships.append({"type": "ATTACHED_TO", "target_id": attachment["InstanceId"]})
    relationships.extend(
        {"type": "USES_SECURITY_GROUP", "target_id": group_id}
        for group_id in security_group_ids
    )
    public_ip = association.get("PublicIp")
    return NormalizedAsset(
        resource_id=f"arn:aws:ec2:{region}:{account_identifier}:network-interface/{interface_id}",
        cloud_provider="aws", account_identifier=account_identifier,
        asset_type="aws.ec2.network_interface", name=interface_id, region=region,
        tags=_tags_to_dict(raw.get("TagSet") or raw.get("Tags")),
        is_public=bool(public_ip), network_exposure="public" if public_ip else "vpc",
        properties={
            "vpc_id": raw.get("VpcId"),
            "subnet_id": raw.get("SubnetId"),
            "status": raw.get("Status"),
            "interface_type": raw.get("InterfaceType"),
            "requester_managed": bool(raw.get("RequesterManaged")),
            "description": raw.get("Description"),
            "private_ip_addresses": private_addresses,
            "public_ip": public_ip,
            "attachment_instance_id": attachment.get("InstanceId"),
            "attachment_status": attachment.get("Status"),
            "attachment_device_index": attachment.get("DeviceIndex"),
            "security_group_ids": security_group_ids,
        },
        relationships=relationships,
        raw=raw,
    )


def normalize_ec2_route_table(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    route_table_id = raw.get("RouteTableId")
    if not route_table_id:
        raise ValueError("EC2 route table raw record missing RouteTableId")
    region = raw.get("Region") or "global"
    routes = [{
        "destination_cidr_block": route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock"),
        "gateway_id": route.get("GatewayId"),
        "state": route.get("State"),
    } for route in raw.get("Routes", [])]
    associations = [{
        "subnet_id": association.get("SubnetId"),
        "main": bool(association.get("Main")),
    } for association in raw.get("Associations", [])]
    return NormalizedAsset(
        resource_id=f"arn:aws:ec2:{region}:{account_identifier}:route-table/{route_table_id}",
        cloud_provider="aws", account_identifier=account_identifier,
        asset_type="aws.ec2.route_table", name=route_table_id, region=region,
        tags=_tags_to_dict(raw.get("Tags")), is_public=False, network_exposure="vpc",
        properties={"vpc_id": raw.get("VpcId"), "routes": routes, "associations": associations},
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}], raw=raw,
    )


def normalize_ec2_network_acl(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    acl_id = raw.get("NetworkAclId")
    if not acl_id:
        raise ValueError("EC2 network ACL raw record missing NetworkAclId")
    region = raw.get("Region") or "global"
    entries = [{
        "rule_number": entry.get("RuleNumber"),
        "protocol": entry.get("Protocol"),
        "rule_action": entry.get("RuleAction"),
        "egress": bool(entry.get("Egress")),
        "cidr_block": entry.get("CidrBlock") or entry.get("Ipv6CidrBlock"),
        "from_port": (entry.get("PortRange") or {}).get("From"),
        "to_port": (entry.get("PortRange") or {}).get("To"),
    } for entry in raw.get("Entries", [])]
    return NormalizedAsset(
        resource_id=f"arn:aws:ec2:{region}:{account_identifier}:network-acl/{acl_id}",
        cloud_provider="aws", account_identifier=account_identifier,
        asset_type="aws.ec2.network_acl", name=acl_id, region=region,
        tags=_tags_to_dict(raw.get("Tags")), is_public=False, network_exposure="vpc",
        properties={
            "vpc_id": raw.get("VpcId"),
            "is_default": bool(raw.get("IsDefault")),
            "subnet_ids": [
                association.get("SubnetId") for association in raw.get("Associations", [])
                if association.get("SubnetId")
            ],
            "entries": entries,
        },
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}], raw=raw,
    )


def normalize_ec2_internet_gateway(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    gateway_id = raw.get("InternetGatewayId")
    if not gateway_id:
        raise ValueError("EC2 internet gateway raw record missing InternetGatewayId")
    region = raw.get("Region") or "global"
    return NormalizedAsset(
        resource_id=f"arn:aws:ec2:{region}:{account_identifier}:internet-gateway/{gateway_id}",
        cloud_provider="aws", account_identifier=account_identifier,
        asset_type="aws.ec2.internet_gateway", name=gateway_id, region=region,
        tags=_tags_to_dict(raw.get("Tags")), is_public=False, network_exposure="vpc",
        properties={
            "attached_vpc_ids": [
                attachment.get("VpcId") for attachment in raw.get("Attachments", [])
                if attachment.get("State") == "available" and attachment.get("VpcId")
            ],
        },
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}], raw=raw,
    )


def _region_from_arn(arn: Optional[str]) -> Optional[str]:
    """arn:aws:lambda:us-east-1:123:function:f -> us-east-1 ('' for global services)."""
    if not arn:
        return None
    parts = str(arn).split(":")
    return parts[3] or None if len(parts) > 3 else None


def normalize_lambda_function(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    name = raw.get("FunctionName") or raw.get("function_name")
    if not name:
        raise ValueError("Lambda raw record missing FunctionName")

    region = raw.get("Region") or _region_from_arn(raw.get("FunctionArn")) or "global"
    arn = raw.get("FunctionArn") or f"arn:aws:lambda:{region}:{account_identifier}:function:{name}"
    # Public = unauthenticated function URL, or a resource policy trusting `*`
    # (both gathered by the collector; absent keys read as not-public).
    url_auth = raw.get("FunctionUrlAuthType")
    public_policy = bool(raw.get("PublicPolicy"))
    is_public = url_auth == "NONE" or public_policy
    vpc_config = raw.get("VpcConfig") or {}
    vpc_id = vpc_config.get("VpcId")
    role_arn = raw.get("Role")

    properties = {
        "runtime": raw.get("Runtime"),
        "handler": raw.get("Handler"),
        "memory_size": raw.get("MemorySize"),
        "timeout": raw.get("Timeout"),
        "execution_role": role_arn,
        "vpc_id": vpc_id,
        # A VPC-attached function occupies an ENI in each of these subnets, which
        # is what stops them being read as empty.
        "subnet_ids": [str(s) for s in vpc_config.get("SubnetIds") or [] if s],
        "security_group_ids": [str(s) for s in vpc_config.get("SecurityGroupIds") or [] if s],
        "function_url_auth": url_auth,
        "public_policy": public_policy,
        # ARNs of the services permitted to invoke this function — the pointer
        # from a Lambda back to the API Gateway or event source in front of it.
        "trigger_source_arns": [str(a) for a in raw.get("TriggerSourceArns") or [] if a],
        "collection_evidence": raw.get("_Evidence") or {},
    }
    relationships: list[dict[str, Any]] = [{"type": "BELONGS_TO", "target_id": account_identifier}]
    if role_arn:
        relationships.append({"type": "EXECUTES_AS", "target_id": role_arn})

    return NormalizedAsset(
        resource_id=arn,
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.lambda.function",
        name=name,
        region=region,
        tags=_tags_to_dict(raw.get("Tags")),
        is_public=is_public,
        encryption_enabled=None,
        network_exposure="public" if is_public else ("vpc" if vpc_id else "private"),
        properties=properties,
        relationships=relationships,
        raw=raw,
    )


def normalize_ecs_cluster(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    name = raw.get("clusterName") or raw.get("ClusterName")
    if not name:
        raise ValueError("ECS raw record missing clusterName")

    arn = raw.get("clusterArn") or f"arn:aws:ecs:global:{account_identifier}:cluster/{name}"
    region = raw.get("Region") or _region_from_arn(arn) or "global"
    insights = next(
        (s.get("value") for s in raw.get("settings", []) if s.get("name") == "containerInsights"),
        None,
    )

    properties = {
        "status": raw.get("status"),
        "running_tasks": raw.get("runningTasksCount"),
        "active_services": raw.get("activeServicesCount"),
        "registered_instances": raw.get("registeredContainerInstancesCount"),
        "container_insights": insights,
    }

    return NormalizedAsset(
        resource_id=arn,
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.ecs.cluster",
        name=name,
        region=region,
        tags=_tags_to_dict(raw.get("tags") or raw.get("Tags")),
        is_public=False,
        encryption_enabled=None,
        network_exposure="vpc",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_ecs_task_definition(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    """Normalize one active ECS task-definition revision without exposing values.

    A task definition is the useful unit for container posture: it binds
    containers to a workload role and declares privileged or host-networked
    execution. Environment variable and secret *values* are intentionally not
    copied into normalized properties.
    """
    arn = raw.get("taskDefinitionArn") or raw.get("TaskDefinitionArn")
    family = raw.get("family") or raw.get("Family")
    revision = raw.get("revision") or raw.get("Revision")
    if not arn and not family:
        raise ValueError("ECS raw record missing taskDefinitionArn or family")
    name = f"{family}:{revision}" if family and revision is not None else str(family or arn)
    arn = arn or f"arn:aws:ecs:global:{account_identifier}:task-definition/{name}"
    region = raw.get("Region") or _region_from_arn(arn) or "global"
    containers = raw.get("containerDefinitions") or raw.get("ContainerDefinitions") or []
    containers = [container for container in containers if isinstance(container, dict)]
    privileged = sorted(
        str(container.get("name") or container.get("Name") or "unnamed")
        for container in containers
        if bool((container.get("linuxParameters") or {}).get("privileged"))
    )
    readonly_disabled = sorted(
        str(container.get("name") or container.get("Name") or "unnamed")
        for container in containers
        if container.get("readonlyRootFilesystem") is not True
    )
    task_role = raw.get("taskRoleArn") or raw.get("TaskRoleArn")
    execution_role = raw.get("executionRoleArn") or raw.get("ExecutionRoleArn")
    relationships = [{"type": "BELONGS_TO", "target_id": account_identifier}]
    for role_arn in (task_role, execution_role):
        if role_arn:
            relationships.append({"type": "EXECUTES_AS", "target_id": str(role_arn)})

    return NormalizedAsset(
        resource_id=str(arn),
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.ecs.task_definition",
        name=name,
        region=region,
        tags=_tags_to_dict(raw.get("tags") or raw.get("Tags")),
        is_public=False,
        encryption_enabled=None,
        network_exposure="vpc",
        properties={
            "family": family,
            "revision": revision,
            "network_mode": raw.get("networkMode") or raw.get("NetworkMode"),
            "host_network": (raw.get("networkMode") or raw.get("NetworkMode")) == "host",
            "requires_compatibilities": raw.get("requiresCompatibilities") or raw.get("RequiresCompatibilities") or [],
            "task_role_arn": task_role,
            "execution_role_arn": execution_role,
            "container_count": len(containers),
            "privileged_containers": privileged,
            "readonly_root_filesystem_disabled_containers": readonly_disabled,
            "secret_reference_count": sum(len(container.get("secrets") or []) for container in containers),
        },
        relationships=relationships,
        raw=raw,
    )


def normalize_eks_cluster(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    """Normalize EKS API endpoint and control-plane security posture."""
    name = raw.get("name") or raw.get("Name")
    if not name:
        raise ValueError("EKS raw record missing name")
    arn = raw.get("arn") or raw.get("Arn") or f"arn:aws:eks:global:{account_identifier}:cluster/{name}"
    region = raw.get("Region") or _region_from_arn(arn) or "global"
    vpc = raw.get("resourcesVpcConfig") or raw.get("ResourcesVpcConfig") or {}
    access = raw.get("accessConfig") or raw.get("AccessConfig") or {}
    logging = raw.get("logging") or raw.get("Logging") or {}
    cluster_logging = logging.get("clusterLogging") or []
    enabled_log_types = sorted({
        str(log_type)
        for config in cluster_logging if isinstance(config, dict) and config.get("enabled")
        for log_type in (config.get("types") or [])
    })
    encryption = raw.get("encryptionConfig") or raw.get("EncryptionConfig") or []
    public_cidrs = list(vpc.get("publicAccessCidrs") or [])
    public_endpoint = bool(vpc.get("endpointPublicAccess"))
    relationships = [{"type": "BELONGS_TO", "target_id": account_identifier}]
    for security_group in vpc.get("securityGroupIds") or []:
        relationships.append({"type": "USES_SECURITY_GROUP", "target_id": str(security_group)})
    role = raw.get("roleArn") or raw.get("RoleArn")
    if role:
        relationships.append({"type": "EXECUTES_AS", "target_id": str(role)})

    return NormalizedAsset(
        resource_id=str(arn),
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.eks.cluster",
        name=str(name),
        region=region,
        tags=_tags_to_dict(raw.get("tags") or raw.get("Tags")),
        is_public=public_endpoint,
        encryption_enabled=bool(encryption),
        network_exposure="public" if public_endpoint else "vpc",
        properties={
            "status": raw.get("status") or raw.get("Status"),
            "version": raw.get("version") or raw.get("Version"),
            "endpoint_public_access": public_endpoint,
            "endpoint_private_access": bool(vpc.get("endpointPrivateAccess")),
            "public_access_cidrs": public_cidrs,
            "secrets_encryption_enabled": bool(encryption),
            "enabled_control_plane_logs": enabled_log_types,
            "vpc_id": vpc.get("vpcId"),
            "subnet_ids": vpc.get("subnetIds") or [],
            "security_group_ids": vpc.get("securityGroupIds") or [],
            "service_role_arn": role,
            "authentication_mode": access.get("authenticationMode"),
        },
        relationships=relationships,
        raw=raw,
    )


def normalize_ecr_repository(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    """Normalize ECR repository configuration and policy evidence."""
    name = raw.get("repositoryName") or raw.get("RepositoryName")
    if not name:
        raise ValueError("ECR raw record missing repositoryName")
    arn = raw.get("repositoryArn") or raw.get("RepositoryArn") or f"arn:aws:ecr:global:{account_identifier}:repository/{name}"
    region = raw.get("Region") or _region_from_arn(arn) or "global"
    scanning = raw.get("imageScanningConfiguration") or raw.get("ImageScanningConfiguration") or {}
    encryption = raw.get("encryptionConfiguration") or raw.get("EncryptionConfiguration") or {}
    evidence = raw.get("_Evidence") or {}

    return NormalizedAsset(
        resource_id=str(arn),
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.ecr.repository",
        name=str(name),
        region=region,
        tags=_tags_to_dict(raw.get("tags") or raw.get("Tags")),
        # Private ECR pulls require an IAM-authorized authorization token even
        # when a repository policy names ``Principal: *``. Treat that as broad
        # cross-account trust, not unauthenticated internet exposure.
        is_public=False,
        # ECR encrypts repositories at rest by design. This field tells the UI
        # that encryption exists; ``encryption_type`` preserves AES256 vs KMS.
        encryption_enabled=True,
        network_exposure="private",
        properties={
            "repository_uri": raw.get("repositoryUri") or raw.get("RepositoryUri"),
            "image_scan_on_push": bool(scanning.get("scanOnPush")),
            "tag_mutability": raw.get("imageTagMutability") or raw.get("ImageTagMutability"),
            "encryption_type": encryption.get("encryptionType"),
            "kms_key": encryption.get("kmsKey"),
            "unrestricted_repository_policy": bool(raw.get("UnrestrictedRepositoryPolicy")),
            "lifecycle_policy_present": bool(raw.get("LifecyclePolicyPresent")),
            "collection_evidence": evidence,
        },
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_secret(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    name = raw.get("Name") or raw.get("name")
    if not name:
        raise ValueError("Secrets Manager raw record missing Name")

    arn = raw.get("ARN") or f"arn:aws:secretsmanager:global:{account_identifier}:secret:{name}"
    region = raw.get("Region") or _region_from_arn(arn) or "global"
    public_policy = bool(raw.get("PublicPolicy"))  # resource policy trusting `*`

    properties = {
        "kms_key_id": raw.get("KmsKeyId"),  # None = aws/secretsmanager default key
        "rotation_enabled": bool(raw.get("RotationEnabled")),
        "last_rotated_date": raw.get("LastRotatedDate"),
        "last_accessed_date": raw.get("LastAccessedDate"),
        "public_policy": public_policy,
        "collection_evidence": raw.get("_Evidence") or {},
    }

    return NormalizedAsset(
        resource_id=arn,
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.secretsmanager.secret",
        name=name,
        region=region,
        tags=_tags_to_dict(raw.get("Tags")),
        is_public=public_policy,
        encryption_enabled=True,  # Secrets Manager always encrypts at rest
        network_exposure="public" if public_policy else "private",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
        resource_created_at=raw.get("CreatedDate"),
    )


def _db_cluster_asset(raw: dict[str, Any], account_identifier: str, asset_type: str) -> NormalizedAsset:
    """Shared shape for RDS/Aurora, Neptune, and DocumentDB clusters — all three
    surface through the same describe_db_clusters API family."""
    cluster_id = raw.get("DBClusterIdentifier") or raw.get("cluster_id")
    if not cluster_id:
        raise ValueError("DB cluster raw record missing DBClusterIdentifier")

    arn = raw.get("DBClusterArn") or f"arn:aws:rds:global:{account_identifier}:cluster:{cluster_id}"
    region = raw.get("Region") or _region_from_arn(arn) or "global"
    is_public = bool(raw.get("PubliclyAccessible"))  # cluster-level: rare, member instances carry their own
    encrypted = bool(raw.get("StorageEncrypted"))

    properties = {
        "engine": raw.get("Engine"),
        "engine_version": raw.get("EngineVersion"),
        "endpoint": raw.get("Endpoint"),
        "reader_endpoint": raw.get("ReaderEndpoint"),
        "port": raw.get("Port"),
        "multi_az": bool(raw.get("MultiAZ")),
        "member_count": len(raw.get("DBClusterMembers", [])),
        "deletion_protection": bool(raw.get("DeletionProtection")),
    }

    return NormalizedAsset(
        resource_id=arn,
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type=asset_type,
        name=cluster_id,
        region=region,
        tags=_tags_to_dict(raw.get("TagList") or raw.get("Tags")),
        is_public=is_public,
        encryption_enabled=encrypted,
        network_exposure="public" if is_public else "vpc",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
        resource_created_at=raw.get("ClusterCreateTime"),
    )


def normalize_rds_cluster(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    return _db_cluster_asset(raw, account_identifier, "aws.rds.db_cluster")


def normalize_neptune_cluster(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    return _db_cluster_asset(raw, account_identifier, "aws.neptune.cluster")


def normalize_docdb_cluster(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    return _db_cluster_asset(raw, account_identifier, "aws.docdb.cluster")


def normalize_rds_proxy(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    name = raw.get("DBProxyName") or raw.get("proxy_name")
    if not name:
        raise ValueError("RDS proxy raw record missing DBProxyName")

    arn = raw.get("DBProxyArn") or f"arn:aws:rds:global:{account_identifier}:db-proxy:{name}"
    region = raw.get("Region") or _region_from_arn(arn) or "global"

    properties = {
        "engine_family": raw.get("EngineFamily"),
        "require_tls": bool(raw.get("RequireTLS")),
        "vpc_id": raw.get("VpcId"),
        "status": raw.get("Status"),
        "auth_count": len(raw.get("Auth", [])),
        "idle_client_timeout": raw.get("IdleClientTimeout"),
    }

    return NormalizedAsset(
        resource_id=arn,
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.rds.db_proxy",
        name=name,
        region=region,
        tags=_tags_to_dict(raw.get("Tags")),
        is_public=False,  # proxies are VPC-only endpoints by design
        encryption_enabled=None,
        network_exposure="vpc",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
        resource_created_at=raw.get("CreatedDate"),
    )


def normalize_redshift_cluster(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    cluster_id = raw.get("ClusterIdentifier") or raw.get("cluster_id")
    if not cluster_id:
        raise ValueError("Redshift raw record missing ClusterIdentifier")

    region = raw.get("Region") or "global"
    is_public = bool(raw.get("PubliclyAccessible"))
    encrypted = bool(raw.get("Encrypted"))
    endpoint = raw.get("Endpoint") or {}

    properties = {
        "node_type": raw.get("NodeType"),
        "node_count": raw.get("NumberOfNodes"),
        "endpoint": endpoint.get("Address"),
        "port": endpoint.get("Port"),
        "vpc_id": raw.get("VpcId"),
        "db_name": raw.get("DBName"),
        "publicly_accessible": is_public,
    }

    return NormalizedAsset(
        resource_id=f"arn:aws:redshift:{region}:{account_identifier}:cluster:{cluster_id}",
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.redshift.cluster",
        name=cluster_id,
        region=region,
        tags=_tags_to_dict(raw.get("Tags")),
        is_public=is_public,
        encryption_enabled=encrypted,
        network_exposure="public" if is_public else "vpc",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
        resource_created_at=raw.get("ClusterCreateTime"),
    )


def normalize_load_balancer(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    name = raw.get("LoadBalancerName") or raw.get("lb_name")
    if not name:
        raise ValueError("ELBv2 raw record missing LoadBalancerName")

    arn = raw.get("LoadBalancerArn") or f"arn:aws:elasticloadbalancing:global:{account_identifier}:loadbalancer/{name}"
    region = raw.get("Region") or _region_from_arn(arn) or "global"
    is_public = raw.get("Scheme") == "internet-facing"
    sg_ids = raw.get("SecurityGroups") or []

    properties = {
        "scheme": raw.get("Scheme"),
        "lb_type": raw.get("Type"),
        "dns_name": raw.get("DNSName"),
        "vpc_id": raw.get("VpcId"),
        "state": (raw.get("State") or {}).get("Code"),
        "security_group_ids": sg_ids,
    }
    relationships: list[dict[str, Any]] = [{"type": "BELONGS_TO", "target_id": account_identifier}]
    for sg in sg_ids:
        relationships.append({"type": "USES_SECURITY_GROUP", "target_id": sg})

    return NormalizedAsset(
        resource_id=arn,
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.elbv2.load_balancer",
        name=name,
        region=region,
        tags=_tags_to_dict(raw.get("Tags")),
        is_public=is_public,
        encryption_enabled=None,
        network_exposure="public" if is_public else "vpc",
        properties=properties,
        relationships=relationships,
        raw=raw,
        resource_created_at=raw.get("CreatedTime"),
    )


def normalize_cloudtrail(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    name = raw.get("Name")
    if not name:
        raise ValueError("CloudTrail raw record missing Name")

    region = raw.get("HomeRegion") or raw.get("Region") or "global"
    arn = raw.get("TrailARN") or f"arn:aws:cloudtrail:{region}:{account_identifier}:trail/{name}"
    kms_key_id = raw.get("KmsKeyId")

    properties = {
        "is_multi_region": bool(raw.get("IsMultiRegionTrail")),
        "is_logging": bool(raw.get("IsLogging")),
        "log_file_validation": bool(raw.get("LogFileValidationEnabled")),
        "kms_encrypted": bool(kms_key_id),
        "kms_key_id": kms_key_id,
        "s3_bucket_name": raw.get("S3BucketName"),
        "cloudwatch_logs_arn": raw.get("CloudWatchLogsLogGroupArn"),
        "is_organization_trail": bool(raw.get("IsOrganizationTrail")),
        "collection_evidence": raw.get("_Evidence") or {},
    }

    return NormalizedAsset(
        resource_id=arn,
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.cloudtrail.trail",
        name=name,
        region=region,
        tags=_tags_to_dict(raw.get("Tags")),
        is_public=False,
        encryption_enabled=bool(kms_key_id),
        network_exposure="private",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_config_recorder(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    name = raw.get("name")
    if not name:
        raise ValueError("Config recorder raw record missing name")

    region = raw.get("Region") or "global"
    group = raw.get("recordingGroup") or {}

    properties = {
        "is_recording": bool(raw.get("_IsRecording")),
        "all_supported": bool(group.get("allSupported")),
        "include_global_resources": bool(group.get("includeGlobalResourceTypes")),
        "role_arn": raw.get("roleARN"),
        "collection_evidence": raw.get("_Evidence") or {},
    }

    return NormalizedAsset(
        resource_id=f"arn:aws:config:{region}:{account_identifier}:config-recorder/{name}",
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.config.recorder",
        name=name,
        region=region,
        tags={},
        is_public=False,
        encryption_enabled=None,
        network_exposure="private",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_kms_key(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    key_id = raw.get("KeyId")
    if not key_id:
        raise ValueError("KMS raw record missing KeyId")

    region = raw.get("Region") or "global"
    arn = raw.get("KeyArn") or f"arn:aws:kms:{region}:{account_identifier}:key/{key_id}"

    properties = {
        "key_state": raw.get("KeyState"),
        "key_manager": raw.get("KeyManager"),
        "key_spec": raw.get("KeySpec"),
        "rotation_enabled": bool(raw.get("RotationEnabled")),
        "rotation_checked": bool(raw.get("RotationChecked")),
    }

    return NormalizedAsset(
        resource_id=arn,
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.kms.key",
        name=key_id,
        region=region,
        tags={},
        is_public=False,
        encryption_enabled=None,
        network_exposure="private",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_cloudwatch_log_group(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    name = raw.get("logGroupName")
    if not name:
        raise ValueError("Log group raw record missing logGroupName")

    region = raw.get("Region") or "global"
    arn = raw.get("arn") or f"arn:aws:logs:{region}:{account_identifier}:log-group:{name}"
    kms_key_id = raw.get("kmsKeyId")

    properties = {
        "retention_days": raw.get("retentionInDays"),
        "kms_key_id": kms_key_id,
        "stored_bytes": raw.get("storedBytes"),
    }

    return NormalizedAsset(
        resource_id=arn,
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.cloudwatch.log_group",
        name=name,
        region=region,
        tags={},
        is_public=False,
        encryption_enabled=bool(kms_key_id),
        network_exposure="private",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_ebs_volume(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    volume_id = raw.get("VolumeId")
    if not volume_id:
        raise ValueError("EBS volume raw record missing VolumeId")

    region = raw.get("Region") or "global"
    attachments = [a for a in raw.get("Attachments") or [] if isinstance(a, dict)]
    attached_instances = [a["InstanceId"] for a in attachments if a.get("InstanceId")]

    properties = {
        "state": raw.get("State"),
        "size_gib": raw.get("Size"),
        "volume_type": raw.get("VolumeType"),
        "kms_key_id": raw.get("KmsKeyId"),
        "attached_instance_ids": attached_instances,
    }

    return NormalizedAsset(
        resource_id=f"arn:aws:ec2:{region}:{account_identifier}:volume/{volume_id}",
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.ec2.volume",
        name=volume_id,
        region=region,
        tags=_tags_to_dict(raw.get("Tags")),
        is_public=False,
        encryption_enabled=bool(raw.get("Encrypted")),
        network_exposure="private",
        properties=properties,
        relationships=[
            {"type": "ATTACHED_TO", "target_id": instance_id}
            for instance_id in attached_instances
        ] or [{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_ebs_snapshot(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    snapshot_id = raw.get("SnapshotId")
    if not snapshot_id:
        raise ValueError("EBS snapshot raw record missing SnapshotId")

    region = raw.get("Region") or "global"
    is_public = bool(raw.get("IsPublic"))
    shared = [str(a) for a in raw.get("SharedWithAccounts") or []]

    properties = {
        "state": raw.get("State"),
        "volume_id": raw.get("VolumeId"),
        "volume_size_gib": raw.get("VolumeSize"),
        "shared_with_accounts": shared,
        "collection_evidence": raw.get("_Evidence") or {},
    }

    return NormalizedAsset(
        resource_id=f"arn:aws:ec2:{region}::snapshot/{snapshot_id}",
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.ec2.snapshot",
        name=snapshot_id,
        region=region,
        tags=_tags_to_dict(raw.get("Tags")),
        is_public=is_public,
        encryption_enabled=bool(raw.get("Encrypted")),
        # A snapshot shared with "all" is copyable by any AWS account. That is
        # data exposure through the AWS control plane, not a network path, so it
        # is recorded as public without claiming an internet route.
        network_exposure="public" if is_public else "private",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_vpc(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    vpc_id = raw.get("VpcId")
    if not vpc_id:
        raise ValueError("VPC raw record missing VpcId")

    region = raw.get("Region") or "global"
    flow_logs = [fl for fl in raw.get("_FlowLogsActive") or [] if isinstance(fl, dict)]

    properties = {
        "cidr_block": raw.get("CidrBlock"),
        "state": raw.get("State"),
        "is_default": bool(raw.get("IsDefault")),
        "flow_logs_enabled": bool(flow_logs),
        "flow_log_ids": [fl.get("FlowLogId") for fl in flow_logs if fl.get("FlowLogId")],
        "collection_evidence": raw.get("_Evidence") or {},
    }

    return NormalizedAsset(
        resource_id=f"arn:aws:ec2:{region}:{account_identifier}:vpc/{vpc_id}",
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.ec2.vpc",
        name=_tags_to_dict(raw.get("Tags")).get("Name") or vpc_id,
        region=region,
        tags=_tags_to_dict(raw.get("Tags")),
        is_public=False,
        encryption_enabled=None,
        network_exposure="vpc",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_efs_file_system(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    file_system_id = raw.get("FileSystemId")
    if not file_system_id:
        raise ValueError("EFS raw record missing FileSystemId")

    region = raw.get("Region") or "global"
    arn = raw.get("FileSystemArn") or (
        f"arn:aws:elasticfilesystem:{region}:{account_identifier}:file-system/{file_system_id}"
    )
    is_public = bool(raw.get("PublicPolicy"))

    properties = {
        "life_cycle_state": raw.get("LifeCycleState"),
        "performance_mode": raw.get("PerformanceMode"),
        "kms_key_id": raw.get("KmsKeyId"),
        "public_policy": is_public,
        "collection_evidence": raw.get("_Evidence") or {},
    }

    return NormalizedAsset(
        resource_id=arn,
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.efs.file_system",
        name=raw.get("Name") or file_system_id,
        region=region,
        tags=_tags_to_dict(raw.get("Tags")),
        is_public=is_public,
        encryption_enabled=bool(raw.get("Encrypted")),
        network_exposure="public" if is_public else "vpc",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_sns_topic(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    arn = raw.get("TopicArn")
    if not arn:
        raise ValueError("SNS raw record missing TopicArn")

    attributes = raw.get("Attributes") or {}
    kms_key_id = raw.get("KmsMasterKeyId") or attributes.get("KmsMasterKeyId")
    is_public = bool(raw.get("PublicPolicy"))

    properties = {
        "kms_master_key_id": kms_key_id,
        "public_policy": is_public,
        "subscriptions_confirmed": attributes.get("SubscriptionsConfirmed"),
        "collection_evidence": raw.get("_Evidence") or {},
    }

    return NormalizedAsset(
        resource_id=arn,
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.sns.topic",
        name=arn.rsplit(":", 1)[-1],
        region=raw.get("Region") or "global",
        tags={},
        is_public=is_public,
        encryption_enabled=bool(kms_key_id),
        network_exposure="public" if is_public else "private",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_sqs_queue(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    arn = raw.get("QueueArn")
    url = raw.get("QueueUrl")
    if not arn and not url:
        raise ValueError("SQS raw record missing QueueArn and QueueUrl")

    attributes = raw.get("Attributes") or {}
    kms_key_id = raw.get("KmsMasterKeyId") or attributes.get("KmsMasterKeyId")
    # SQS-managed SSE encrypts with an AWS-owned key. It is real encryption at
    # rest, so it must not be reported as an unencrypted queue.
    sse_managed = bool(raw.get("SqsManagedSseEnabled"))
    is_public = bool(raw.get("PublicPolicy"))

    properties = {
        "queue_url": url,
        "kms_master_key_id": kms_key_id,
        "sqs_managed_sse_enabled": sse_managed,
        "public_policy": is_public,
        "collection_evidence": raw.get("_Evidence") or {},
    }

    return NormalizedAsset(
        resource_id=arn or str(url),
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.sqs.queue",
        name=(arn or str(url)).rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1],
        region=raw.get("Region") or "global",
        tags={},
        is_public=is_public,
        encryption_enabled=bool(kms_key_id) or sse_managed,
        network_exposure="public" if is_public else "private",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_dynamodb_table(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    table_name = raw.get("TableName")
    if not table_name:
        raise ValueError("DynamoDB raw record missing TableName")

    region = raw.get("Region") or "global"
    arn = raw.get("TableArn") or (
        f"arn:aws:dynamodb:{region}:{account_identifier}:table/{table_name}"
    )
    sse = raw.get("SSEDescription") or {}

    properties = {
        "table_status": raw.get("TableStatus"),
        # DynamoDB always encrypts at rest; SSEDescription appears only when a
        # KMS key (AWS-managed or customer-managed) replaces the owned key.
        "sse_type": sse.get("SSEType"),
        "kms_key_arn": sse.get("KMSMasterKeyArn"),
        "point_in_time_recovery_status": raw.get("_PitrStatus"),
        "deletion_protection_enabled": bool(raw.get("DeletionProtectionEnabled")),
        "item_count": raw.get("ItemCount"),
        "collection_evidence": raw.get("_Evidence") or {},
    }

    return NormalizedAsset(
        resource_id=arn,
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.dynamodb.table",
        name=table_name,
        region=region,
        tags={},
        is_public=False,
        encryption_enabled=True,
        network_exposure="private",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_apigateway_rest_api(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    api_id = raw.get("id")
    if not api_id:
        raise ValueError("API Gateway raw record missing id")

    region = raw.get("Region") or "global"
    endpoint_types = [
        str(t) for t in (raw.get("endpointConfiguration") or {}).get("types") or []
    ]
    # PRIVATE APIs are reachable only through an interface VPC endpoint. EDGE and
    # REGIONAL resolve on the public internet.
    internet_facing = bool(endpoint_types) and "PRIVATE" not in endpoint_types

    stages = [s for s in raw.get("_Stages") or [] if isinstance(s, dict)]
    properties = {
        "endpoint_types": endpoint_types,
        "api_key_source": raw.get("apiKeySource"),
        "stages": [
            {
                "name": stage.get("stageName"),
                "access_logging_enabled": bool(
                    (stage.get("accessLogSettings") or {}).get("destinationArn")
                ),
                "cache_enabled": bool(stage.get("cacheClusterEnabled")),
                "cache_data_encrypted": bool(
                    (stage.get("methodSettings") or {}).get("*/*", {}).get("cacheDataEncrypted")
                ),
                "web_acl_arn": stage.get("webAclArn"),
                "xray_tracing_enabled": bool(stage.get("tracingEnabled")),
            }
            for stage in stages
        ],
        "collection_evidence": raw.get("_Evidence") or {},
    }

    return NormalizedAsset(
        resource_id=f"arn:aws:apigateway:{region}::/restapis/{api_id}",
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.apigateway.rest_api",
        name=raw.get("name") or api_id,
        region=region,
        tags=raw.get("tags") if isinstance(raw.get("tags"), dict) else {},
        is_public=internet_facing,
        encryption_enabled=None,
        network_exposure="public" if internet_facing else "vpc",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_guardduty_detector(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    detector_id = raw.get("DetectorId")
    if not detector_id:
        raise ValueError("GuardDuty raw record missing DetectorId")

    region = raw.get("Region") or "global"
    properties = {
        "status": raw.get("Status"),
        "finding_publishing_frequency": raw.get("FindingPublishingFrequency"),
        "enabled_features": [
            f.get("Name") for f in raw.get("Features") or []
            if isinstance(f, dict) and f.get("Status") == "ENABLED"
        ],
        "collection_evidence": raw.get("_Evidence") or {},
    }

    return NormalizedAsset(
        resource_id=f"arn:aws:guardduty:{region}:{account_identifier}:detector/{detector_id}",
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.guardduty.detector",
        name=detector_id,
        region=region,
        tags=raw.get("Tags") if isinstance(raw.get("Tags"), dict) else {},
        is_public=False,
        encryption_enabled=None,
        network_exposure="private",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_iam_account_settings(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    """The account-wide IAM controls as one pseudo-asset.

    Root credentials and the password policy belong to the account rather than
    to any resource, but rules need something with a resource_id to attach a
    finding to. The account root ARN is the honest identifier for them.
    """
    summary = raw.get("SummaryMap") or {}
    policy = raw.get("PasswordPolicy") or {}
    account = raw.get("AccountId") or account_identifier

    properties = {
        "root_mfa_enabled": bool(summary.get("AccountMFAEnabled")),
        "root_access_keys_present": bool(summary.get("AccountAccessKeysPresent")),
        "users": summary.get("Users"),
        "mfa_devices": summary.get("MFADevices"),
        "password_policy_present": bool(policy),
        "password_min_length": policy.get("MinimumPasswordLength"),
        "password_reuse_prevention": policy.get("PasswordReusePrevention"),
        "password_require_symbols": bool(policy.get("RequireSymbols")),
        "password_require_numbers": bool(policy.get("RequireNumbers")),
        "password_require_uppercase": bool(policy.get("RequireUppercaseCharacters")),
        "password_require_lowercase": bool(policy.get("RequireLowercaseCharacters")),
        "password_max_age_days": policy.get("MaxPasswordAge"),
        "collection_evidence": raw.get("_Evidence") or {},
    }

    return NormalizedAsset(
        resource_id=f"arn:aws:iam::{account}:root",
        cloud_provider="aws",
        account_identifier=account_identifier,
        asset_type="aws.iam.account_settings",
        name=f"account-{account}",
        region="global",
        tags={},
        is_public=False,
        encryption_enabled=None,
        network_exposure="private",
        properties=properties,
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


# ── Azure / GCP (multi-cloud spine readiness) ──────────────────
# Pure normalizers so the spine accepts multi-cloud records today; the live
# collectors land once the azure-mgmt-*/google-cloud-* SDKs join the env.

def normalize_azure_storage_account(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    name = raw.get("name")
    if not name:
        raise ValueError("Azure storage raw record missing name")

    rid = raw.get("id") or f"/subscriptions/{account_identifier}/storageAccounts/{name}"
    props = raw.get("properties") or {}
    public_blob = bool(props.get("allowBlobPublicAccess"))
    encryption = (props.get("encryption") or {}).get("services") or {}
    encrypted = bool((encryption.get("blob") or {}).get("enabled", True))

    return NormalizedAsset(
        resource_id=rid,
        cloud_provider="azure",
        account_identifier=account_identifier,
        asset_type="azure.storage.account",
        name=name,
        region=raw.get("location") or "global",
        tags=raw.get("tags") or {},
        is_public=public_blob,
        encryption_enabled=encrypted,
        network_exposure="public" if public_blob else "private",
        properties={
            "sku": (raw.get("sku") or {}).get("name"),
            "kind": raw.get("kind"),
            "https_only": bool(props.get("supportsHttpsTrafficOnly", True)),
            "minimum_tls": props.get("minimumTlsVersion"),
            "allow_blob_public_access": public_blob,
        },
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


def normalize_gcp_bucket(raw: dict[str, Any], account_identifier: str) -> NormalizedAsset:
    name = raw.get("name")
    if not name:
        raise ValueError("GCS raw record missing name")

    iam = raw.get("iamConfiguration") or {}
    # allUsers/allAuthenticatedUsers binding, surfaced by the collector.
    is_public = bool(raw.get("PublicBinding"))
    uniform = bool((iam.get("uniformBucketLevelAccess") or {}).get("enabled"))

    return NormalizedAsset(
        resource_id=f"//storage.googleapis.com/{name}",
        cloud_provider="gcp",
        account_identifier=account_identifier,
        asset_type="gcp.storage.bucket",
        name=name,
        region=(raw.get("location") or "global").lower(),
        tags=raw.get("labels") or {},
        is_public=is_public,
        encryption_enabled=True,  # GCS always encrypts at rest
        network_exposure="public" if is_public else "private",
        properties={
            "storage_class": raw.get("storageClass"),
            "uniform_bucket_level_access": uniform,
            "versioning": bool((raw.get("versioning") or {}).get("enabled")),
            "public_access_prevention": iam.get("publicAccessPrevention"),
        },
        relationships=[{"type": "BELONGS_TO", "target_id": account_identifier}],
        raw=raw,
    )


# source resource type (as emitted by collectors) → normalizer fn
Normalizer = Callable[[dict[str, Any], str], NormalizedAsset]

NORMALIZERS: dict[str, Normalizer] = {
    "s3:bucket": normalize_s3_bucket,
    "aws.s3.bucket": normalize_s3_bucket,
    "ec2:instance": normalize_ec2_instance,
    "aws.ec2.instance": normalize_ec2_instance,
    "ec2:security-group": normalize_security_group,
    "aws.ec2.security_group": normalize_security_group,
    "aws.ec2.subnet": normalize_ec2_subnet,
    "aws.ec2.network_interface": normalize_ec2_network_interface,
    "aws.ec2.route_table": normalize_ec2_route_table,
    "aws.ec2.network_acl": normalize_ec2_network_acl,
    "aws.ec2.internet_gateway": normalize_ec2_internet_gateway,
    "iam:role": normalize_iam_role,
    "aws.iam.role": normalize_iam_role,
    "iam:user": normalize_iam_user,
    "aws.iam.user": normalize_iam_user,
    "rds:instance": normalize_rds_instance,
    "aws.rds.db_instance": normalize_rds_instance,
    "lambda:function": normalize_lambda_function,
    "aws.lambda.function": normalize_lambda_function,
    "ecs:cluster": normalize_ecs_cluster,
    "aws.ecs.cluster": normalize_ecs_cluster,
    "aws.ecs.task_definition": normalize_ecs_task_definition,
    "aws.eks.cluster": normalize_eks_cluster,
    "aws.ecr.repository": normalize_ecr_repository,
    "secretsmanager:secret": normalize_secret,
    "aws.secretsmanager.secret": normalize_secret,
    "rds:cluster": normalize_rds_cluster,
    "aws.rds.db_cluster": normalize_rds_cluster,
    "neptune:cluster": normalize_neptune_cluster,
    "aws.neptune.cluster": normalize_neptune_cluster,
    "docdb:cluster": normalize_docdb_cluster,
    "aws.docdb.cluster": normalize_docdb_cluster,
    "rds:proxy": normalize_rds_proxy,
    "aws.rds.db_proxy": normalize_rds_proxy,
    "redshift:cluster": normalize_redshift_cluster,
    "aws.redshift.cluster": normalize_redshift_cluster,
    "elbv2:load-balancer": normalize_load_balancer,
    "aws.elbv2.load_balancer": normalize_load_balancer,
    "azure.storage.account": normalize_azure_storage_account,
    "gcp.storage.bucket": normalize_gcp_bucket,
    "aws.cloudtrail.trail": normalize_cloudtrail,
    "aws.config.recorder": normalize_config_recorder,
    "aws.kms.key": normalize_kms_key,
    "aws.cloudwatch.log_group": normalize_cloudwatch_log_group,
    "aws.ec2.volume": normalize_ebs_volume,
    "aws.ec2.snapshot": normalize_ebs_snapshot,
    "aws.ec2.vpc": normalize_vpc,
    "aws.efs.file_system": normalize_efs_file_system,
    "aws.sns.topic": normalize_sns_topic,
    "aws.sqs.queue": normalize_sqs_queue,
    "aws.dynamodb.table": normalize_dynamodb_table,
    "aws.apigateway.rest_api": normalize_apigateway_rest_api,
    "aws.guardduty.detector": normalize_guardduty_detector,
    "aws.iam.account_settings": normalize_iam_account_settings,
}


def get_normalizer(source_type: str) -> Optional[Normalizer]:
    return NORMALIZERS.get(source_type)
