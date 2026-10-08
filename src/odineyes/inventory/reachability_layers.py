"""Layered reachability: network, identity and data proven independently.

``reachability.py`` answers one question well — can a packet arrive from the
internet. That is only the first of the three layers a reachability model needs.
A database nobody can route to is not at risk; neither is an internet-facing one
holding no sensitive data that no principal has a permission path into. Risk is
the *intersection*.

So each layer is assessed separately and keeps its own evidence:

  network   a packet can arrive           (delegated to reachability.py)
  identity  a principal has a permission path to the resource
  data      the resource holds data classified sensitive

The verdict is derived from which layers are *proven*, never from which look
likely. Every layer reuses :class:`ReachabilityAssessment`, so the same rule
holds throughout: a conclusion carries the evidence that produced it, and
anything unproven is ``unverified`` with the gap named in ``missing`` rather
than guessed at. That is deliberately stricter than the industry norm of
scoring a hunch — an unverified layer says so instead of inventing a number.

A note on the data layer specifically: ``issues.py`` infers sensitivity from a
name regex plus encryption and public flags. That is fine for ranking a list,
but it is a guess, and a guess must not become half of a "toxic" verdict. Here
the data layer is proven only from a DSPM classification and is otherwise
``unverified``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional

from odineyes.inventory.finding_risk import store_key
from odineyes.inventory.reachability import (
    _WORLD_CIDR,
    NetworkTopology,
    ReachabilityAssessment,
    _evidence,
    _relation_ids,
    _security_groups_allow_world_port,
    assess_ec2_internet_reachability,
    assess_rds_internet_reachability,
    build_network_topology,
)

LAYERS = ("network", "identity", "data")

# Labels a DSPM classification can carry that count as sensitive. Mirrors
# finding_risk._SENSITIVE deliberately: two different answers to "is this
# sensitive" in one product is a bug waiting to happen.
_SENSITIVE_LABELS = {"CRITICAL", "HIGH", "MEDIUM"}

# Asset types that can hold customer data, and so are the only ones for which a
# data-layer verdict means anything. These MUST match the strings the
# normalizers actually emit — a typo here does not fail, it silently returns
# not_applicable and quietly switches the layer off. test_reachability_layers
# asserts every entry against the canonical normalizer registry for that reason.
_DATA_STORES = {
    "aws.s3.bucket",
    "aws.rds.db_instance",
    "aws.rds.db_cluster",
    "aws.dynamodb.table",
    "aws.redshift.cluster",
    "aws.efs.file_system",
    "aws.neptune.cluster",
    "aws.docdb.cluster",
}

# Types the RDS-style proven-path evaluator handles (it gates on the public
# endpoint flag, not on type, so the dispatch decides what reaches it).
_DATABASE_TYPES = {
    "aws.rds.db_instance",
    "aws.rds.db_cluster",
    "aws.redshift.cluster",
    "aws.neptune.cluster",
    "aws.docdb.cluster",
}

# The port used when proving network reachability for a store whose own port is
# not recorded. RDS carries its endpoint port; EC2 must be asked about one.
_DEFAULT_EC2_PORT = 22
# Load balancers are probed on HTTPS unless the caller names a port.
_DEFAULT_LB_PORT = 443


@dataclass(frozen=True)
class LayeredReachability:
    """Per-layer verdicts for one resource, plus the combination they imply."""

    resource_id: str
    layers: dict[str, ReachabilityAssessment]

    @property
    def proven(self) -> tuple[str, ...]:
        """Layers proven reachable — the only ones the verdict may rest on."""
        return tuple(
            layer for layer in LAYERS
            if self.layers.get(layer) is not None
            and self.layers[layer].status == "reachable"
        )

    @property
    def verdict(self) -> str:
        """toxic | exploitable | exposed | contained | unverified.

        Ordered by how much is proven, not by how bad it sounds. ``contained``
        requires a *proven* block, so an asset we simply could not evaluate
        never masquerades as safe.
        """
        proven = set(self.proven)
        if proven == set(LAYERS):
            return "toxic"
        if "network" in proven and len(proven) >= 2:
            return "exploitable"
        if "network" in proven:
            return "exposed"
        network = self.layers.get("network")
        if network is not None and network.status == "blocked":
            return "contained"
        return "unverified"

    @property
    def unproven(self) -> tuple[str, ...]:
        """Layers that could not be decided — why a verdict is not stronger."""
        return tuple(
            layer for layer in LAYERS
            if self.layers.get(layer) is not None
            and self.layers[layer].status == "unverified"
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "verdict": self.verdict,
            "proven_layers": list(self.proven),
            "unverified_layers": list(self.unproven),
            "layers": {
                layer: assessment.as_dict()
                for layer, assessment in self.layers.items()
            },
        }


def _resource_id(asset: Any) -> str:
    return str(getattr(asset, "resource_id", "") or "")


def _facet_observed(asset: Any, facet: str) -> bool:
    """Whether a collection facet was actually observed or proven absent.

    Same gate ``rules.py`` uses. An unread facet must never be read as a benign
    value — "we could not check" and "it is off" are different answers.
    """
    properties = getattr(asset, "properties", {}) or {}
    state = (properties.get("collection_evidence") or {}).get(facet)
    return state in {"observed", "absent"}


def _assess_s3_network(asset: Any) -> ReachabilityAssessment:
    """Prove or refuse internet access to a bucket.

    S3 has no routing layer to prove a path through: the endpoint is on the
    internet by construction and access is decided entirely by the public access
    block, bucket policy and ACL. So unlike RDS, the collected exposure verdict
    *is* the packet-path proof — provided we actually observed the settings that
    produce it, which is what the evidence facet gates on.
    """
    if not _facet_observed(asset, "public_access_block"):
        return ReachabilityAssessment(
            "unverified", missing=["S3 public access block observation"]
        )

    properties = getattr(asset, "properties", {}) or {}
    block = properties.get("block_public_access") or {}
    if getattr(asset, "is_public", False):
        return ReachabilityAssessment("reachable", [_evidence(
            "s3:GetBucketPolicyStatus, s3:GetPublicAccessBlock",
            f"bucket is public with block_public_access = {block or 'none'}",
            "the bucket endpoint is internet-facing and policy permits anonymous access",
        )])
    return ReachabilityAssessment(
        "blocked",
        [_evidence(
            "s3:GetPublicAccessBlock",
            f"block_public_access = {block or 'none'}",
            "no anonymous access path",
        )],
        blockers=["bucket policy and public access block do not permit anonymous access"],
    )


def _assess_lambda_network(
    asset: Any, *, public_entrypoints: Mapping[str, str] | None = None
) -> ReachabilityAssessment:
    """Prove or refuse anonymous/any-principal invocation of a function.

    Like S3, there is no customer routing to prove: the Lambda endpoint is an
    AWS service endpoint. What decides reach is the function URL auth type, the
    resource policy, and — the case a URL-only check misses entirely — whether
    something internet-facing is wired to invoke it.

    That last one is the common shape in production. A function with no URL and
    no wildcard principal sitting behind a public REST API is fully exposed, and
    calling it ``blocked`` is a false negative on the most ordinary serverless
    deployment there is. ``public_entrypoints`` maps the ARN of an
    internet-facing front door to a short description of it; a function whose
    resource policy names one is reachable through it.
    """
    if not _facet_observed(asset, "resource_policy"):
        return ReachabilityAssessment(
            "unverified", missing=["Lambda resource policy observation"]
        )

    properties = getattr(asset, "properties", {}) or {}
    if properties.get("function_url_auth") == "NONE":
        return ReachabilityAssessment("reachable", [_evidence(
            "lambda:GetFunctionUrlConfig",
            "FunctionUrlAuthType = NONE",
            "the function URL accepts unauthenticated requests from the internet",
        )])
    if properties.get("public_policy"):
        # Deliberately distinguished in the evidence: a wildcard principal is
        # reachable by any AWS caller, which is not the same as anonymous.
        return ReachabilityAssessment("reachable", [_evidence(
            "lambda:GetPolicy",
            "resource policy grants a wildcard principal",
            "invocable by any AWS principal, not by an anonymous caller",
        )])

    triggers = [str(a) for a in properties.get("trigger_source_arns") or [] if a]
    for trigger in triggers:
        entrypoint = _match_entrypoint(trigger, public_entrypoints or {})
        if entrypoint is not None:
            front_door, description = entrypoint
            return ReachabilityAssessment("reachable", [_evidence(
                "lambda:GetPolicy, apigateway:GetRestApis",
                f"resource policy permits invocation from {trigger}",
                f"reachable through {description} ({front_door}), which resolves on "
                "the public internet",
            )])

    if triggers and public_entrypoints is None:
        # Named front doors we were never given the inventory to resolve. Saying
        # "blocked" here would be the exact false negative this branch exists to
        # prevent.
        return ReachabilityAssessment(
            "unverified",
            [_evidence("lambda:GetPolicy", f"{len(triggers)} service trigger(s)", "unresolved")],
            missing=["inventory of the services permitted to invoke this function"],
        )

    return ReachabilityAssessment(
        "blocked",
        [_evidence(
            "lambda:GetPolicy",
            "no wildcard principal, URL auth enforced"
            + (f", {len(triggers)} trigger(s) none internet-facing" if triggers else ""),
            "no path",
        )],
        blockers=["function URL requires auth, no wildcard principal, and no "
                  "internet-facing service is permitted to invoke it"],
    )


def _match_entrypoint(
    trigger_arn: str, public_entrypoints: Mapping[str, str]
) -> Optional[tuple[str, str]]:
    """Resolve a resource-policy SourceArn against known public front doors.

    SourceArn conditions are written with wildcards and a stage/method path —
    ``arn:aws:execute-api:eu-west-1:1:abc123/*/GET/users`` — while the API is
    inventoried as ``arn:aws:apigateway:eu-west-1::/restapis/abc123``. The
    stable join is the API id, so that is what is matched rather than the ARN.
    """
    for front_door, description in public_entrypoints.items():
        if not front_door:
            continue
        api_id = front_door.rstrip("/").rsplit("/", 1)[-1]
        if api_id and api_id in trigger_arn:
            return front_door, description
    return None


def public_entrypoints_for(assets: Iterable[Any]) -> dict[str, str]:
    """Internet-facing front doors that can invoke something behind them.

    Only API Gateway today. The map is ARN -> description so the evidence on the
    far side can name what the caller reaches through, instead of asserting an
    unexplained "reachable".
    """
    out: dict[str, str] = {}
    for asset in assets:
        if getattr(asset, "asset_type", "") != "aws.apigateway.rest_api":
            continue
        if not getattr(asset, "is_public", False):
            continue
        properties = getattr(asset, "properties", {}) or {}
        types = ", ".join(str(t) for t in properties.get("endpoint_types") or []) or "REGIONAL"
        name = getattr(asset, "name", "") or "REST API"
        out[_resource_id(asset)] = f"{types} API Gateway '{name}'"
    return out


def _assess_eks_network(asset: Any) -> ReachabilityAssessment:
    """Prove or refuse world access to the cluster's Kubernetes API endpoint.

    A public endpoint restricted by CIDR is genuinely not world-reachable, so
    the allow-list is checked rather than the boolean alone. Note this is the
    *network* layer only: a reachable API server still enforces Kubernetes
    authentication, which is why this alone is not an attack path.
    """
    properties = getattr(asset, "properties", {}) or {}
    if not properties.get("endpoint_public_access"):
        return ReachabilityAssessment(
            "blocked",
            [_evidence("eks:DescribeCluster", "endpointPublicAccess = false", "private endpoint")],
            blockers=["the Kubernetes API endpoint is private"],
        )

    cidrs = [str(c) for c in properties.get("public_access_cidrs") or []]
    if not cidrs or _WORLD_CIDR["ipv4"] in cidrs:
        return ReachabilityAssessment("reachable", [_evidence(
            "eks:DescribeCluster",
            f"endpointPublicAccess = true, publicAccessCidrs = {cidrs or ['0.0.0.0/0 (default)']}",
            "the Kubernetes API endpoint accepts connections from the internet",
        )])
    return ReachabilityAssessment(
        "blocked",
        [_evidence("eks:DescribeCluster", f"publicAccessCidrs = {cidrs}", "allow-list only")],
        blockers=[f"public endpoint restricted to {len(cidrs)} CIDR(s), not the world"],
    )


def _assess_elb_network(
    asset: Any, *, topology: NetworkTopology, port: Optional[int]
) -> ReachabilityAssessment:
    """Prove or refuse world access to a load balancer.

    An internet-facing scheme is stronger evidence than RDS's PubliclyAccessible
    flag: AWS will only place an internet-facing balancer in subnets with an
    Internet gateway route, so the scheme itself carries the routing proof. What
    it does not carry is the security group, so that is still checked when the
    balancer has one. Network Load Balancers may legitimately have none.
    """
    properties = getattr(asset, "properties", {}) or {}
    scheme = properties.get("scheme")
    if scheme != "internet-facing":
        return ReachabilityAssessment(
            "blocked",
            [_evidence("elasticloadbalancing:DescribeLoadBalancers", f"Scheme = {scheme}", "internal")],
            blockers=["the load balancer scheme is internal"],
        )

    evidence = [_evidence(
        "elasticloadbalancing:DescribeLoadBalancers",
        "Scheme = internet-facing",
        "AWS places internet-facing balancers only in subnets routed to an Internet gateway",
    )]
    sg_ids = _relation_ids(asset, "USES_SECURITY_GROUP") or [
        str(v) for v in properties.get("security_group_ids") or [] if v
    ]
    if not sg_ids:
        # NLBs commonly have no security group; the scheme alone is the proof.
        return ReachabilityAssessment("reachable", evidence)

    resolved = [topology.security_groups[s] for s in sg_ids if s in topology.security_groups]
    if len(resolved) != len(set(sg_ids)):
        return ReachabilityAssessment(
            "unverified", evidence, missing=["one or more load balancer security groups"]
        )
    probe = port if port is not None else _DEFAULT_LB_PORT
    open_families = _security_groups_allow_world_port(resolved, probe)
    ingress = open_families.get("ipv4") or open_families.get("ipv6")
    if not ingress:
        return ReachabilityAssessment(
            "blocked", evidence,
            blockers=[f"no attached security group allows the world to TCP port {probe}"],
        )
    return ReachabilityAssessment("reachable", evidence + [ingress])


def assess_network_layer(
    asset: Any,
    *,
    topology: NetworkTopology,
    port: Optional[int] = None,
    public_entrypoints: Mapping[str, str] | None = None,
) -> ReachabilityAssessment:
    """Delegate to the proven-path network engine by asset type."""
    asset_type = getattr(asset, "asset_type", "")
    if asset_type == "aws.s3.bucket":
        return _assess_s3_network(asset)
    if asset_type == "aws.lambda.function":
        return _assess_lambda_network(asset, public_entrypoints=public_entrypoints)
    if asset_type == "aws.eks.cluster":
        return _assess_eks_network(asset)
    if asset_type == "aws.elbv2.load_balancer":
        return _assess_elb_network(asset, topology=topology, port=port)
    if asset_type == "aws.ec2.instance":
        return assess_ec2_internet_reachability(
            asset, port if port is not None else _DEFAULT_EC2_PORT, topology=topology
        )
    if asset_type in _DATABASE_TYPES:
        return assess_rds_internet_reachability(asset, topology=topology)
    # Everything else has no evaluator. Saying "not_applicable" would claim the
    # question does not apply, which is false — it applies, we cannot answer it.
    return ReachabilityAssessment(
        "unverified", missing=[f"network reachability evaluator for {asset_type}"]
    )


def assess_identity_layer(
    asset: Any,
    *,
    relationships: Iterable[Any],
    has_identity_inventory: bool,
) -> ReachabilityAssessment:
    """Prove a permission path from some principal to this resource.

    Evidence comes from the CIEM engine, which already fails closed on missing
    policy evidence, conditions, explicit denies, unreadable permissions
    boundaries and incompatible role trust. So an edge existing here *is* the
    proof; this function's job is to attribute it, not to re-derive it.

    Absent an identity inventory the answer is unknown, not "no". A blocked
    verdict is only honest when we actually looked at the policies.
    """
    resource_id = _resource_id(asset)
    if not resource_id:
        return ReachabilityAssessment("unverified", missing=["resource id"])
    if not has_identity_inventory:
        return ReachabilityAssessment(
            "unverified", missing=["IAM role and user inventory"]
        )

    inbound = [
        relationship for relationship in relationships
        if str(getattr(relationship, "target_id", "")) == resource_id
    ]
    if not inbound:
        return ReachabilityAssessment(
            "blocked",
            blockers=["no principal has a proven permission path to this resource"],
        )

    evidence = []
    for relationship in inbound:
        properties = getattr(relationship, "properties", {}) or {}
        actions = properties.get("actions") or []
        evidence.append(_evidence(
            str(properties.get("engine") or "odineyes-ciem"),
            f"{getattr(relationship, 'source_id', '?')} "
            f"{getattr(relationship, 'relationship_type', '?')} {resource_id}",
            "; ".join(str(action) for action in actions)
            or "permission path proven by the CIEM engine",
        ))
    return ReachabilityAssessment("reachable", evidence)


def assess_data_layer(
    asset: Any,
    *,
    data_labels: Mapping[str, str],
) -> ReachabilityAssessment:
    """Prove the resource holds sensitive data, from classification only.

    ``data_labels`` maps :func:`store_key` to a DSPM sensitivity label. An
    unclassified store is ``unverified`` — never assumed clean, and never
    guessed sensitive from its name.
    """
    asset_type = getattr(asset, "asset_type", "")
    if asset_type not in _DATA_STORES:
        return ReachabilityAssessment("not_applicable")

    resource_id = _resource_id(asset)
    key = store_key(resource_id)
    if not key or key not in data_labels:
        return ReachabilityAssessment(
            "unverified", missing=[f"DSPM classification for {resource_id or asset_type}"]
        )

    label = str(data_labels[key] or "NONE").upper()
    detail = _evidence("dspm:classification", f"sensitivity = {label}", f"store {key}")
    if label in _SENSITIVE_LABELS:
        return ReachabilityAssessment("reachable", [detail])
    return ReachabilityAssessment(
        "blocked", [detail], blockers=[f"classified {label}, not sensitive"]
    )


def assess_layers(
    asset: Any,
    *,
    topology: NetworkTopology | None = None,
    network: ReachabilityAssessment | None = None,
    relationships: Iterable[Any] = (),
    data_labels: Mapping[str, str] | None = None,
    has_identity_inventory: bool = False,
    port: Optional[int] = None,
    public_entrypoints: Mapping[str, str] | None = None,
) -> LayeredReachability:
    """Assess all three layers for one asset.

    ``network`` lets a caller that has already proven the packet path hand it in
    rather than have it re-derived — the graph builder does exactly that, and
    re-running the evaluator there would double the most expensive layer.
    """
    if network is None:
        if topology is None:
            raise ValueError("assess_layers needs either a topology or a network verdict")
        network = assess_network_layer(
            asset, topology=topology, port=port, public_entrypoints=public_entrypoints
        )
    relationships = list(relationships)
    return LayeredReachability(
        resource_id=_resource_id(asset),
        layers={
            "network": network,
            "identity": assess_identity_layer(
                asset,
                relationships=relationships,
                has_identity_inventory=has_identity_inventory,
            ),
            "data": assess_data_layer(asset, data_labels=data_labels or {}),
        },
    )


def assess_account(
    assets: Iterable[Any],
    *,
    relationships: Iterable[Any] = (),
    data_labels: Mapping[str, str] | None = None,
    port: Optional[int] = None,
) -> list[LayeredReachability]:
    """Assess every asset in an account, indexing shared evidence once.

    ponytail: topology and the identity-inventory check are hoisted here for the
    same reason ``build_network_topology`` was — doing them per asset made the
    network evaluator quadratic on large accounts.
    """
    assets = list(assets)
    relationships = list(relationships)
    topology = build_network_topology(assets)
    entrypoints = public_entrypoints_for(assets)
    has_identity_inventory = any(
        getattr(asset, "asset_type", "") in {"aws.iam.role", "aws.iam.user"}
        for asset in assets
    )
    return [
        assess_layers(
            asset,
            topology=topology,
            relationships=relationships,
            data_labels=data_labels,
            has_identity_inventory=has_identity_inventory,
            port=port,
            public_entrypoints=entrypoints,
        )
        for asset in assets
    ]


def data_labels_for_account(session: Any, account_id: int) -> dict[str, str]:
    """Load persisted DSPM labels for one account, keyed for :func:`store_key`.

    Without this the data layer is permanently ``unverified`` and nothing ever
    reaches a ``toxic`` verdict — the classification exists in the DB, it just
    has to be handed to the evaluator. Import is local so the pure evaluators
    above stay usable with no database at all.
    """
    from odineyes.db.models import DspmFinding

    rows = session.query(DspmFinding.store_id, DspmFinding.label).filter(
        DspmFinding.account_id == account_id
    ).all()
    return {store_key(store_id): str(label or "NONE") for store_id, label in rows}


def toxic_combinations(results: Iterable[LayeredReachability]) -> list[LayeredReachability]:
    """Resources where all three layers are proven — reachable, permissioned and
    holding sensitive data. This is the short list worth waking someone for."""
    return [result for result in results if result.verdict == "toxic"]


if __name__ == "__main__":
    # Offline self-check: verdict arithmetic and the proven-only discipline.
    def _a(status: str) -> ReachabilityAssessment:
        return ReachabilityAssessment(status)

    def _layered(network: str, identity: str, data: str) -> LayeredReachability:
        return LayeredReachability(
            "r", {"network": _a(network), "identity": _a(identity), "data": _a(data)}
        )

    assert _layered("reachable", "reachable", "reachable").verdict == "toxic"
    assert _layered("reachable", "reachable", "unverified").verdict == "exploitable"
    assert _layered("reachable", "blocked", "blocked").verdict == "exposed"
    assert _layered("blocked", "reachable", "reachable").verdict == "contained"
    assert _layered("unverified", "reachable", "reachable").verdict == "unverified"
    # An unevaluated network layer must never read as contained.
    assert _layered("unverified", "blocked", "blocked").verdict == "unverified"
    assert _layered("reachable", "unverified", "reachable").proven == ("network", "data")
    assert _layered("reachable", "unverified", "reachable").unproven == ("identity",)

    class _Asset:
        def __init__(self, asset_type, resource_id):
            self.asset_type, self.resource_id = asset_type, resource_id
            self.properties = {}

    class _Rel:
        def __init__(self, source_id, target_id):
            self.source_id, self.target_id = source_id, target_id
            self.relationship_type = "CAN_MODIFY_AND_INVOKE"
            self.properties = {"engine": "odineyes-ciem-v1", "actions": ["lambda:Invoke"]}

    bucket = _Asset("aws.s3.bucket", "arn:aws:s3:::pii-bucket")
    # Sensitivity is proven from classification, not from the word "pii".
    assert assess_data_layer(bucket, data_labels={}).status == "unverified"
    assert assess_data_layer(bucket, data_labels={"pii-bucket": "HIGH"}).status == "reachable"
    assert assess_data_layer(bucket, data_labels={"pii-bucket": "NONE"}).status == "blocked"
    assert assess_data_layer(_Asset("aws.ec2.instance", "i-1"), data_labels={}).status == (
        "not_applicable"
    )

    # No identity inventory means unknown, never "blocked".
    assert assess_identity_layer(
        bucket, relationships=[], has_identity_inventory=False
    ).status == "unverified"
    assert assess_identity_layer(
        bucket, relationships=[], has_identity_inventory=True
    ).status == "blocked"
    reached = assess_identity_layer(
        bucket,
        relationships=[_Rel("arn:aws:iam::1:role/app", "arn:aws:s3:::pii-bucket")],
        has_identity_inventory=True,
    )
    assert reached.status == "reachable" and reached.evidence

    # A type with no network evaluator is unverified, not not_applicable: the
    # question applies, we simply cannot answer it yet.
    empty_topology = build_network_topology([])
    assert assess_network_layer(
        _Asset("aws.lambda.function", "fn"), topology=empty_topology
    ).status == "unverified"

    # S3: an unobserved public access block is never read as "not public".
    assert assess_network_layer(bucket, topology=empty_topology).status == "unverified"
    bucket.properties = {"collection_evidence": {"public_access_block": "observed"}}
    bucket.is_public = True
    assert assess_network_layer(bucket, topology=empty_topology).status == "reachable"
    bucket.is_public = False
    assert assess_network_layer(bucket, topology=empty_topology).status == "blocked"

    results = [_layered("reachable", "reachable", "reachable"), _layered("blocked", "blocked", "blocked")]
    assert len(toxic_combinations(results)) == 1

    # A handed-in network verdict is used as-is, and is required when there is
    # no topology to derive one from.
    handed = assess_layers(
        bucket,
        network=ReachabilityAssessment("reachable"),
        relationships=[_Rel("arn:aws:iam::1:role/app", "arn:aws:s3:::pii-bucket")],
        data_labels={"pii-bucket": "CRITICAL"},
        has_identity_inventory=True,
    )
    assert handed.verdict == "toxic", handed.as_dict()
    try:
        assess_layers(bucket)
    except ValueError:
        pass
    else:  # pragma: no cover - the guard is the point
        raise AssertionError("assess_layers must refuse to invent a network verdict")
    print("reachability_layers self-check OK")
