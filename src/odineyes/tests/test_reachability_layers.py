"""Layered reachability: the verdict must rest only on proven layers.

The self-check inside the module already covers the verdict arithmetic. What
matters here is the behaviour that is easy to regress once this is wired into
the graph: that an unevaluated layer never becomes a benign one, that the
sensitivity half of a "toxic" verdict comes from classification rather than
from a suggestive bucket name, and that the graph actually publishes it.
"""

from __future__ import annotations

from odineyes.inventory.graph import AssetGraph
from odineyes.inventory.reachability import ReachabilityAssessment
from odineyes.inventory.reachability_layers import (
    assess_data_layer,
    assess_identity_layer,
    assess_layers,
    assess_network_layer,
    toxic_combinations,
)
from odineyes.inventory.schema import NormalizedAsset

ACCOUNT = "123456789012"


def _bucket(name: str, *, public: bool, observed: bool = True) -> NormalizedAsset:
    evidence = {"public_access_block": "observed" if observed else "unavailable"}
    return NormalizedAsset(
        resource_id=f"arn:aws:s3:::{name}",
        cloud_provider="aws",
        account_identifier=ACCOUNT,
        asset_type="aws.s3.bucket",
        name=name,
        is_public=public,
        properties={"collection_evidence": evidence, "block_public_access": {}},
    )


def _role(name: str) -> NormalizedAsset:
    return NormalizedAsset(
        resource_id=f"arn:aws:iam::{ACCOUNT}:role/{name}",
        cloud_provider="aws",
        account_identifier=ACCOUNT,
        asset_type="aws.iam.role",
        name=name,
        properties={},
    )


class _Rel:
    def __init__(self, source_id: str, target_id: str) -> None:
        self.source_id = source_id
        self.target_id = target_id
        self.relationship_type = "CAN_ACCESS"
        self.properties = {"engine": "odineyes-ciem-v1", "actions": ["s3:GetObject"]}


def test_layer_asset_types_match_the_normalizers():
    """A typo in an asset-type string does not fail — it silently returns
    not_applicable and switches the layer off. Pin them to the real registry."""
    from odineyes.inventory.normalizers import NORMALIZERS
    from odineyes.inventory.reachability_layers import _DATA_STORES, _DATABASE_TYPES

    known = set(NORMALIZERS)
    assert _DATA_STORES - known == set(), _DATA_STORES - known
    assert _DATABASE_TYPES - known == set(), _DATABASE_TYPES - known


def test_unobserved_public_access_block_is_not_read_as_private():
    """The failure that matters: treating "we could not check" as "it is fine"."""
    assessment = assess_network_layer(
        _bucket("b", public=False, observed=False), topology=None  # type: ignore[arg-type]
    )
    assert assessment.status == "unverified"
    assert assessment.missing == ["S3 public access block observation"]


def test_sensitivity_comes_from_classification_not_from_the_name():
    bucket = _bucket("customer-pii-prod", public=True)
    # A name screaming PII proves nothing on its own.
    assert assess_data_layer(bucket, data_labels={}).status == "unverified"
    assert assess_data_layer(
        bucket, data_labels={"customer-pii-prod": "HIGH"}
    ).status == "reachable"
    # And a classified-clean store is a proven block, not a silent pass.
    assert assess_data_layer(
        bucket, data_labels={"customer-pii-prod": "NONE"}
    ).status == "blocked"


def test_identity_layer_without_iam_inventory_is_unknown_not_blocked():
    bucket = _bucket("b", public=True)
    assert assess_identity_layer(
        bucket, relationships=[], has_identity_inventory=False
    ).status == "unverified"
    assert assess_identity_layer(
        bucket, relationships=[], has_identity_inventory=True
    ).status == "blocked"


def test_toxic_requires_all_three_layers_proven():
    bucket = _bucket("pii", public=True)
    relationship = _Rel(f"arn:aws:iam::{ACCOUNT}:role/app", bucket.resource_id)

    partial = assess_layers(
        bucket,
        network=ReachabilityAssessment("reachable"),
        relationships=[relationship],
        data_labels={},                      # sensitivity unknown
        has_identity_inventory=True,
    )
    assert partial.verdict == "exploitable"
    assert partial.unproven == ("data",)
    assert not toxic_combinations([partial])

    full = assess_layers(
        bucket,
        network=ReachabilityAssessment("reachable"),
        relationships=[relationship],
        data_labels={"pii": "CRITICAL"},
        has_identity_inventory=True,
    )
    assert full.verdict == "toxic"
    assert full.proven == ("network", "identity", "data")
    assert toxic_combinations([partial, full]) == [full]


def _asset(asset_type: str, resource_id: str, properties: dict, **kwargs) -> NormalizedAsset:
    return NormalizedAsset(
        resource_id=resource_id, cloud_provider="aws", account_identifier=ACCOUNT,
        asset_type=asset_type, properties=properties, **kwargs,
    )


def test_lambda_unauthenticated_url_is_reachable_but_wildcard_policy_is_distinguished():
    observed = {"collection_evidence": {"resource_policy": "observed"}}
    anon = _asset("aws.lambda.function", "arn:fn:anon", {**observed, "function_url_auth": "NONE"})
    result = assess_network_layer(anon, topology=None)  # type: ignore[arg-type]
    assert result.status == "reachable"
    assert "unauthenticated" in result.evidence[0]["effect"]

    wildcard = _asset("aws.lambda.function", "arn:fn:wild", {**observed, "public_policy": True})
    result = assess_network_layer(wildcard, topology=None)  # type: ignore[arg-type]
    assert result.status == "reachable"
    # A wildcard principal is any AWS caller, not an anonymous one.
    assert "any AWS principal" in result.evidence[0]["effect"]

    private = _asset("aws.lambda.function", "arn:fn:priv", {**observed, "function_url_auth": "AWS_IAM"})
    assert assess_network_layer(private, topology=None).status == "blocked"  # type: ignore[arg-type]

    # Unread resource policy is never read as "not public".
    blind = _asset("aws.lambda.function", "arn:fn:blind", {})
    assert assess_network_layer(blind, topology=None).status == "unverified"  # type: ignore[arg-type]


def test_eks_public_endpoint_restricted_by_cidr_is_not_world_reachable():
    world = _asset("aws.eks.cluster", "arn:eks:a", {
        "endpoint_public_access": True, "public_access_cidrs": ["0.0.0.0/0"]})
    assert assess_network_layer(world, topology=None).status == "reachable"  # type: ignore[arg-type]

    # A public endpoint locked to an office range is genuinely not world-open.
    fenced = _asset("aws.eks.cluster", "arn:eks:b", {
        "endpoint_public_access": True, "public_access_cidrs": ["203.0.113.0/24"]})
    assert assess_network_layer(fenced, topology=None).status == "blocked"  # type: ignore[arg-type]

    private = _asset("aws.eks.cluster", "arn:eks:c", {"endpoint_public_access": False})
    assert assess_network_layer(private, topology=None).status == "blocked"  # type: ignore[arg-type]


def test_internet_facing_load_balancer_still_checks_its_security_group():
    from odineyes.inventory.reachability import build_network_topology

    sg = _asset(
        "aws.ec2.security_group",
        f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/sg-1",
        {"world_open_ingress": [
            {"cidr": "0.0.0.0/0", "protocol": "tcp", "from_port": 443, "to_port": 443}
        ]},
    )
    closed_sg = _asset(
        "aws.ec2.security_group",
        f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/sg-2",
        {"world_open_ingress": []},
    )
    topology = build_network_topology([sg, closed_sg])

    open_lb = _asset("aws.elbv2.load_balancer", "arn:lb:1", {
        "scheme": "internet-facing", "security_group_ids": ["sg-1"]})
    assert assess_network_layer(open_lb, topology=topology).status == "reachable"

    shut_lb = _asset("aws.elbv2.load_balancer", "arn:lb:2", {
        "scheme": "internet-facing", "security_group_ids": ["sg-2"]})
    assert assess_network_layer(shut_lb, topology=topology).status == "blocked"

    internal = _asset("aws.elbv2.load_balancer", "arn:lb:3", {"scheme": "internal"})
    assert assess_network_layer(internal, topology=topology).status == "blocked"

    # An NLB with no security group rests on the scheme alone, which AWS backs:
    # internet-facing balancers only live in IGW-routed subnets.
    nlb = _asset("aws.elbv2.load_balancer", "arn:lb:4", {"scheme": "internet-facing"})
    assert assess_network_layer(nlb, topology=topology).status == "reachable"


def test_graph_publishes_a_layered_verdict_per_asset():
    bucket = _bucket("pii", public=True)
    graph = AssetGraph.build([bucket, _role("app")], data_labels={"pii": "CRITICAL"})

    layered = graph.nodes[bucket.resource_id].properties["layered_reachability"]
    assert layered["layers"]["network"]["status"] == "reachable"
    assert layered["layers"]["data"]["status"] == "reachable"
    # No CIEM edge reaches this bucket, so identity is a proven block and the
    # verdict must stop short of toxic. It is still "exploitable": a public
    # bucket holding PII is taken anonymously, without any principal path.
    assert layered["layers"]["identity"]["status"] == "blocked"
    assert layered["verdict"] == "exploitable"
    assert layered["proven_layers"] == ["network", "data"]


def test_graph_layered_verdict_degrades_to_unverified_without_evidence():
    bucket = _bucket("quiet", public=False, observed=False)
    graph = AssetGraph.build([bucket])
    layered = graph.nodes[bucket.resource_id].properties["layered_reachability"]
    assert layered["verdict"] == "unverified"
    assert "network" in layered["unverified_layers"]
    assert "identity" in layered["unverified_layers"]


# ── internet -> API Gateway -> Lambda ───────────────────────────

def _api(api_id: str, *, public: bool, types: list[str] | None = None) -> NormalizedAsset:
    return _asset(
        "aws.apigateway.rest_api", f"arn:aws:apigateway:eu-west-1::/restapis/{api_id}",
        {"endpoint_types": types or (["REGIONAL"] if public else ["PRIVATE"])},
        name=f"api-{api_id}", is_public=public,
    )


def _fn(name: str, triggers: list[str]) -> NormalizedAsset:
    return _asset(
        "aws.lambda.function", f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:{name}",
        {"collection_evidence": {"resource_policy": "observed"},
         "function_url_auth": "AWS_IAM", "public_policy": False,
         "trigger_source_arns": triggers},
        name=name,
    )


def test_lambda_behind_a_public_api_gateway_is_reachable_not_contained():
    """The blind spot a function-URL-only check leaves: no URL, no wildcard
    principal, and still fully exposed through a public REST API."""
    from odineyes.inventory.reachability_layers import public_entrypoints_for

    api = _api("abc123", public=True)
    fn = _fn("orders", [f"arn:aws:execute-api:eu-west-1:{ACCOUNT}:abc123/*/GET/orders"])
    entrypoints = public_entrypoints_for([api, fn])

    result = assess_network_layer(fn, topology=None, public_entrypoints=entrypoints)  # type: ignore[arg-type]
    assert result.status == "reachable"
    assert "API Gateway" in result.evidence[0]["effect"]


def test_a_private_api_gateway_does_not_make_its_lambda_reachable():
    from odineyes.inventory.reachability_layers import public_entrypoints_for

    api = _api("priv99", public=False)
    fn = _fn("internal", [f"arn:aws:execute-api:eu-west-1:{ACCOUNT}:priv99/*/POST/x"])
    entrypoints = public_entrypoints_for([api, fn])
    assert entrypoints == {}, "a PRIVATE API is not a public entrypoint"

    result = assess_network_layer(fn, topology=None, public_entrypoints=entrypoints)  # type: ignore[arg-type]
    assert result.status == "blocked"


def test_named_triggers_with_no_inventory_are_unverified_never_blocked():
    """Refusing to resolve a front door must not be reported as there being no
    front door — that is the false negative this whole branch exists to stop."""
    fn = _fn("mystery", ["arn:aws:execute-api:eu-west-1:1:zzz/*/GET/"])
    result = assess_network_layer(fn, topology=None)  # type: ignore[arg-type]
    assert result.status == "unverified"
    assert result.missing == [
        "inventory of the services permitted to invoke this function"]


def test_a_lambda_with_no_triggers_at_all_is_still_a_proven_block():
    fn = _fn("quiet", [])
    assert assess_network_layer(fn, topology=None, public_entrypoints={}).status == "blocked"  # type: ignore[arg-type]
