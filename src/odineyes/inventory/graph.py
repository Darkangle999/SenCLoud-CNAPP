"""In-process security graph over the normalized inventory spine.

Builds nodes from persisted ``Asset`` rows (or in-memory ``NormalizedAsset``
objects — anything satisfying ``rules.AssetLike``) and derives edges from the
standard fields and relationships every normalizer guarantees. No external
graph store: the asset set for one account fits comfortably in memory, and the
same traversals run identically in tests and production.

Edge derivations:
  EXPOSED_TO            internet → any public asset (port labels via attached SGs)
  USES_SECURITY_GROUP   instance → security group (resolved from the bare sg-id)
  CAN_ASSUME            instance → role (instance-profile name → role name) and
                        external principal → role (wildcard / external trust)
  CAN_ACCESS            admin role → every bucket (admin reads all data)
"""

from __future__ import annotations

import hashlib
import re
from fnmatch import fnmatchcase, translate
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from odineyes.inventory.iam_analysis import (
    ASSUME_ROLE_ACTIONS,
    S3_READ_ACTIONS,
    boundary_allows,
    identity_allows,
)
from odineyes.inventory.ciem_relationships import derive_ciem_relationships
from odineyes.inventory.finding_risk import store_key
from odineyes.inventory.normalizers import extract_trust_statement_evidence
from odineyes.inventory.reachability import (
    ReachabilityAssessment,
    assess_ec2_internet_reachability,
    assess_rds_internet_reachability,
    build_network_topology,
    public_endpoint_configured,
)
from odineyes.inventory.reachability_layers import (
    assess_layers,
    assess_network_layer,
    public_entrypoints_for,
)

INTERNET_ID = "internet"

# Edge types an attacker actually traverses (USES_SECURITY_GROUP is metadata).
_ATTACK_EDGES = (
    "EXPOSED_TO",
    "CAN_ASSUME",
    "CAN_ACCESS",
    "CAN_MODIFY_AND_INVOKE",
    "CAN_IMPERSONATE_VIA_SERVICE",
)
_TARGET_KINDS = ("role", "bucket", "database")
# Names that imply the data/identity at the end of a path is worth reaching.
_SENSITIVE = re.compile(
    r"(data|backup|log|secret|cred|customer|cust|prod|pii|financ|private|confidential|admin)", re.I,
)

# asset_type → graph node kind (unknown types stay out of the graph).
_KINDS = {
    "aws.ec2.instance": "compute",
    "aws.lambda.function": "compute",
    "aws.ecs.task_definition": "workload",
    "aws.eks.cluster": "kubernetes",
    "aws.ecr.repository": "container_registry",
    # Carried so the layered reachability pass can reach it. Detectors query by
    # kind, so a kind none of them ask for adds a node without changing them.
    "aws.elbv2.load_balancer": "load_balancer",
    "aws.ec2.security_group": "security_group",
    "aws.iam.role": "role",
    "aws.iam.user": "user",
    "aws.s3.bucket": "bucket",
    "aws.rds.db_instance": "database",
    "aws.rds.db_cluster": "database",
    "aws.neptune.cluster": "database",
    "aws.docdb.cluster": "database",
    "aws.redshift.cluster": "database",
}


_GLOB = re.compile(r"[*?\[]")


class _GrantIndex:
    """One principal's IAM resource grants, pre-sorted by how they match.

    The identity loops test every grant against every bucket and every role, so
    on a large account this ran hundreds of thousands of ``fnmatchcase`` calls —
    each one translating the pattern and running a regex. Almost all real grants
    are literal ARNs, which is a dict lookup. Splitting them up front turns the
    common case into O(1) and leaves the regex only for grants that need it.
    """

    __slots__ = ("star", "exact", "patterns")

    def __init__(self, grants: Iterable[str]) -> None:
        self.star: list[str] = []
        self.exact: dict[str, list[str]] = {}
        self.patterns: list[tuple[re.Pattern[str], str]] = []
        for grant in grants:
            if grant == "*":
                self.star.append(grant)
                continue
            if _GLOB.search(grant):
                self.patterns.append((re.compile(translate(grant)), grant))
            else:
                self.exact.setdefault(grant, []).append(grant)
            # An S3 grant also matches its bucket node by exact ARN, whether or
            # not the object suffix globs — mirrors _resource_matches, which
            # compares the collapsed ARN with == rather than fnmatch. Skipped
            # when the grant already is that ARN, else a plain bucket grant
            # would be registered twice and returned duplicated.
            if grant.startswith("arn:aws:s3:::"):
                collapsed = "arn:aws:s3:::" + grant.split(":::", 1)[1].split("/", 1)[0]
                if collapsed != grant:
                    self.exact.setdefault(collapsed, []).append(grant)

    def __bool__(self) -> bool:
        return bool(self.star or self.exact or self.patterns)

    def matches(self, node_id: str) -> list[str]:
        """Grants that cover ``node_id``. Order-independent — every caller
        sorts the result into a set for evidence."""
        found = list(self.star)
        found += self.exact.get(node_id, ())
        for pattern, grant in self.patterns:
            if pattern.match(node_id):
                found.append(grant)
        return found


@dataclass
class Node:
    id: str
    kind: str
    name: str
    asset: Any = None  # backing AssetLike, None for pseudo-nodes
    properties: dict[str, Any] = field(default_factory=dict)

    def hop(self) -> dict[str, str]:
        return {"kind": self.kind, "id": self.id, "name": self.name}


@dataclass
class Edge:
    src: str
    dst: str
    edge_type: str
    properties: dict[str, Any] = field(default_factory=dict)


class AssetGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self._out: dict[str, list[Edge]] = {}
        # (src, dst, edge_type) -> Edge. Insertion has to be idempotent, and
        # scanning src's edge list to check made _add_edge quadratic in
        # out-degree: an admin role gets one CAN_ACCESS edge per bucket, so the
        # 800th bucket rescanned 799 edges. That single lookup was ~43% of the
        # whole build on a 3.3k-asset account.
        self._edge_index: dict[tuple[str, str, str], Edge] = {}
        # kind -> {node_id: Node}, maintained on insert. nodes_of_kind is called
        # inside the identity loops, and a full scan of self.nodes each time is
        # the other half of the same quadratic. Keyed by id (not a list) because
        # the same external principal is re-added once per role that trusts it.
        self._by_kind: dict[str, dict[str, Node]] = {}

    def node(self, node_id: str) -> Optional[Node]:
        return self.nodes.get(node_id)

    def out_edges(self, node_id: str, edge_type: Optional[str] = None) -> list[Edge]:
        edges = self._out.get(node_id, [])
        return [e for e in edges if edge_type is None or e.edge_type == edge_type]

    def nodes_of_kind(self, kind: str) -> list[Node]:
        return list(self._by_kind.get(kind, {}).values())

    def all_edges(self) -> list[Edge]:
        return [e for edges in self._out.values() for e in edges]

    def _path_meta(self, trail: list[str]) -> dict[str, Any]:
        """Derive a severity + label for one enumerated attacker route."""
        nodes = [self.nodes[i] for i in trail]
        term = nodes[-1]
        has_admin = any(n.kind == "role" and n.properties.get("has_admin") for n in nodes)
        sensitive = any(
            n.kind in ("bucket", "database") and _SENSITIVE.search(n.name) for n in nodes
        )
        if has_admin:
            severity = "critical"
        elif term.kind == "database" or sensitive:
            severity = "high"
        elif term.kind == "role":
            severity = "high"
        elif term.kind == "bucket":
            severity = "medium"
        else:
            severity = "low"
        pid = "path:" + hashlib.sha1("|".join(trail).encode()).hexdigest()[:12]
        return {
            "id": pid, "nodes": list(trail), "length": len(trail) - 1,
            "entry": nodes[0].kind, "target": term.name, "target_kind": term.kind,
            "severity": severity,
        }

    def enumerate_paths(self, max_depth: int = 7, max_paths: int = 400) -> list[dict[str, Any]]:
        """Every distinct simple attacker route from an entry point (internet or
        an external principal) to a reachable target (role / bucket / database).
        This is the superset of what the curated detectors flag — it surfaces
        latent paths no single rule names. Depth- and count-capped so a dense
        graph can't explode combinatorially."""
        starts = [INTERNET_ID] + [n.id for n in self.nodes_of_kind("external")]
        results: list[dict[str, Any]] = []
        seen: set[tuple[str, ...]] = set()

        def dfs(node_id: str, trail: list[str]) -> None:
            if len(results) >= max_paths:
                return
            node = self.nodes.get(node_id)
            # Emit a route whenever the current terminal is a valuable target and
            # the trail has actually moved (≥2 nodes), even if it can extend further.
            if node and node.kind in _TARGET_KINDS and len(trail) >= 2:
                key = tuple(trail)
                if key not in seen:
                    seen.add(key)
                    results.append(self._path_meta(trail))
            if len(trail) >= max_depth:
                return
            for e in self.out_edges(node_id):
                if (
                    e.edge_type in _ATTACK_EDGES
                    and not e.properties.get("verified_onboarding")
                    and e.dst not in trail
                ):
                    dfs(e.dst, trail + [e.dst])

        for s in starts:
            if s in self.nodes:
                dfs(s, [s])

        results.sort(key=lambda p: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(p["severity"], 9), -p["length"]))
        return results

    def serialize(self) -> dict[str, Any]:
        """Flatten to JSON-able nodes + edges for the graph canvas. Must be
        called while the backing assets are still session-attached."""
        # Property keys worth surfacing to the UI (drives node badges / colors).
        _PROP_KEYS = ("has_admin", "wildcard", "publicly_assumable", "engine", "open_port_labels")
        nodes = []
        for n in self.nodes.values():
            asset = n.asset
            nodes.append({
                "id": n.id, "kind": n.kind, "name": n.name,
                "asset_type": getattr(asset, "asset_type", None),
                "region": getattr(asset, "region", None),
                "is_public": bool(getattr(asset, "is_public", False)),
                "risk_score": float(getattr(asset, "risk_score", 0) or 0),
                "properties": {k: n.properties.get(k) for k in _PROP_KEYS if n.properties.get(k) is not None},
            })
        edges = []
        for e in self.all_edges():
            ed: dict[str, Any] = {"source": e.src, "target": e.dst, "type": e.edge_type}
            if e.properties.get("port_labels"):
                ed["ports"] = e.properties["port_labels"]
            if e.properties.get("wildcard"):
                ed["wildcard"] = True
            if e.properties.get("verified_onboarding"):
                ed["verified_onboarding"] = True
            for key in (
                "engine", "via_service", "actions", "evidence",
                "authorization_scope", "effective_access_complete",
            ):
                if key in e.properties:
                    ed[key] = e.properties[key]
            edges.append(ed)
        return {"nodes": nodes, "edges": edges}

    def _add_node(self, node: Node) -> Node:
        previous = self.nodes.get(node.id)
        if previous is not None and previous.kind != node.kind:
            self._by_kind.get(previous.kind, {}).pop(node.id, None)
        self._by_kind.setdefault(node.kind, {})[node.id] = node
        self.nodes[node.id] = node
        return node

    def _add_edge(self, src: str, dst: str, edge_type: str, properties: Optional[dict] = None) -> None:
        existing = self._edge_index.get((src, dst, edge_type))
        if existing is not None:
            existing.properties.update(properties or {})
            return
        edge = Edge(src, dst, edge_type, properties or {})
        self._edge_index[(src, dst, edge_type)] = edge
        self._out.setdefault(src, []).append(edge)

    @staticmethod
    def _resource_matches(node_id: str, grant: str) -> bool:
        if grant == "*" or fnmatchcase(node_id, grant):
            return True
        # S3 object grants use arn:...:bucket/prefix/* while the graph node is
        # the bucket ARN. Collapse the object suffix to its datastore node.
        if grant.startswith("arn:aws:s3:::"):
            bucket_arn = "arn:aws:s3:::" + grant.split(":::", 1)[1].split("/", 1)[0]
            return node_id == bucket_arn
        return False

    @staticmethod
    def _grant_index(grants: list[str]) -> "_GrantIndex":
        """Compile one principal's grants once instead of fnmatch-ing every
        (grant, resource) pair. Same verdict as ``_resource_matches`` — the
        module self-check asserts that against the original on random input."""
        return _GrantIndex(grants)

    @staticmethod
    def _account_from_arn(arn: str) -> Optional[str]:
        parts = arn.split(":")
        return parts[4] if len(parts) > 4 and parts[4] else None

    @classmethod
    def _trusts_principal(cls, target: Node, source_id: str) -> bool:
        if target.properties.get("publicly_assumable"):
            return True
        principals = [str(p) for p in target.properties.get("trust_principals") or []]
        source_account = cls._account_from_arn(source_id)
        candidates = {source_id}
        if source_account:
            candidates.add(f"arn:aws:iam::{source_account}:root")
        return any(
            principal == "*"
            or any(fnmatchcase(candidate, principal) for candidate in candidates)
            for principal in principals
        )

    @staticmethod
    def _trust_evidence(node: Node) -> list[dict[str, list[str]]]:
        """Read normalized trust evidence, with a raw-policy fallback.

        The fallback makes the fix effective for inventories collected before
        ``trust_statements`` was added: their persisted raw IAM GetRole record
        already contains the trust policy we need to validate.
        """
        evidence = node.properties.get("trust_statements") or []
        if evidence:
            return [item for item in evidence if isinstance(item, dict)]
        raw = getattr(node.asset, "raw", None) or {}
        return extract_trust_statement_evidence(raw.get("AssumeRolePolicyDocument"))

    @classmethod
    def _verified_onboarding_trust(
        cls,
        target: Node,
        principal: str,
        scanner_principal_arn: Optional[str],
        expected_external_id: Optional[str],
        expected_role_arn: Optional[str],
    ) -> tuple[bool, bool]:
        """Return ``(verified, has_external_id)`` for one trust principal.

        A connection is expected only when all three independently observed
        facts agree: this is the role registered for the customer account, the
        trust names this deployment's exact scanner principal, and the
        statement carries the stable account ExternalId. A matching role name,
        account root, or *any* ExternalId is deliberately insufficient.
        """
        has_external_id = False
        for statement in cls._trust_evidence(target):
            principals = {str(value) for value in statement.get("principals") or []}
            if principal not in principals:
                continue
            external_ids = {str(value) for value in statement.get("external_ids") or []}
            has_external_id = has_external_id or bool(external_ids)
            if (
                scanner_principal_arn
                and expected_external_id
                and expected_role_arn == target.id
                and principal == scanner_principal_arn
                and expected_external_id in external_ids
            ):
                return True, True
        return False, has_external_id

    def analysis_summary(self, *, total_assets: int, paths: list[dict[str, Any]]) -> dict[str, Any]:
        """Explain whether an empty path set is a clean result or weak evidence."""
        edges = self.all_edges()
        attack_edges = [
            e for e in edges
            if e.edge_type in _ATTACK_EDGES and not e.properties.get("verified_onboarding")
        ]
        entry_edges = [e for e in attack_edges if e.src == INTERNET_ID or e.src.startswith("external:")]
        identities = self.nodes_of_kind("role") + self.nodes_of_kind("user")
        policy_observed = sum(
            1 for node in identities if node.properties.get("policy_analysis_complete")
        )
        data_nodes = self.nodes_of_kind("bucket") + self.nodes_of_kind("database")

        coverage = [
            {"key": "inventory", "status": "ready" if total_assets else "missing",
             "observed": total_assets,
             "detail": f"{total_assets} active assets normalized." if total_assets else "No assets scanned."},
            {"key": "identity", "status": (
                "not_observed" if not identities else
                "ready" if policy_observed == len(identities) else "partial"),
             "observed": len(identities),
             "detail": (f"Policy evidence collected for {policy_observed}/{len(identities)} identities."
                        if identities else "No IAM identities observed.")},
            {"key": "data", "status": "ready" if data_nodes else "not_observed",
             "observed": len(data_nodes),
             "detail": f"{len(data_nodes)} graphable data stores observed." if data_nodes else "No graphable data stores observed."},
            {"key": "relationships", "status": (
                "ready" if not identities or policy_observed == len(identities) else "partial"),
             "observed": len(attack_edges),
             "detail": f"{len(attack_edges)} attacker-traversable relationships derived."},
            {"key": "entry_points", "status": "ready",
             "observed": len(entry_edges),
             "detail": (f"{len(entry_edges)} public or external entry relationships observed."
                        if entry_edges else "No public or externally trusted entry relationship observed.")},
        ]

        if not total_assets:
            status, conclusion = "insufficient", "not_analyzed"
            message = "No inventory evidence is available. Run a successful scan before interpreting attack paths."
        elif policy_observed < len(identities):
            status, conclusion = "partial", "insufficient_identity_evidence"
            message = ("No path can be declared clean yet: IAM policy evidence is incomplete. "
                       "Run a fresh scan with the updated collector.")
        elif paths:
            status, conclusion = "ready", "paths_detected"
            message = f"{len(paths)} walkable attack path(s) were derived from current evidence."
        elif not entry_edges:
            status, conclusion = "ready", "no_entry_points_observed"
            message = ("No walkable path was found because the scan observed no public or external "
                       "entry relationship in the modeled assets.")
        else:
            status, conclusion = "ready", "no_path_to_target"
            message = "Entry points exist, but none reaches a privileged identity or data target."

        return {
            "status": status,
            "conclusion": conclusion,
            "message": message,
            "metrics": {
                "assets": total_assets,
                "graph_nodes": len(self.nodes),
                "graph_edges": len(edges),
                "attack_edges": len(attack_edges),
                "entry_edges": len(entry_edges),
                "paths": len(paths),
            },
            "coverage": coverage,
            "limitations": [
                "SCPs, RCPs, session policies, resource policies, and conditional request context are not fully evaluated.",
                "Conditional service-escalation grants fail closed until request-context evaluation is implemented.",
                "A missing runtime sensor means paths are possible exposures, not proof of active exploitation.",
            ],
        }

    @classmethod
    def build(
        cls,
        assets: Iterable[Any],
        *,
        scanner_principal_arn: Optional[str] = None,
        account_external_ids: Optional[dict[str, str]] = None,
        account_role_arns: Optional[dict[str, str]] = None,
        data_labels: Optional[dict[str, str]] = None,
    ) -> "AssetGraph":
        """Build the graph, optionally identifying verified onboarding trust.

        The account maps are supplied by the service from CloudAccount records,
        never from a role's own policy, so an attacker cannot self-label a
        trust as benign.
        """
        g = cls()
        g._add_node(Node(INTERNET_ID, "internet", "Internet"))

        account_external_ids = account_external_ids or {}
        account_role_arns = account_role_arns or {}

        all_assets = list(assets)
        assets = [a for a in all_assets if a.asset_type in _KINDS]
        # Indexed once here, not per database: the reachability evaluator is
        # called for every public database and each build is a full asset scan.
        network_topology = build_network_topology(all_assets)
        # Network verdicts are recorded as they are proven below, then reused by
        # the layered pass rather than re-derived — it is the costly layer.
        network_verdicts: dict[str, ReachabilityAssessment] = {}
        # Relationships carry bare ids (sg-xxx); assets key on full ARNs —
        # index by the trailing path segment to resolve them.
        by_short: dict[str, str] = {}
        role_by_name: dict[str, str] = {}
        for a in assets:
            kind = _KINDS[a.asset_type]
            name = getattr(a, "name", None) or a.resource_id
            g._add_node(Node(a.resource_id, kind, name, a, dict(a.properties or {})))
            by_short[a.resource_id.rsplit("/", 1)[-1]] = a.resource_id
            if kind == "role":
                role_by_name[name] = a.resource_id

        for a in assets:
            kind = _KINDS[a.asset_type]
            node = g.nodes[a.resource_id]

            if kind in {"compute", "workload", "kubernetes"}:
                for rel in a.relationships or []:
                    if rel.get("type") == "USES_SECURITY_GROUP":
                        sg_id = by_short.get(str(rel.get("target_id")))
                        if sg_id:
                            g._add_edge(a.resource_id, sg_id, "USES_SECURITY_GROUP")
                    elif rel.get("type") == "EXECUTES_AS":
                        # Lambda execution role: the relationship target is the
                        # role ARN itself, so it resolves directly.
                        if rel.get("target_id") in g.nodes:
                            g._add_edge(a.resource_id, str(rel["target_id"]), "CAN_ASSUME")
                # Instance-profile → role: AWS creates the profile with the
                # role's name by default, so a name match is the binding in the
                # overwhelmingly common case (the raw EC2 record carries only
                # the profile ARN, never the role).
                profile_arn = (a.properties or {}).get("iam_instance_profile")
                if profile_arn:
                    profile_name = str(profile_arn).rsplit("/", 1)[-1]
                    role_id = role_by_name.get(profile_name)
                    if role_id:
                        g._add_edge(a.resource_id, role_id, "CAN_ASSUME")
                # A public EC2/Lambda endpoint can be an attacker entry. An EKS
                # public API endpoint still enforces Kubernetes authentication,
                # and task definitions describe desired state rather than a
                # reachable runtime endpoint, so neither becomes an attack-path
                # entry merely from its inventory record.
                if a.asset_type == "aws.ec2.instance":
                    port_labels: list[str] = []
                    for e in g.out_edges(a.resource_id, "USES_SECURITY_GROUP"):
                        sg = g.node(e.dst)
                        if sg:
                            port_labels += sg.properties.get("open_port_labels") or []
                    probe_ports = sorted({
                        int(port)
                        for e in g.out_edges(a.resource_id, "USES_SECURITY_GROUP")
                        for sg in [g.node(e.dst)]
                        if sg
                        for port in (sg.properties.get("open_ports") or [])
                    })
                    assessments = [
                        assess_ec2_internet_reachability(
                            a, 22 if port == 0 else port, topology=network_topology
                        )
                        for port in probe_ports
                    ]
                    node.properties["internet_reachability"] = [
                        assessment.as_dict() for assessment in assessments
                    ]
                    # One instance, several probed ports: the network layer is
                    # reachable if any single port proves a path.
                    network_verdicts[a.resource_id] = next(
                        (x for x in assessments if x.status == "reachable"),
                        assessments[0] if assessments else ReachabilityAssessment(
                            "unverified", missing=["no open ports to probe"]
                        ),
                    )
                    if any(assessment.status == "reachable" for assessment in assessments):
                        g._add_edge(
                            INTERNET_ID, a.resource_id, "EXPOSED_TO",
                            {"port_labels": sorted(set(port_labels)), "verified": True},
                        )
                elif kind == "compute" and a.is_public:
                    # Lambda function URLs are service endpoints; unlike EC2,
                    # their path does not depend on customer VPC routing.
                    g._add_edge(INTERNET_ID, a.resource_id, "EXPOSED_TO")

            elif kind == "database" and public_endpoint_configured(a):
                # RDS PubliclyAccessible is a configuration flag, not a packet
                # path. Only fully proven evidence becomes an attacker edge.
                assessment = assess_rds_internet_reachability(a, topology=network_topology)
                node.properties["internet_reachability"] = assessment.as_dict()
                network_verdicts[a.resource_id] = assessment
                if assessment.status == "reachable":
                    g._add_edge(
                        INTERNET_ID, a.resource_id, "EXPOSED_TO",
                        {"reachability": assessment.as_dict(), "verified": True},
                    )

            elif kind == "bucket" and a.is_public:
                g._add_edge(INTERNET_ID, a.resource_id, "EXPOSED_TO")

            elif kind == "role":
                props = a.properties or {}
                if props.get("has_admin"):
                    for bucket in g.nodes_of_kind("bucket"):
                        g._add_edge(a.resource_id, bucket.id, "CAN_ACCESS")
                if props.get("trust_external") or props.get("publicly_assumable"):
                    wildcard = bool(props.get("publicly_assumable"))
                    principals = [str(value) for value in props.get("trust_principals") or []]
                    if wildcard:
                        principals = ["*"]
                    if not principals:
                        principals = ["unknown-external-principal"]
                    # NormalizedAsset carries account_identifier; the persisted
                    # SQL Asset does not, so derive the AWS account from its ARN.
                    account_identifier = (
                        getattr(a, "account_identifier", None)
                        or cls._account_from_arn(a.resource_id)
                        or ""
                    )
                    expected_external_id = account_external_ids.get(str(account_identifier))
                    expected_role_arn = account_role_arns.get(str(account_identifier))
                    for principal in sorted(set(principals)):
                        verified, has_external_id = cls._verified_onboarding_trust(
                            node, principal, scanner_principal_arn, expected_external_id,
                            expected_role_arn,
                        )
                        label = "Any AWS account" if principal == "*" else principal
                        ext = g._add_node(Node(
                            f"external:{principal}", "external", label,
                            properties={"wildcard": principal == "*", "principals": [principal]},
                        ))
                        g._add_edge(
                            ext.id, a.resource_id, "CAN_ASSUME",
                            {
                                "wildcard": principal == "*",
                                "verified_onboarding": verified,
                                "external_id_protected": has_external_id,
                            },
                        )

        # Derive policy-backed identity relationships after every node exists.
        # These edges are explicit-Allow only; the readiness response states the
        # IAM semantics not yet evaluated so the UI never presents false certainty.
        identities = g.nodes_of_kind("role") + g.nodes_of_kind("user")
        roles = g.nodes_of_kind("role")
        buckets = g.nodes_of_kind("bucket")
        for principal in identities:
            props = principal.properties
            # Hoisted out of the per-target loops: these are properties of the
            # principal, not of the resource, but were re-read per bucket and
            # per role — identities × resources times over.
            boundary_state = str(props.get("permissions_boundary_state") or "not_configured")
            boundary_grants = props.get("permissions_boundary_grants") or []
            policy_grants = props.get("policy_grants") or []
            authorization_scope = props.get("authorization_scope")
            access_complete = bool(props.get("effective_access_complete"))
            grants = [str(r) for r in props.get("s3_read_resources") or []]
            if props.get("has_admin"):
                grants.append("*")
            grant_index = cls._grant_index(grants)
            for bucket in buckets:
                matched = grant_index.matches(bucket.id)
                # No matching grant means no edge regardless of what the boundary
                # or identity policy says, and both of those are the expensive
                # checks. Short-circuit before paying for them.
                if not matched:
                    continue
                boundary_permits = boundary_allows(
                    boundary_state, boundary_grants, S3_READ_ACTIONS, bucket.id,
                )
                identity_permits = identity_allows(
                    policy_grants, S3_READ_ACTIONS, bucket.id,
                ) if policy_grants else True
                if identity_permits and boundary_permits:
                    g._add_edge(
                        principal.id, bucket.id, "CAN_ACCESS",
                        {
                            "evidence": "explicit IAM Allow within permissions boundary",
                            "resources": sorted(set(matched)),
                            "authorization_scope": authorization_scope,
                            "effective_access_complete": access_complete,
                        },
                    )

            assume_index = cls._grant_index(
                [str(r) for r in props.get("assume_role_resources") or []]
            )
            for target in roles:
                if target.id == principal.id:
                    continue
                matched = assume_index.matches(target.id)
                if not matched:
                    continue
                boundary_permits = boundary_allows(
                    boundary_state, boundary_grants, ASSUME_ROLE_ACTIONS, target.id,
                )
                identity_permits = identity_allows(
                    policy_grants, ASSUME_ROLE_ACTIONS, target.id,
                ) if policy_grants else True
                if (
                    identity_permits
                    and boundary_permits
                    and cls._trusts_principal(target, principal.id)
                ):
                    g._add_edge(
                        principal.id, target.id, "CAN_ASSUME",
                        {
                            "evidence": (
                                "identity policy + permissions boundary + role trust"
                            ),
                            "resources": sorted(set(matched)),
                            "authorization_scope": authorization_scope,
                            "effective_access_complete": access_complete,
                        },
                    )

        # Second-order CIEM edges: service-mediated paths such as modifying an
        # existing Lambda or creating a new workload with iam:PassRole.
        ciem_relationships = derive_ciem_relationships(all_assets)
        for relationship in ciem_relationships:
            if (
                relationship.source_id in g.nodes
                and relationship.target_id in g.nodes
            ):
                g._add_edge(
                    relationship.source_id,
                    relationship.target_id,
                    relationship.relationship_type,
                    relationship.properties,
                )

        # Layered verdict. Network exposure alone is not risk: it matters when a
        # principal also has a permission path in and the resource holds data
        # worth taking. Each layer keeps its own evidence, and the combination
        # rests only on layers actually proven — so an asset we could not fully
        # evaluate reads as "unverified", never as safe.
        has_identity_inventory = any(
            a.asset_type in {"aws.iam.role", "aws.iam.user"} for a in all_assets
        )
        # Internet-facing front doors, indexed once: a Lambda with no function
        # URL can still be fully exposed through a public API Gateway.
        entrypoints = public_entrypoints_for(all_assets)
        for a in assets:
            node = g.nodes[a.resource_id]
            network = network_verdicts.get(a.resource_id)
            if network is None:
                network = assess_network_layer(
                    a, topology=network_topology, public_entrypoints=entrypoints
                )
            layered = assess_layers(
                a,
                network=network,
                relationships=ciem_relationships,
                data_labels=data_labels or {},
                has_identity_inventory=has_identity_inventory,
            )
            node.properties["layered_reachability"] = layered.as_dict()

            # A name such as "customer-data-prod" is useful search metadata,
            # not proof of sensitive content. Carry the DSPM verdict onto the
            # graph node so issue detectors can promote severity only from a
            # real classification. Unclassified remains explicit rather than
            # silently falling back to a name heuristic.
            label_key = store_key(a.resource_id)
            node.properties["data_sensitivity_label"] = str(
                (data_labels or {}).get(label_key) or "UNCLASSIFIED"
            ).upper()

        return g


if __name__ == "__main__":  # pragma: no cover — equivalence check for _GrantIndex
    # _GrantIndex replaced a per-pair fnmatchcase call. The only thing that
    # matters is that it never disagrees with the function it replaced, so
    # assert exactly that over the grant shapes real IAM policies produce.
    _GRANTS = [
        "*", "arn:aws:s3:::data-prod", "arn:aws:s3:::data-*",
        "arn:aws:s3:::data-prod/*", "arn:aws:s3:::logs-*/year=*/*",
        "arn:aws:iam::123456789012:role/app", "arn:aws:iam::123456789012:role/app-*",
        "arn:aws:iam::*:role/deploy", "arn:aws:s3:::a?c", "arn:aws:s3:::set[0-9]",
    ]
    _IDS = [
        "arn:aws:s3:::data-prod", "arn:aws:s3:::data-staging", "arn:aws:s3:::logs-prod",
        "arn:aws:s3:::abc", "arn:aws:s3:::set7", "arn:aws:s3:::other",
        "arn:aws:iam::123456789012:role/app", "arn:aws:iam::123456789012:role/app-two",
        "arn:aws:iam::999999999999:role/deploy",
    ]
    for _grant in _GRANTS:
        _index = _GrantIndex([_grant])
        for _id in _IDS:
            _want = AssetGraph._resource_matches(_id, _grant)
            _got = bool(_index.matches(_id))
            assert _want == _got, f"{_grant!r} vs {_id!r}: fnmatch={_want} index={_got}"

    # And with every grant loaded at once, the set of matching grants must be
    # identical too — not merely whether *something* matched.
    _index = _GrantIndex(_GRANTS)
    for _id in _IDS:
        _want = [g for g in _GRANTS if AssetGraph._resource_matches(_id, g)]
        _got = _index.matches(_id)
        assert sorted(_got) == sorted(_want), f"{_id}: want {_want} got {_got}"
        assert len(_got) == len(set(_got)), f"{_id}: duplicate grants {_got}"

    assert not _GrantIndex([])
    print("graph._GrantIndex: equivalent to _resource_matches on all sampled inputs")
