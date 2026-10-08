"""Phase 3/4 issue engine: correlated attack paths over the asset graph.

An *issue* is distinct from a *finding*: a finding is one rule firing on one
asset; an issue is a chain of individually-minor conditions that combine into
a walkable attack path. The engine traverses ``AssetGraph`` (built from the
persisted spine) and scores each path with the contextual risk model:

    risk_score = base × exposure × blast_radius × freshness   (0–100)

  base          inherent severity of the combination (0–10)
  exposure      how reachable the entry point is (internet 1.0, external
                trust 0.85, internal 0.6)
  blast_radius  what falls if the path is walked (admin 1.0, data 0.85,
                single service 0.6)
  freshness     confidence decay — paths confirmed by a recent scan score
                higher than ones resting on week-old data

Pure and offline like the rules engine: no cloud calls, deterministic,
fixture-testable.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from odineyes.inventory.graph import INTERNET_ID, AssetGraph, Node

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Names remain a weak ranking hint for unclassified stores. They never promote
# an issue to critical; only a DSPM classification can do that.
_SENSITIVE_NAME = re.compile(
    r"(data|backup|log|secret|cred|customer|cust|prod|pii|financ|private|confidential)", re.I,
)

# Privesc primitives that let a principal grant itself more access.
_PRIVESC_ACTIONS = {
    "*", "iam:*", "iam:CreatePolicyVersion", "iam:AttachRolePolicy",
    "iam:PutRolePolicy", "iam:AttachUserPolicy", "iam:PutUserPolicy",
    "iam:UpdateAssumeRolePolicy", "iam:CreateAccessKey",
    "iam:SetDefaultPolicyVersion",
}

# CI/CD identity providers that federate an external pipeline into the account.
# A role trusting one of these is assumable by GitHub Actions / GitLab / etc.
# OIDC issuers that let an external build system assume a role in this account.
# Terraform Cloud is on the list because a workspace there routinely holds the
# credentials that build the account itself, which makes it a higher-value
# pivot than any of the source-control providers, not a lesser one. IAM Roles
# Anywhere is the same shape without a hosted issuer: a certificate outside AWS
# that exchanges for real credentials.
_CICD_OIDC = re.compile(
    r"("
    r"token\.actions\.githubusercontent\.com"      # GitHub Actions
    r"|gitlab\.com"                                 # GitLab CI
    r"|bitbucket\.org"                              # Bitbucket Pipelines
    r"|oidc\.circleci\.com"                         # CircleCI
    r"|app\.terraform\.io"                          # Terraform Cloud
    r"|\.hashicorp\.cloud"                          # HCP
    r"|rolesanywhere\.amazonaws\.com"               # IAM Roles Anywhere
    r"|vstoken\.dev\.azure\.com"                    # Azure DevOps
    r"|accounts\.google\.com"                       # Cloud Build / GCP workload identity
    r"|oidc\.eks\.[a-z0-9-]+\.amazonaws\.com"       # IRSA — a pod is an external caller too
    r")",
    re.I,
)

# issue_type → compliance controls the path evidences (aligned with rules.COMPLIANCE).
COMPLIANCE: dict[str, dict[str, list[str]]] = {
    "PUBLIC_COMPUTE_TO_ADMIN": {
        "CIS": ["1.16", "5.2"], "SOC2": ["CC6.1"], "NIST": ["AC-3", "AC-6"],
        "PCI-DSS": ["7.1"], "ISO27001": ["A.5.15", "A.8.3"]},
    "PUBLIC_COMPUTE_TO_DATA": {
        "CIS": ["5.2"], "SOC2": ["CC6.1", "CC6.7"], "NIST": ["AC-3", "SC-7"],
        "PCI-DSS": ["1.3.1", "7.1"], "ISO27001": ["A.8.3", "A.8.20"]},
    "PUBLIC_S3_EXPOSURE": {
        "CIS": ["2.1.1", "2.1.5"], "SOC2": ["CC6.1", "CC6.7"],
        "NIST": ["AC-3", "SC-28"], "PCI-DSS": ["3.5"],
        "HIPAA": ["164.312(a)(1)"], "ISO27001": ["A.8.3", "A.8.24"], "GDPR": ["Art.32"]},
    "PUBLIC_DATABASE_PATH": {
        "CIS": ["5.2"], "SOC2": ["CC6.1", "CC6.7"], "NIST": ["AC-3", "SC-7", "SC-28"],
        "PCI-DSS": ["1.3.1"], "HIPAA": ["164.312(a)(1)"], "ISO27001": ["A.8.20"]},
    "CROSS_ACCOUNT_LATERAL": {
        "CIS": ["1.16"], "SOC2": ["CC6.1"], "NIST": ["AC-3", "AC-6"],
        "PCI-DSS": ["7.1"], "ISO27001": ["A.5.15"]},
    "IAM_PRIVILEGE_ESCALATION": {
        "CIS": ["1.16"], "SOC2": ["CC6.1"], "NIST": ["AC-6", "AC-2"],
        "PCI-DSS": ["7.1"], "ISO27001": ["A.5.15", "A.5.16"]},
    "SECOND_ORDER_ROLE_ESCALATION": {
        "CIS": ["1.16"], "SOC2": ["CC6.1"], "NIST": ["AC-6", "AC-2"],
        "PCI-DSS": ["7.1"], "ISO27001": ["A.5.15", "A.5.16"]},
    "OVERPRIVILEGED_CICD_ROLE": {
        "CIS": ["1.16"], "SOC2": ["CC6.1", "CC8.1"], "NIST": ["AC-6", "AC-2"],
        "PCI-DSS": ["7.1"], "ISO27001": ["A.5.15", "A.8.2"]},
}


@dataclass
class Issue:
    issue_type: str
    title: str
    severity: str                 # critical | high | medium | low
    risk_score: float             # 0-100
    resource_id: str              # entry-point asset
    why: str
    remediation: str
    path: list[dict[str, str]] = field(default_factory=list)   # ordered hops
    compliance: dict[str, list[str]] = field(default_factory=dict)
    related: list[str] = field(default_factory=list)
    # Verifiable evidence trail: each item {source, observation, effect} reads like
    # an audit-log line — the API query, the value it returned, and how it moves
    # the score. ``scoring`` shows those factors adding up to the number + severity.
    evidence: list[dict[str, str]] = field(default_factory=list)
    scoring: str = ""
    # Route confidence (0–1): how completely the path is backed by freshly
    # confirmed assets — distinct from risk (how bad it is if real). A stale or
    # partially-evidenced route scores lower so an operator can sort certainty
    # from severity. ponytail: today freshness × completeness; the upgrade path is
    # per-edge typed weights (observed config > inferred reachability) and a bump
    # to 1.0 when runtime corroborates the path (actively_exploited).
    confidence: float = 1.0
    # confirmed: complete, current asset-backed path
    # stale: complete path whose entry observation is older than one day
    # partial: one or more routed hops lack canonical asset evidence
    evidence_status: str = "confirmed"

    @property
    def path_hash(self) -> str:
        raw = self.issue_type + "|" + "|".join(h["id"] for h in self.path)
        return hashlib.sha1(raw.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_type": self.issue_type, "title": self.title,
            "severity": self.severity, "risk_score": self.risk_score,
            "resource_id": self.resource_id, "why": self.why,
            "remediation": self.remediation, "path": self.path,
            "compliance": self.compliance, "related": self.related,
            "evidence": self.evidence, "scoring": self.scoring,
            "confidence": self.confidence,
            "evidence_status": self.evidence_status,
        }


def _freshness(node: Node) -> float:
    """Confidence decay by scan recency of the entry asset (1.0 → 0.85)."""
    scanned = getattr(node.asset, "last_scanned_at", None)
    if not isinstance(scanned, datetime):
        return 1.0
    if scanned.tzinfo is None:
        scanned = scanned.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - scanned).total_seconds() / 86400
    if age_days <= 1:
        return 1.0
    if age_days <= 7:
        return 0.95
    return 0.85


def _risk(base: float, exposure: float, blast: float, freshness: float,
          sensitivity: float = 1.0) -> float:
    return round(min(base * 10 * exposure * blast * freshness * sensitivity, 100.0), 1)


def _severity_for(score: float) -> str:
    """Severity label follows the computed risk score — the badge never
    contradicts the number (a 51/100 is not 'critical')."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _data_sensitivity(node: Node | None) -> float:
    """Data-impact factor backed by DSPM when available.

    Names are retained only as a bounded ranking hint for unclassified data.
    They cannot reach the full weight reserved for a confirmed classification.
    Exposure and encryption are scored separately by detectors, so neither is
    allowed to masquerade as proof of sensitive contents here.
    """
    if node is None:
        return 1.0
    label = _data_label(node)
    classified = {
        "CRITICAL": 1.0,
        "HIGH": 0.95,
        "MEDIUM": 0.85,
        "LOW": 0.70,
        "NONE": 0.60,
    }
    if label in classified:
        return classified[label]
    return 0.75 if _SENSITIVE_NAME.search(node.name or "") else 0.65


def _data_label(node: Node | None) -> str:
    if node is None:
        return "UNCLASSIFIED"
    return str(node.properties.get("data_sensitivity_label") or "UNCLASSIFIED").upper()


def _classified_sensitive(node: Node | None) -> bool:
    return _data_label(node) in {"CRITICAL", "HIGH", "MEDIUM"}


def _data_evidence(node: Node | None) -> dict[str, str]:
    label = _data_label(node)
    if label == "UNCLASSIFIED":
        return _ev(
            "dspm:classification",
            "sensitivity = UNCLASSIFIED",
            "name used only as a bounded ranking hint; no critical promotion",
        )
    return _ev(
        "dspm:classification",
        f"sensitivity = {label}",
        "confirmed data-impact input",
    )


# Environment tag → business-context multiplier. A prod asset anywhere in the
# path raises its rank (a critical on production outranks the same issue on a
# sandbox); a wholly non-prod path is de-prioritised. Reads the standard
# Environment/env/tier tag keys, case-insensitively.
_PROD_ENV = re.compile(r"^(prod|production|prd|live)$", re.I)
_NONPROD_ENV = re.compile(r"^(dev|development|test|testing|qa|stage|staging|sandbox|sbx|demo)$", re.I)
_ENV_TAG_KEYS = ("environment", "env", "stage", "tier")


def _env_weight(hops: list[Node]) -> float:
    envs: list[str] = []
    for n in hops:
        tags = getattr(n.asset, "tags", None) or {}
        for k, v in tags.items():
            if k.lower() in _ENV_TAG_KEYS and v is not None:
                envs.append(str(v))
    if any(_PROD_ENV.match(e) for e in envs):
        return 1.2
    if envs and all(_NONPROD_ENV.match(e) for e in envs):
        return 0.85
    return 1.0


def _confidence(hops: list[Node], entry: Node) -> float:
    """How completely the route is evidenced (0–1): freshness of the entry asset
    × completeness. Completeness is the fraction of routed hops backed by a real
    asset rather than an inferred gap — internet/external pseudo-nodes are
    definitional (not inferred) so they don't count against it. Config-derived
    paths (every detector here) are fully asset-backed → completeness 1.0, so
    confidence tracks freshness today; the factor drops below 1 only once a
    detector emits a hop with no confirming asset (an inferred edge)."""
    routed = [h for h in hops if h.kind not in {"internet", "external"}]
    if not routed:
        return round(_freshness(entry), 2)
    backed = sum(1 for h in routed if h.asset is not None)
    completeness = backed / len(routed)
    return round(_freshness(entry) * completeness, 2)


def _evidence_status(hops: list[Node], entry: Node) -> str:
    routed = [hop for hop in hops if hop.kind not in {"internet", "external"}]
    if any(hop.asset is None for hop in routed):
        return "partial"
    if _freshness(entry) < 1.0:
        return "stale"
    return "confirmed"


def _ev(source: str, observation: str, effect: str) -> dict[str, str]:
    """One verifiable evidence record — the query/source that produced it, the
    observed value (log-like), and how it moves the score."""
    return {"source": source, "observation": observation, "effect": effect}


def _issue(issue_type: str, title: str, severity: str, risk: float,
           hops: list[Node], why: str, remediation: str,
           related: list[str] | None = None,
           evidence: list[dict[str, str]] | None = None,
           scoring: str = "") -> Issue:
    # Entry point = first hop backed by a real asset (skip internet/external).
    entry = next((h for h in hops if h.asset is not None), hops[0])
    # Business-context: rescale by the path's Environment tags. Prod may only
    # raise the badge (never soften a detector's intended severity); non-prod
    # lowers the score for ranking but keeps the label.
    env = _env_weight(hops)
    if env != 1.0:
        risk = round(min(risk * env, 100.0), 1)
        if env > 1.0:
            bumped = _severity_for(risk)
            if _SEVERITY_RANK.get(bumped, 9) < _SEVERITY_RANK.get(severity, 9):
                severity = bumped
    confidence = _confidence(hops, entry)
    return Issue(
        issue_type=issue_type, title=title, severity=severity, risk_score=risk,
        resource_id=entry.id, why=why, remediation=remediation,
        path=[h.hop() for h in hops],
        compliance=COMPLIANCE.get(issue_type, {}), related=related or [],
        evidence=evidence or [], scoring=scoring,
        confidence=confidence,
        evidence_status=_evidence_status(hops, entry),
    )


# ── detectors ──────────────────────────────────────────────────

def _public_compute_to_admin(g: AssetGraph) -> list[Issue]:
    out = []
    internet = g.node(INTERNET_ID)
    for e in g.out_edges(INTERNET_ID, "EXPOSED_TO"):
        inst = g.node(e.dst)
        if not inst or inst.kind != "compute":
            continue
        ports = e.properties.get("port_labels", [])
        remote = any(p in ports for p in ("SSH", "RDP", "ALL"))
        for ae in g.out_edges(inst.id, "CAN_ASSUME"):
            role = g.node(ae.dst)
            if not role or not role.properties.get("has_admin"):
                continue
            risk = _risk(9.5 + (0.5 if remote else 0), 1.0, 1.0, _freshness(inst))
            out.append(_issue(
                "PUBLIC_COMPUTE_TO_ADMIN",
                "Internet-exposed compute with admin credentials", "critical", risk,
                [internet, inst, role],
                why=(f"{inst.name} is reachable from the internet"
                     f"{' on ' + ', '.join(ports) if ports else ''} and carries IAM role "
                     f"'{role.name}' with effective admin "
                     f"({role.properties.get('admin_reason') or 'admin policy'}). "
                     f"Compromise of the workload is full account takeover."),
                remediation=("Remove the public IP or restrict ingress, and replace the "
                             "attached role with a least-privilege one."),
                related=[role.id],
            ))
    return out


def _public_compute_to_data(g: AssetGraph) -> list[Issue]:
    out = []
    internet = g.node(INTERNET_ID)
    for e in g.out_edges(INTERNET_ID, "EXPOSED_TO"):
        inst = g.node(e.dst)
        if not inst or inst.kind != "compute":
            continue
        for ae in g.out_edges(inst.id, "CAN_ASSUME"):
            role = g.node(ae.dst)
            if not role:
                continue

            # Follow bounded role chaining before reaching data. This closes the
            # common blind spot where the workload role cannot read S3 directly
            # but can assume a second role that can. Keep one shortest evidenced
            # path per bucket to avoid cycle/path explosion.
            queue: list[tuple[Node, list[Node]]] = [(role, [role])]
            # `visited` is shared across every branch of this search, so each
            # role is expanded once and the path recorded for a bucket is the
            # shortest one found, not the only one that exists. That is the
            # right trade for risk scoring — a shorter chain is never less
            # severe — but the access_path shown in the UI is therefore *a*
            # route, not an exhaustive list. Remediating it can leave a longer
            # chain to the same bucket intact, which the next scan re-reports.
            visited = {role.id}
            data_paths: list[tuple[Node, list[Node]]] = []
            while queue:
                current, role_path = queue.pop(0)
                for be in g.out_edges(current.id, "CAN_ACCESS"):
                    bucket = g.node(be.dst)
                    if bucket and bucket.kind == "bucket":
                        data_paths.append((bucket, role_path + [bucket]))
                if len(role_path) >= 4:
                    continue
                for role_edge in g.out_edges(current.id, "CAN_ASSUME"):
                    next_role = g.node(role_edge.dst)
                    if next_role and next_role.kind == "role" and next_role.id not in visited:
                        visited.add(next_role.id)
                        queue.append((next_role, role_path + [next_role]))

            if not data_paths:
                continue
            by_bucket: dict[str, tuple[Node, list[Node]]] = {}
            for bucket, path in data_paths:
                if bucket.id not in by_bucket or len(path) < len(by_bucket[bucket.id][1]):
                    by_bucket[bucket.id] = (bucket, path)
            reachable = list(by_bucket.values())
            buckets = [bucket for bucket, _ in reachable]
            sensitive = [
                (bucket, path) for bucket, path in reachable
                if _classified_sensitive(bucket)
            ]
            showcase, access_path = sensitive[0] if sensitive else reachable[0]
            risk = _risk(8.5 if sensitive else 7.0, 1.0, 0.85, _freshness(inst),
                         sensitivity=_data_sensitivity(showcase))
            role_names = " -> ".join(node.name for node in access_path[:-1])
            out.append(_issue(
                "PUBLIC_COMPUTE_TO_DATA",
                "Internet-exposed compute with a path to S3 data",
                "critical" if sensitive else "high", risk,
                [internet, inst] + access_path,
                why=(f"{inst.name} (internet-exposed) can follow IAM path '{role_names}', which "
                     f"reaches {len(buckets)} S3 bucket(s)"
                     f"{', including DSPM-classified ' + _data_label(showcase) + ' data in ' + repr(showcase.name) if sensitive else ''}. "
                     f"A foothold on the host reaches the data."),
                remediation=("Remove the unnecessary S3 or sts:AssumeRole grant, tighten the "
                             "target role trust policy, and move the host off the public internet."),
                related=[b.id for b in buckets],
                evidence=[_data_evidence(showcase)],
            ))
    return out


def _public_bucket_exposure(g: AssetGraph) -> list[Issue]:
    out = []
    internet = g.node(INTERNET_ID)
    for e in g.out_edges(INTERNET_ID, "EXPOSED_TO"):
        bucket = g.node(e.dst)
        if not bucket or bucket.kind != "bucket":
            continue
        sensitive = _classified_sensitive(bucket)
        unencrypted = getattr(bucket.asset, "encryption_enabled", None) is False
        base = (8.5 if sensitive else 6.5) + (0.5 if unencrypted else 0)
        risk = _risk(base, 1.0, 0.6, _freshness(bucket), sensitivity=_data_sensitivity(bucket))
        out.append(_issue(
            "PUBLIC_S3_EXPOSURE", "Publicly accessible S3 bucket",
            "critical" if sensitive else "high", risk,
            [internet, bucket],
            why=(f"Bucket '{bucket.name}' is publicly accessible"
                 f"{', unencrypted' if unencrypted else ''}"
                 f"{', and DSPM classifies its data as ' + _data_label(bucket) if sensitive else ''}. "
                 f"Anyone on the internet may read its objects."),
            remediation="Enable Block Public Access and remove public policy/ACL grants.",
            evidence=[_data_evidence(bucket)],
        ))
    return out


def _public_database(g: AssetGraph) -> list[Issue]:
    out = []
    internet = g.node(INTERNET_ID)
    for e in g.out_edges(INTERNET_ID, "EXPOSED_TO"):
        db = g.node(e.dst)
        if not db or db.kind != "database":
            continue
        engine = db.properties.get("engine") or "unknown engine"
        iam_auth = bool(db.properties.get("iam_auth_enabled"))
        unencrypted = getattr(db.asset, "encryption_enabled", None) is False

        # Graph creates this edge only after the reachability evaluator has
        # verified SG ingress, default route, attached IGW and both NACL
        # directions. Configuration-only and unverified databases never arrive
        # here, so they cannot pollute attack paths.
        reachability = e.properties.get("reachability") or {}
        evidence = list(reachability.get("evidence") or [])
        evidence.append(_ev("rds:DescribeDBInstances", f"StorageEncrypted = {str(not unencrypted).lower()}",
                            "data readable if storage/snapshot leaks → +1.0 base"
                            if unencrypted else "encrypted at rest"))
        evidence.append(_ev("rds:DescribeDBInstances", f"IAMDatabaseAuthenticationEnabled = {str(iam_auth).lower()}",
                            "connection still requires valid credentials — no anonymous access"))
        evidence.append(_data_evidence(db))
        exposure = 1.0
        reach = "is verified reachable from 0.0.0.0/0 on the database port"

        # A database is credential-gated — unlike a public S3 bucket there is no
        # anonymous read. Network exposure raises attack surface (credential
        # brute-force, pre-auth engine CVEs, snapshot/credential leak); it is not,
        # by itself, account/data takeover. So base is moderate and severity
        # follows the score. ponytail: escalate base when we collect proof the
        # auth barrier is weak (IAM-auth disabled + no password rotation, default
        # credentials, known exploitable engine CVE) — the rungs that reach 'critical'.
        base = 6.0 + (1.0 if unencrypted else 0.0)
        fresh, sens = _freshness(db), _data_sensitivity(db)
        risk = _risk(base, exposure, 0.85, fresh, sensitivity=sens)
        severity = _severity_for(risk)
        scoring = (f"base {base:.1f}{' (+1.0 unencrypted)' if unencrypted else ''} "
                   f"× exposure {exposure:.2f} × blast 0.85 "
                   f"× freshness {fresh:.2f} × data-sensitivity {sens:.2f} "
                   f"= {risk:.1f}/100 → {severity.upper()}")

        out.append(_issue(
            "PUBLIC_DATABASE_PATH", "Verified internet-reachable database", severity, risk,
            [internet, db],
            why=(f"Database '{db.name}' ({engine}) {reach}"
                 f"{', and is unencrypted at rest' if unencrypted else ''}. "
                 f"Access still requires valid credentials, so the exposure raises "
                 f"attack surface — credential brute-force, pre-auth engine CVEs, "
                 f"snapshot/backup leakage — rather than granting direct access."),
            remediation=("Set PubliclyAccessible=false and move the instance to private "
                         "subnets; restrict the security group to known CIDRs; enable "
                         "encryption at rest and IAM database authentication."),
            evidence=evidence, scoring=scoring,
        ))
    return out


def _cross_account_lateral(g: AssetGraph) -> list[Issue]:
    out = []
    for ext in g.nodes_of_kind("external"):
        for e in g.out_edges(ext.id, "CAN_ASSUME"):
            # Odineyes onboarding intentionally creates a cross-account trust.
            # Suppress it only after the graph verifies the exact scanner ARN
            # and this account's stored ExternalId; never blanket-suppress
            # external IAM roles.
            if e.properties.get("verified_onboarding"):
                continue
            role = g.node(e.dst)
            if not role or role.kind != "role":
                continue
            wildcard = bool(e.properties.get("wildcard"))
            admin = bool(role.properties.get("has_admin"))
            buckets = [g.node(be.dst) for be in g.out_edges(role.id, "CAN_ACCESS")]
            buckets = [b for b in buckets if b]
            risk = _risk(
                9.0 if (admin or wildcard) else 7.0,
                1.0 if wildcard else 0.85,
                1.0 if admin else 0.7,
                _freshness(role),
            )
            tail = " The role has effective admin." if admin else ""
            if buckets:
                tail += f" It can read {len(buckets)} S3 bucket(s)."
            remediation = (
                "Verify that this external principal and its ExternalId are approved for "
                "this role; restrict the trust to the exact required principal ARN."
                if e.properties.get("external_id_protected")
                else "Scope the trust policy to known principal ARNs and add an ExternalId condition."
            )
            out.append(_issue(
                "CROSS_ACCOUNT_LATERAL", "IAM role assumable from outside the account",
                "critical" if (admin and wildcard) else "high", risk,
                [ext, role] + (buckets[:1] if buckets else []),
                why=(f"Role '{role.name}' trusts "
                     f"{'any AWS principal (wildcard)' if wildcard else ext.name}. "
                     f"A principal there can assume it.{tail}"),
                remediation=remediation,
                related=[b.id for b in buckets],
            ))
    return out


def _iam_privilege_escalation(g: AssetGraph) -> list[Issue]:
    out = []
    for role in g.nodes_of_kind("role"):
        if role.properties.get("has_admin"):
            continue  # admin already covered by stronger paths
        dangerous = sorted(set(role.properties.get("privesc_actions") or []) & _PRIVESC_ACTIONS)
        if not dangerous:
            continue
        externally_reachable = bool(
            role.properties.get("trust_external") or role.properties.get("publicly_assumable")
        )
        risk = _risk(7.5, 1.0 if externally_reachable else 0.6, 1.0, _freshness(role))
        out.append(_issue(
            "IAM_PRIVILEGE_ESCALATION", "IAM role can escalate to admin", "high", risk,
            [role],
            why=(f"Role '{role.name}' is granted {', '.join(dangerous)}. A principal "
                 f"using this role can grant itself further permissions and reach admin."),
            remediation="Remove the escalation primitives or constrain them with permission boundaries.",
        ))
    return out


def _second_order_role_escalation(g: AssetGraph) -> list[Issue]:
    """Service-mediated role access derived by the CIEM relationship engine."""
    out: list[Issue] = []

    # Existing Lambda takeover: principal -> mutable function -> execution role.
    for principal in g.nodes_of_kind("role") + g.nodes_of_kind("user"):
        for edge in g.out_edges(principal.id, "CAN_MODIFY_AND_INVOKE"):
            workload = g.node(edge.dst)
            if not workload:
                continue
            for role_edge in g.out_edges(workload.id, "CAN_ASSUME"):
                target = g.node(role_edge.dst)
                if not target or target.kind != "role":
                    continue
                privileged = bool(
                    target.properties.get("has_admin")
                    or target.properties.get("effective_privesc_actions")
                )
                if not privileged:
                    continue
                external = bool(
                    principal.properties.get("trust_external")
                    or principal.properties.get("publicly_assumable")
                )
                risk = _risk(
                    9.0 if target.properties.get("has_admin") else 7.5,
                    1.0 if external else 0.85,
                    1.0,
                    _freshness(principal),
                )
                issue = _issue(
                    "SECOND_ORDER_ROLE_ESCALATION",
                    "Principal can reach a privileged role through Lambda",
                    _severity_for(risk),
                    risk,
                    [principal, workload, target],
                    why=(
                        f"{principal.name} can replace and invoke code in Lambda "
                        f"'{workload.name}'. The function executes as role '{target.name}', "
                        "so the principal can exercise that role without sts:AssumeRole."
                    ),
                    remediation=(
                        "Remove either lambda:UpdateFunctionCode or lambda:InvokeFunction, "
                        "restrict both to approved deployment identities, and reduce the "
                        "function execution role."
                    ),
                    related=[target.id],
                    evidence=[
                        _ev(
                            "normalized IAM policies + Lambda configuration",
                            str(edge.properties.get("evidence") or ""),
                            "creates a service-mediated path to the execution role",
                        )
                    ],
                )
                if not edge.properties.get("effective_access_complete"):
                    issue.confidence = min(issue.confidence, 0.8)
                out.append(issue)

    # New service workload + PassRole. Aggregate services for the same source
    # and target so one remediation decision does not become five alerts.
    grouped: dict[tuple[str, str], list[Any]] = {}
    for principal in g.nodes_of_kind("role") + g.nodes_of_kind("user"):
        for edge in g.out_edges(principal.id, "CAN_IMPERSONATE_VIA_SERVICE"):
            grouped.setdefault((principal.id, edge.dst), []).append(edge)

    for (principal_id, target_id), edges in grouped.items():
        principal, target = g.node(principal_id), g.node(target_id)
        if not principal or not target or target.kind != "role":
            continue
        privileged = bool(
            target.properties.get("has_admin")
            or target.properties.get("effective_privesc_actions")
        )
        if not privileged:
            continue
        services = sorted({
            str(edge.properties.get("via_service") or "AWS service")
            for edge in edges
        })
        external = bool(
            principal.properties.get("trust_external")
            or principal.properties.get("publicly_assumable")
        )
        risk = _risk(
            9.0 if target.properties.get("has_admin") else 7.5,
            1.0 if external else 0.85,
            1.0,
            _freshness(principal),
        )
        issue = _issue(
            "SECOND_ORDER_ROLE_ESCALATION",
            "Principal can PassRole into attacker-controlled service execution",
            _severity_for(risk),
            risk,
            [principal, target],
            why=(
                f"{principal.name} can create and execute attacker-controlled "
                f"{', '.join(services)} work while passing privileged role "
                f"'{target.name}'. The service assumes the role on the principal's behalf."
            ),
            remediation=(
                "Restrict iam:PassRole to approved role paths with iam:PassedToService, "
                "remove unnecessary service creation/execution actions, and reduce the "
                "target role privileges."
            ),
            related=[target.id],
            evidence=[
                _ev(
                    "normalized IAM policies + role trust",
                    "; ".join(str(edge.properties.get("evidence") or "") for edge in edges),
                    "proves the correlated service actions, exact PassRole grant, and service trust",
                )
            ],
        )
        if not all(edge.properties.get("effective_access_complete") for edge in edges):
            issue.confidence = min(issue.confidence, 0.8)
        out.append(issue)

    return out


def _overprivileged_cicd_role(g: AssetGraph) -> list[Issue]:
    """A role federated to an external CI/CD provider (GitHub Actions, GitLab, …)
    that also holds admin or privilege-escalation grants. A leaked secret or a
    malicious pull-request workflow can assume it and pivot to account takeover —
    the OIDC trust means the attacker never needs a foothold inside the account."""
    out = []
    for role in g.nodes_of_kind("role"):
        federated = role.properties.get("trust_federated") or []
        providers = [str(f) for f in federated if _CICD_OIDC.search(str(f))]
        if not providers:
            continue
        admin = bool(role.properties.get("has_admin"))
        privesc = sorted(set(role.properties.get("privesc_actions") or []) & _PRIVESC_ACTIONS)
        if not (admin or privesc):
            continue  # federated but least-privilege — not an escalation path
        grant = "effective admin" if admin else ", ".join(privesc)
        provider = providers[0].rsplit("/", 1)[-1]
        risk = _risk(9.0 if admin else 7.5, 1.0, 1.0 if admin else 0.7, _freshness(role))
        out.append(_issue(
            "OVERPRIVILEGED_CICD_ROLE", "CI/CD OIDC role with excessive privileges",
            "critical" if admin else "high", risk,
            [role],
            why=(f"Role '{role.name}' is assumable by external CI/CD via OIDC provider "
                 f"'{provider}' and grants {grant}. A compromised or malicious pipeline run "
                 f"can assume it and {'take over the account' if admin else 'escalate toward admin'} "
                 f"with no prior foothold."),
            remediation=("Pin the OIDC trust with a sub/aud condition scoped to the exact "
                         "repository and branch, and replace admin/escalation grants with "
                         "least privilege."),
            evidence=[
                _ev("iam:GetRole",
                    f"AssumeRolePolicyDocument.Principal.Federated = {provider}",
                    "assumable by external CI/CD pipeline → exposure 1.00"),
                _ev("iam:ListAttachedRolePolicies", f"role grants {grant}",
                    "pipeline compromise → "
                    + ("account takeover" if admin else "privilege escalation")),
            ],
        ))
    return out


_DETECTORS = [
    _public_compute_to_admin,
    _public_compute_to_data,
    _public_bucket_exposure,
    _public_database,
    _cross_account_lateral,
    _iam_privilege_escalation,
    _second_order_role_escalation,
    _overprivileged_cicd_role,
]


# ── engine ─────────────────────────────────────────────────────

def analyze(
    assets: Iterable[Any],
    *,
    scanner_principal_arn: str | None = None,
    account_external_ids: dict[str, str] | None = None,
    account_role_arns: dict[str, str] | None = None,
    data_labels: dict[str, str] | None = None,
) -> list[Issue]:
    """Build the graph, run every detector, de-dupe and rank by risk.

    The optional onboarding context comes from the application's own account
    registry. It is intentionally not inferred from the target IAM role, so a
    role cannot suppress a real finding by merely copying an ExternalId.
    """
    g = AssetGraph.build(
        assets,
        scanner_principal_arn=scanner_principal_arn,
        account_external_ids=account_external_ids,
        account_role_arns=account_role_arns,
        data_labels=data_labels,
    )
    issues: list[Issue] = []
    for detector in _DETECTORS:
        issues.extend(detector(g))

    seen: set[str] = set()
    unique: list[Issue] = []
    for issue in sorted(
        issues,
        key=lambda i: (-i.risk_score, _SEVERITY_RANK.get(i.severity, 9), i.issue_type, i.resource_id),
    ):
        if issue.path_hash not in seen:
            seen.add(issue.path_hash)
            unique.append(issue)
    return unique
