"""Engine selection for the attack-path layer: Python, Go, or both in shadow.

The Go engine (``scanner-go/cmd/odineyes-graph``) took over the half of the work
profiling showed to be expensive: node and edge assembly, the identity
cross-products, traversal, scoring and dedup. Python keeps everything that
decides a *fact about one asset* — reachability, layered reachability and the
CIEM relationships — because those are the atomic-rule layer, and they arrive in
the snapshot already decided so Go never re-derives a security verdict.

Selection is ``ODINEYES_GRAPH_ENGINE``:

    auto     Go above ``ODINEYES_GRAPH_GO_MIN_ASSETS`` assets, Python below
    python   force the in-process engine
    shadow   run both, return Python's answer, log any divergence
    go       force Go, falling back to Python if the binary is missing or fails

``auto`` is the default because Go is not unconditionally faster. Measured on
this codebase, the subprocess spawn plus JSON round-trip is a fixed floor of
roughly 40ms, so Go wins by ~2.2x at 3,300 assets and *loses* by 4-8x on a small
account where Python finishes in milliseconds. The crossover sits near a
thousand assets.

The fallback is deliberate. A CSPM that returns no attack paths because a
subprocess failed looks exactly like a CSPM that found none, and that is the
one failure mode this codebase refuses to have.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from odineyes.inventory.issues import Issue, analyze as analyze_python

logger = logging.getLogger(__name__)

ENV_ENGINE = "ODINEYES_GRAPH_ENGINE"
ENV_BINARY = "ODINEYES_GO_GRAPH_PATH"
ENV_TIMEOUT = "ODINEYES_GO_GRAPH_TIMEOUT"
ENV_MIN_ASSETS = "ODINEYES_GRAPH_GO_MIN_ASSETS"

DEFAULT_BINARY = "odineyes-graph"
DEFAULT_TIMEOUT_SECONDS = 120
SNAPSHOT_VERSION = 2
# Measured crossover: below this the subprocess costs more than it saves.
DEFAULT_GO_MIN_ASSETS = 1000

# A snapshot is JSON on a pipe; cap the response so a runaway engine cannot
# exhaust the API container's memory before json.loads even runs.
_MAX_RESPONSE_BYTES = 256 * 1024 * 1024


def selected_engine() -> str:
    value = (os.environ.get(ENV_ENGINE) or "auto").strip().lower()
    return value if value in {"auto", "python", "go", "shadow"} else "auto"


def go_min_assets() -> int:
    try:
        return max(0, int(os.environ.get(ENV_MIN_ASSETS) or DEFAULT_GO_MIN_ASSETS))
    except ValueError:
        return DEFAULT_GO_MIN_ASSETS


# ── snapshot ───────────────────────────────────────────────────

def _iso(value: Any) -> str:
    if not isinstance(value, datetime):
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _jsonable(value: Any) -> Any:
    """Coerce a property value into something json.dumps accepts.

    Properties are an open bag filled by every normalizer, so an unexpected
    type here must degrade to its string form rather than raise — losing one
    property's fidelity is survivable, failing the whole scan is not.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if isinstance(value, datetime):
        return _iso(value)
    return str(value)


def build_snapshot(
    assets: Iterable[Any],
    *,
    scanner_principal_arn: Optional[str] = None,
    account_external_ids: Optional[dict[str, str]] = None,
    account_role_arns: Optional[dict[str, str]] = None,
    data_labels: Optional[dict[str, str]] = None,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Derive the per-asset facts, then package them for the Go engine.

    Everything computed here is exactly what ``AssetGraph.build`` computes
    before it starts assembling edges — same functions, same arguments — so the
    two engines reason from identical evidence and any divergence is in the
    graph logic rather than in the inputs.
    """
    from odineyes.inventory.ciem_relationships import derive_ciem_relationships
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

    all_assets = list(assets)
    graphed = [a for a in all_assets if a.asset_type in _KINDS]
    topology = build_network_topology(all_assets)
    entrypoints = public_entrypoints_for(all_assets)

    # Security groups resolve from the bare sg-id the relationship carries.
    by_short = {a.resource_id.rsplit("/", 1)[-1]: a for a in graphed}

    network_verdicts: dict[str, ReachabilityAssessment] = {}
    internet_reachability: dict[str, Any] = {}

    for asset in graphed:
        if asset.asset_type == "aws.ec2.instance":
            probe_ports = sorted({
                int(port)
                for rel in asset.relationships or []
                if rel.get("type") == "USES_SECURITY_GROUP"
                for sg in [by_short.get(str(rel.get("target_id")))]
                if sg is not None
                for port in ((sg.properties or {}).get("open_ports") or [])
            })
            assessments = [
                assess_ec2_internet_reachability(
                    asset, 22 if port == 0 else port, topology=topology
                )
                for port in probe_ports
            ]
            internet_reachability[asset.resource_id] = [a.as_dict() for a in assessments]
            # One instance, several probed ports: the network layer is reachable
            # if any single port proves a path.
            network_verdicts[asset.resource_id] = next(
                (x for x in assessments if x.status == "reachable"),
                assessments[0] if assessments else ReachabilityAssessment(
                    "unverified", missing=["no open ports to probe"]
                ),
            )
        elif _KINDS.get(asset.asset_type) == "database" and public_endpoint_configured(asset):
            assessment = assess_rds_internet_reachability(asset, topology=topology)
            internet_reachability[asset.resource_id] = assessment.as_dict()
            network_verdicts[asset.resource_id] = assessment

    ciem = derive_ciem_relationships(all_assets)
    has_identity_inventory = any(
        a.asset_type in {"aws.iam.role", "aws.iam.user"} for a in all_assets
    )

    layered: dict[str, Any] = {}
    for asset in graphed:
        network = network_verdicts.get(asset.resource_id)
        if network is None:
            network = assess_network_layer(
                asset, topology=topology, public_entrypoints=entrypoints
            )
        layered[asset.resource_id] = assess_layers(
            asset,
            network=network,
            relationships=ciem,
            data_labels=data_labels or {},
            has_identity_inventory=has_identity_inventory,
        ).as_dict()

    return {
        "version": SNAPSHOT_VERSION,
        "scanner_principal_arn": scanner_principal_arn or "",
        "account_external_ids": account_external_ids or {},
        "account_role_arns": account_role_arns or {},
        "now": _iso(now or datetime.now(timezone.utc)),
        "assets": [_asset_payload(a, data_labels=data_labels or {}) for a in graphed],
        "network_status": {
            asset_id: verdict.status for asset_id, verdict in network_verdicts.items()
        },
        "network_verdicts": {
            asset_id: verdict.as_dict() for asset_id, verdict in network_verdicts.items()
        },
        "internet_reachability": internet_reachability,
        "layered_reachability": layered,
        "ciem_relationships": [
            {
                "source_id": r.source_id,
                "target_id": r.target_id,
                "relationship_type": r.relationship_type,
                "properties": _jsonable(r.properties),
            }
            for r in ciem
        ],
    }


def _asset_payload(
    asset: Any,
    *,
    data_labels: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    properties = dict(asset.properties or {})
    from odineyes.inventory.finding_risk import store_key

    label_key = store_key(asset.resource_id)
    properties["data_sensitivity_label"] = str(
        (data_labels or {}).get(label_key) or "UNCLASSIFIED"
    ).upper()
    # trust_statements needs the raw-policy fallback the Python graph applies,
    # otherwise an inventory collected before the field existed would look like
    # a role with no trust evidence — and an unverifiable trust must never read
    # as a verified one.
    if not properties.get("trust_statements"):
        from odineyes.inventory.normalizers import extract_trust_statement_evidence

        raw = getattr(asset, "raw", None) or {}
        recovered = extract_trust_statement_evidence(raw.get("AssumeRolePolicyDocument"))
        if recovered:
            properties["trust_statements"] = recovered

    return {
        "resource_id": asset.resource_id,
        "asset_type": asset.asset_type,
        "name": getattr(asset, "name", None) or asset.resource_id,
        "region": getattr(asset, "region", None) or "",
        "account_identifier": str(getattr(asset, "account_identifier", "") or ""),
        "is_public": bool(getattr(asset, "is_public", False)),
        "encryption_enabled": getattr(asset, "encryption_enabled", None),
        "last_scanned_at": _iso(getattr(asset, "last_scanned_at", None)),
        "risk_score": float(getattr(asset, "risk_score", 0) or 0),
        "tags": {str(k): str(v) for k, v in (getattr(asset, "tags", None) or {}).items()
                 if v is not None},
        "properties": _jsonable(properties),
        "relationships": [
            {"type": str(r.get("type") or ""), "target_id": str(r.get("target_id") or "")}
            for r in (asset.relationships or [])
        ],
    }


# Imported late to avoid a cycle: graph imports reachability, which does not
# import this module, but issues imports graph.
from odineyes.inventory.graph import _KINDS  # noqa: E402


# ── go invocation ──────────────────────────────────────────────

def _resolve_binary() -> str:
    configured = (os.environ.get(ENV_BINARY) or "").strip()
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return str(path)
        raise RuntimeError(f"Go graph engine not found at '{path}'")
    resolved = shutil.which(DEFAULT_BINARY)
    if resolved:
        return resolved
    raise RuntimeError(
        f"Go graph engine '{DEFAULT_BINARY}' is not on PATH. "
        f"Build scanner-go/cmd/odineyes-graph or set {ENV_BINARY}."
    )


def _timeout_seconds() -> int:
    try:
        return max(1, int(os.environ.get(ENV_TIMEOUT) or DEFAULT_TIMEOUT_SECONDS))
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS


def run_go_engine(snapshot: dict[str, Any], *, issues_only: bool = True) -> dict[str, Any]:
    """Run the Go engine over a snapshot and return its parsed result.

    ``issues_only`` skips the serialized graph and path enumeration. Those are
    for the UI canvas, and on a large account the graph projection alone is tens
    of megabytes of JSON — encoding it for a caller that only wants issues costs
    more than the analysis itself.
    """
    executable = _resolve_binary()
    request = json.dumps(snapshot).encode("utf-8")
    argv = [executable]
    if issues_only:
        argv += ["--skip-graph", "--skip-paths"]

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(  # noqa: S603 — executable is operator-configured
            argv,
            stdin=subprocess.PIPE,
            stdout=stdout_file,
            stderr=stderr_file,
        )
        try:
            process.communicate(input=request, timeout=_timeout_seconds())
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise RuntimeError("Go graph engine timed out")

        stderr_file.seek(0)
        stderr = stderr_file.read(8192).decode("utf-8", "replace").strip()
        if process.returncode != 0:
            raise RuntimeError(f"Go graph engine exited {process.returncode}: {stderr}")

        stdout_file.seek(0, os.SEEK_END)
        if stdout_file.tell() > _MAX_RESPONSE_BYTES:
            raise RuntimeError("Go graph engine response exceeded the size limit")
        stdout_file.seek(0)
        payload = stdout_file.read()

    result = json.loads(payload.decode("utf-8"))
    if result.get("version") != SNAPSHOT_VERSION:
        raise RuntimeError(
            f"Go graph engine returned contract version {result.get('version')}, "
            f"expected {SNAPSHOT_VERSION}"
        )
    return result


def _issue_from_dict(record: dict[str, Any]) -> Issue:
    return Issue(
        issue_type=str(record.get("issue_type") or ""),
        title=str(record.get("title") or ""),
        severity=str(record.get("severity") or ""),
        risk_score=float(record.get("risk_score") or 0.0),
        resource_id=str(record.get("resource_id") or ""),
        why=str(record.get("why") or ""),
        remediation=str(record.get("remediation") or ""),
        path=list(record.get("path") or []),
        compliance=dict(record.get("compliance") or {}),
        related=list(record.get("related") or []),
        evidence=list(record.get("evidence") or []),
        scoring=str(record.get("scoring") or ""),
        confidence=float(record.get("confidence") if record.get("confidence") is not None else 1.0),
        evidence_status=str(record.get("evidence_status") or "confirmed"),
    )


# ── parity ─────────────────────────────────────────────────────

def _comparable(issue: Issue) -> tuple:
    """The fields that must agree between engines.

    Deliberately every field an operator acts on, not just the identity: an
    engine that finds the same paths but scores them differently has still
    changed which alerts get worked first.
    """
    return (
        issue.issue_type, issue.resource_id, issue.severity, round(issue.risk_score, 1),
        round(issue.confidence, 2),
        issue.evidence_status,
        tuple(json.dumps(hop, sort_keys=True, separators=(",", ":")) for hop in issue.path),
        issue.title, issue.why, issue.remediation, tuple(sorted(issue.related)),
        json.dumps(issue.compliance, sort_keys=True, separators=(",", ":")),
        tuple(json.dumps(item, sort_keys=True, separators=(",", ":"))
              for item in issue.evidence),
        issue.scoring,
    )


def compare(python_issues: list[Issue], go_issues: list[Issue]) -> dict[str, Any]:
    """Diff two engines' output. Empty ``differences`` means byte-equal verdicts."""
    python_set = {_comparable(i) for i in python_issues}
    go_set = {_comparable(i) for i in go_issues}
    only_python = sorted(python_set - go_set)
    only_go = sorted(go_set - python_set)
    return {
        "python_count": len(python_issues),
        "go_count": len(go_issues),
        "only_python": [list(item[:6]) for item in only_python[:20]],
        "only_go": [list(item[:6]) for item in only_go[:20]],
        "only_python_total": len(only_python),
        "only_go_total": len(only_go),
        "match": not only_python and not only_go,
        # Ordering is what the UI ranks by, so it is reported but does not by
        # itself fail parity — the sets agreeing is the security property.
        "order_match": [_comparable(i) for i in python_issues] == [_comparable(i) for i in go_issues],
    }


# ── entry point ────────────────────────────────────────────────

def analyze(
    assets: Iterable[Any],
    *,
    scanner_principal_arn: Optional[str] = None,
    account_external_ids: Optional[dict[str, str]] = None,
    account_role_arns: Optional[dict[str, str]] = None,
    data_labels: Optional[dict[str, str]] = None,
    engine: Optional[str] = None,
) -> list[Issue]:
    """Run the attack-path engine selected by configuration."""
    mode = (engine or selected_engine()).lower()
    if mode not in {"auto", "python", "go", "shadow"}:
        logger.warning("unknown graph engine mode %r; using auto", mode)
        mode = "auto"
    kwargs = {
        "scanner_principal_arn": scanner_principal_arn,
        "account_external_ids": account_external_ids,
        "account_role_arns": account_role_arns,
        "data_labels": data_labels,
    }

    if mode == "python":
        return analyze_python(assets, **kwargs)

    assets = list(assets)

    if mode == "auto":
        mode = "go" if len(assets) >= go_min_assets() else "python"
        if mode == "python":
            return analyze_python(assets, **kwargs)

    if mode == "go":
        try:
            snapshot = build_snapshot(assets, **kwargs)
            result = run_go_engine(snapshot)
            return [_issue_from_dict(item) for item in result.get("issues") or []]
        except Exception as exc:  # noqa: BLE001 — see module docstring
            logger.warning(
                "Go graph engine failed (%s); falling back to the Python engine", exc
            )
            return analyze_python(assets, **kwargs)

    # shadow: Python's answer is authoritative, Go's is measured against it.
    python_issues = analyze_python(assets, **kwargs)
    try:
        snapshot = build_snapshot(assets, **kwargs)
        result = run_go_engine(snapshot)
        go_issues = [_issue_from_dict(item) for item in result.get("issues") or []]
    except Exception as exc:  # noqa: BLE001
        logger.warning("Go graph engine failed in shadow mode: %s", exc)
        return python_issues

    report = compare(python_issues, go_issues)
    if report["match"]:
        logger.info(
            "graph engine shadow parity passed: %d issues identical", report["python_count"]
        )
    else:
        logger.warning(
            "graph engine shadow MISMATCH: python=%d go=%d only_python=%d only_go=%d %s",
            report["python_count"], report["go_count"],
            report["only_python_total"], report["only_go_total"],
            json.dumps({"only_python": report["only_python"], "only_go": report["only_go"]}),
        )
    return python_issues
