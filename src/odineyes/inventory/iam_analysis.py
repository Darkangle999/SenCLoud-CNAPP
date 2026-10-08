"""Conservative IAM identity-policy evidence for the CIEM pipeline.

This module does not claim to be a complete AWS authorization simulator.
It models identity policies, inherited IAM group policies, and permissions
boundaries. Resource policies, session policies, SCPs, and RCPs remain outside
the evaluated scope and are reported as coverage limits to API consumers.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any, Iterable

from odineyes.cloud.aws_collector import AwsCollector, _PRIVESC_ACTIONS

ASSUME_ROLE_ACTIONS = ("sts:AssumeRole",)
S3_READ_ACTIONS = (
    "s3:GetObject",
    "s3:GetObjectVersion",
    "s3:GetObjectAttributes",
    "s3:SelectObjectContent",
)

_MAX_GRANT_EVIDENCE = 500


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, str)]
    return []


def _condition_keys(condition: Any) -> list[str]:
    if not isinstance(condition, dict):
        return []
    keys: set[str] = set()
    for values in condition.values():
        if isinstance(values, dict):
            keys.update(str(key) for key in values)
    return sorted(keys)


def normalize_policy_document(
    document: Any,
    *,
    source_type: str,
    source_name: str,
    source_arn: str = "",
    inherited: bool = False,
    group_name: str = "",
) -> list[dict[str, Any]]:
    """Convert one IAM policy into compact, queryable statement evidence."""
    grants: list[dict[str, Any]] = []
    for index, statement in enumerate(AwsCollector._statements(document)):
        if not isinstance(statement, dict):
            continue
        condition = statement.get("Condition")
        grants.append({
            "statement_index": index,
            "effect": str(statement.get("Effect") or ""),
            "actions": _strings(statement.get("Action")),
            "not_actions": _strings(statement.get("NotAction")),
            "resources": _strings(statement.get("Resource")),
            "not_resources": _strings(statement.get("NotResource")),
            "conditional": bool(condition),
            "condition_keys": _condition_keys(condition),
            "source_type": source_type,
            "source_name": source_name,
            "source_arn": source_arn,
            "inherited": inherited,
            "group_name": group_name,
        })
    return grants


def _action_matches(action: str, pattern: str) -> bool:
    return fnmatchcase(action.lower(), pattern.lower())


def _resource_matches(resource: str, pattern: str) -> bool:
    if pattern == "*" or fnmatchcase(resource, pattern):
        return True
    if resource.startswith("arn:aws:s3:::") and pattern.startswith("arn:aws:s3:::"):
        resource_bucket = resource.split(":::", 1)[1].split("/", 1)[0]
        pattern_bucket = pattern.split(":::", 1)[1].split("/", 1)[0]
        return fnmatchcase(resource_bucket, pattern_bucket)
    return False


def _explicit_unconditional_allows(grants: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        grant for grant in grants
        if grant.get("effect") == "Allow"
        and not grant.get("conditional")
        and not grant.get("not_actions")
        and not grant.get("not_resources")
        and grant.get("actions")
        and grant.get("resources")
    ]


def granted_resources(
    grants: Iterable[dict[str, Any]],
    candidate_actions: Iterable[str],
) -> set[str]:
    """Resources in unconditional explicit Allow statements for given actions."""
    candidates = tuple(candidate_actions)
    resources: set[str] = set()
    for grant in _explicit_unconditional_allows(grants):
        if any(
            _action_matches(candidate, pattern)
            for candidate in candidates
            for pattern in grant["actions"]
        ):
            resources.update(grant["resources"])
    return resources


def identity_allows(
    grants: Iterable[dict[str, Any]],
    candidate_actions: Iterable[str],
    resource: str,
) -> bool:
    """Whether normalized identity evidence supports a capability candidate.

    Explicit Deny overrides Allow. Complex Deny statements using NotAction or
    NotResource fail closed until the full condition evaluator is implemented.
    """
    candidates = tuple(candidate_actions)
    grants = list(grants)
    for grant in grants:
        if grant.get("effect") != "Deny":
            continue
        if grant.get("not_actions") or grant.get("not_resources"):
            return False
        if (
            any(
                _action_matches(candidate, pattern)
                for candidate in candidates
                for pattern in grant.get("actions") or []
            )
            and any(
                _resource_matches(resource, pattern)
                for pattern in grant.get("resources") or []
            )
        ):
            return False

    return any(
        any(
            _action_matches(candidate, pattern)
            for candidate in candidates
            for pattern in grant["actions"]
        )
        and any(
            _resource_matches(resource, pattern)
            for pattern in grant["resources"]
        )
        for grant in _explicit_unconditional_allows(grants)
    )


def boundary_allows(
    boundary_state: str,
    boundary_grants: Iterable[dict[str, Any]],
    candidate_actions: Iterable[str],
    resource: str,
) -> bool:
    """Whether the observed boundary permits at least one candidate capability.

    ``not_configured`` means there is no boundary intersection. A configured
    but unreadable boundary returns False so attack-path edges fail closed.
    Conditional boundary allows are not treated as proof because their request
    context is unavailable. Any matching explicit deny is also fail-closed.
    """
    if boundary_state == "not_configured":
        return True
    if boundary_state != "observed":
        return False

    candidates = tuple(candidate_actions)
    grants = list(boundary_grants)
    for grant in grants:
        if grant.get("effect") != "Deny":
            continue
        if grant.get("not_actions") or grant.get("not_resources"):
            return False
        actions = grant.get("actions") or []
        resources = grant.get("resources") or []
        if (
            any(_action_matches(candidate, pattern) for candidate in candidates for pattern in actions)
            and any(_resource_matches(resource, pattern) for pattern in resources)
        ):
            return False

    return any(
        any(_action_matches(candidate, pattern) for candidate in candidates for pattern in grant["actions"])
        and any(_resource_matches(resource, pattern) for pattern in grant["resources"])
        for grant in _explicit_unconditional_allows(grants)
    )


def _source_summary(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_type": str(entry.get("source_type") or ""),
        "source_name": str(entry.get("source_name") or ""),
        "source_arn": str(entry.get("source_arn") or ""),
        "inherited": bool(entry.get("inherited")),
        "group_name": str(entry.get("group_name") or ""),
    }


def analyze_identity_policies(
    policy_documents: Iterable[dict[str, Any]],
    *,
    boundary_document: dict[str, Any] | None = None,
    boundary_arn: str = "",
    boundary_state: str = "not_configured",
    analysis_complete: bool = True,
) -> dict[str, Any]:
    """Build normalized CIEM evidence and bounded capability candidates."""
    documents = list(policy_documents)
    grants: list[dict[str, Any]] = []
    for entry in documents:
        grants.extend(normalize_policy_document(
            entry.get("document") or {},
            source_type=str(entry.get("source_type") or ""),
            source_name=str(entry.get("source_name") or ""),
            source_arn=str(entry.get("source_arn") or ""),
            inherited=bool(entry.get("inherited")),
            group_name=str(entry.get("group_name") or ""),
        ))

    boundary_grants: list[dict[str, Any]] = []
    if boundary_document is not None:
        boundary_grants = normalize_policy_document(
            boundary_document,
            source_type="permissions_boundary",
            source_name=boundary_arn.rsplit("/", 1)[-1],
            source_arn=boundary_arn,
        )

    unconditional = _explicit_unconditional_allows(grants)
    admin_grants = [
        grant for grant in unconditional
        if "*" in grant["actions"] and "*" in grant["resources"]
    ]
    admin_grant = bool(admin_grants)
    identity_permits_admin = admin_grant and not any(
        grant.get("effect") == "Deny" for grant in grants
    )
    boundary_permits_admin = boundary_allows(
        boundary_state, boundary_grants, ("*",), "*",
    )

    privesc: set[str] = set()
    effective_privesc: set[str] = set()
    for grant in unconditional:
        for action_pattern in grant["actions"]:
            matched_actions = {
                action for action in _PRIVESC_ACTIONS
                if _action_matches(action, action_pattern)
            }
            if action_pattern in {"*", "iam:*", "sts:*"}:
                matched_actions.add(action_pattern)
            for action in matched_actions:
                privesc.add(action)
                if any(
                    identity_allows(grants, (action,), resource)
                    and boundary_allows(
                        boundary_state, boundary_grants, (action,), resource
                    )
                    for resource in grant["resources"]
                ):
                    effective_privesc.add(action)

    sources = [_source_summary(entry) for entry in documents]
    unique_sources = list({
        (
            source["source_type"],
            source["source_name"],
            source["source_arn"],
            source["inherited"],
            source["group_name"],
        ): source
        for source in sources
    }.values())
    direct_sources = [source for source in unique_sources if not source["inherited"]]
    inherited_sources = [source for source in unique_sources if source["inherited"]]

    admin_reason = ""
    if admin_grants:
        source = admin_grants[0]
        source_label = {
            "role_managed": "managed policy",
            "user_managed": "managed policy",
            "group_managed": "managed policy",
            "role_inline": "inline policy",
            "user_inline": "inline policy",
            "group_inline": "inline policy",
        }.get(str(source.get("source_type") or ""), str(source.get("source_type") or "policy"))
        inherited_suffix = (
            f" via group {source['group_name']}" if source.get("group_name") else ""
        )
        admin_reason = (
            f"{source_label} {source['source_name']} (*:*)"
            f"{inherited_suffix}"
        )

    truncated = len(grants) > _MAX_GRANT_EVIDENCE
    return {
        "has_admin_grant": admin_grant,
        # Backward-compatible field, but now boundary-aware. Organization and
        # resource controls are still disclosed as unevaluated below.
        "has_admin": identity_permits_admin and boundary_permits_admin,
        "admin_reason": admin_reason,
        "privesc_actions": sorted(privesc),
        "effective_privesc_actions": sorted(effective_privesc),
        "assume_role_resources": sorted(granted_resources(grants, ASSUME_ROLE_ACTIONS)),
        "s3_read_resources": sorted(granted_resources(grants, S3_READ_ACTIONS)),
        "policy_sources": unique_sources,
        "policy_grants": grants[:_MAX_GRANT_EVIDENCE],
        "grant_evidence_truncated": truncated,
        "policy_source_count": len(unique_sources),
        "direct_policy_count": len(direct_sources),
        "inherited_policy_count": len(inherited_sources),
        "allow_statement_count": sum(grant.get("effect") == "Allow" for grant in grants),
        "explicit_deny_count": sum(grant.get("effect") == "Deny" for grant in grants),
        "conditional_statement_count": sum(bool(grant.get("conditional")) for grant in grants),
        "wildcard_action_statement_count": sum(
            any(action == "*" or action.endswith(":*") for action in grant.get("actions") or [])
            for grant in unconditional
        ),
        "wildcard_resource_statement_count": sum(
            "*" in (grant.get("resources") or []) for grant in unconditional
        ),
        "permissions_boundary_arn": boundary_arn,
        "permissions_boundary_state": boundary_state,
        "permissions_boundary_grants": boundary_grants,
        "boundary_restricts_admin": admin_grant and not boundary_permits_admin,
        "policy_analysis_complete": analysis_complete,
        "authorization_scope": (
            "identity_policies_and_boundary"
            if boundary_state == "observed"
            else "identity_policies"
        ),
        "effective_access_complete": False,
        "unevaluated_policy_layers": [
            "resource_policies",
            "session_policies",
            "service_control_policies",
            "resource_control_policies",
        ],
    }
