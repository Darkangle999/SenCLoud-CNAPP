"""Evidence-conservative second-order CIEM relationship engine.

IAM risk is often indirect: a principal cannot assume an admin role directly,
but can make an AWS service execute attacker-controlled work under that role.
This module derives those relationships from Odineyes' normalized policy and
workload evidence.

The implementation is clean-room and does not import or redistribute
IAMhounddog. IAMhounddog's public data-model description informed the problem
shape; Odineyes keeps its own authorization semantics and graph schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from odineyes.inventory.iam_analysis import boundary_allows, identity_allows


@dataclass(frozen=True)
class CiemRelationship:
    source_id: str
    target_id: str
    relationship_type: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _ServiceEscalationPattern:
    service: str
    trusted_service: str
    required_actions: tuple[str, ...]


# Create-and-execute combinations that let a caller select a role and cause
# attacker-controlled work to run under it. Every action must be an
# unconditional explicit Allow that survives the permissions boundary.
_SERVICE_ESCALATION_PATTERNS = (
    _ServiceEscalationPattern(
        "lambda", "lambda.amazonaws.com",
        ("lambda:CreateFunction", "lambda:InvokeFunction"),
    ),
    _ServiceEscalationPattern(
        "cloudformation", "cloudformation.amazonaws.com",
        ("cloudformation:CreateStack",),
    ),
    _ServiceEscalationPattern(
        "codebuild", "codebuild.amazonaws.com",
        ("codebuild:CreateProject", "codebuild:StartBuild"),
    ),
    _ServiceEscalationPattern(
        "ecs", "ecs-tasks.amazonaws.com",
        ("ecs:CreateCluster", "ecs:RegisterTaskDefinition", "ecs:RunTask"),
    ),
    _ServiceEscalationPattern(
        "stepfunctions", "states.amazonaws.com",
        ("states:CreateStateMachine", "states:StartExecution"),
    ),
)


def _properties(asset: Any) -> dict[str, Any]:
    return getattr(asset, "properties", {}) or {}


def _allows(asset: Any, action: str, resource: str) -> bool:
    properties = _properties(asset)
    grants = properties.get("policy_grants") or []
    if not grants or not properties.get("policy_analysis_complete"):
        return False
    return (
        identity_allows(grants, (action,), resource)
        and boundary_allows(
            str(properties.get("permissions_boundary_state") or "not_configured"),
            properties.get("permissions_boundary_grants") or [],
            (action,),
            resource,
        )
    )


def _role_ids(asset: Any) -> list[str]:
    return sorted({
        str(relationship["target_id"])
        for relationship in (getattr(asset, "relationships", []) or [])
        if relationship.get("type") == "EXECUTES_AS"
        and relationship.get("target_id")
    })


def derive_ciem_relationships(assets: Iterable[Any]) -> list[CiemRelationship]:
    """Derive service-mediated relationships from normalized assets.

    Missing evidence, conditions, explicit denies, unreadable boundaries,
    absent PassRole, and incompatible role trust all fail closed.
    """
    assets = list(assets)
    identities = [
        asset for asset in assets
        if getattr(asset, "asset_type", "") in {"aws.iam.role", "aws.iam.user"}
    ]
    roles = {
        str(getattr(asset, "resource_id", "")): asset
        for asset in assets
        if getattr(asset, "asset_type", "") == "aws.iam.role"
    }
    lambdas = [
        asset for asset in assets
        if getattr(asset, "asset_type", "") == "aws.lambda.function"
    ]

    relationships: list[CiemRelationship] = []

    # Existing-function takeover. PassRole is unnecessary because AWS already
    # observed the function-to-role binding.
    for principal in identities:
        principal_id = str(getattr(principal, "resource_id", ""))
        for function in lambdas:
            function_id = str(getattr(function, "resource_id", ""))
            role_ids = _role_ids(function)
            required = ("lambda:UpdateFunctionCode", "lambda:InvokeFunction")
            if not role_ids or not all(
                _allows(principal, action, function_id) for action in required
            ):
                continue
            relationships.append(CiemRelationship(
                principal_id,
                function_id,
                "CAN_MODIFY_AND_INVOKE",
                {
                    "engine": "odineyes-ciem-v1",
                    "via_service": "lambda",
                    "actions": list(required),
                    "target_role_ids": role_ids,
                    "evidence": (
                        "unconditional identity-policy Allows survived the permissions "
                        "boundary; the function execution-role binding was observed"
                    ),
                    "authorization_scope": _properties(principal).get("authorization_scope"),
                    "effective_access_complete": bool(
                        _properties(principal).get("effective_access_complete")
                    ),
                },
            ))

    # New-workload creation. Require service actions, PassRole on the exact role,
    # and a target trust policy that accepts that AWS service.
    for principal in identities:
        principal_id = str(getattr(principal, "resource_id", ""))
        # Create APIs use Resource "*". Requiring every action on "*" avoids
        # inventing a future ARN because an unrelated wildcard happens to fit.
        enabled_patterns = [
            pattern for pattern in _SERVICE_ESCALATION_PATTERNS
            if all(
                _allows(principal, action, "*")
                for action in pattern.required_actions
            )
        ]
        if not enabled_patterns:
            continue
        for role_id, role in roles.items():
            if role_id == principal_id or not _allows(principal, "iam:PassRole", role_id):
                continue
            trusted_services = {
                str(value).lower()
                for value in _properties(role).get("trust_services") or []
            }
            for pattern in enabled_patterns:
                if pattern.trusted_service not in trusted_services:
                    continue
                relationships.append(CiemRelationship(
                    principal_id,
                    role_id,
                    "CAN_IMPERSONATE_VIA_SERVICE",
                    {
                        "engine": "odineyes-ciem-v1",
                        "via_service": pattern.service,
                        "actions": [*pattern.required_actions, "iam:PassRole"],
                        "evidence": (
                            f"principal can create/execute {pattern.service} work, can "
                            f"PassRole on the exact target, and the role trusts "
                            f"{pattern.trusted_service}"
                        ),
                        "authorization_scope": _properties(principal).get("authorization_scope"),
                        "effective_access_complete": bool(
                            _properties(principal).get("effective_access_complete")
                        ),
                    },
                ))

    return sorted(
        relationships,
        key=lambda item: (
            item.source_id,
            item.target_id,
            item.relationship_type,
            str(item.properties.get("via_service") or ""),
        ),
    )
