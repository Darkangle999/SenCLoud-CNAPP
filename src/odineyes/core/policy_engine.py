"""Generic evaluator for user-defined custom policies.

A policy is a {type, params} rule checked against the *normalized* asset fields
the inventory already stores (tags, is_public, encryption_enabled,
network_exposure, asset_type) — no new collection, no per-policy code. It emits
one finding per evaluated asset (status pass|fail) in the same shape the scan
findings use, so ``ComplianceMapper.score`` and the contextual-risk path consume
them unchanged.

ponytail: four rule types cover the common asks (tag hygiene, encryption,
public exposure, network reach). Add a rule type here when a real policy needs
one — don't build a rule DSL until a customer asks for boolean composition.
"""

from __future__ import annotations

from typing import Any, Optional

_EXPOSURE_RANK = {"private": 0, "vpc": 1, "public": 2}


def _matches_type(asset_type: str, resource_type: Optional[str]) -> bool:
    """None → all assets; otherwise exact or dotted-prefix match
    ("aws.s3" matches "aws.s3.bucket")."""
    if not resource_type:
        return True
    return asset_type == resource_type or asset_type.startswith(resource_type + ".")


def _violates(rule: dict[str, Any], asset: dict[str, Any]) -> Optional[str]:
    """Return a human reason if the asset violates the rule, else None (pass)."""
    rtype = rule.get("type")
    params = rule.get("params") or {}

    if rtype == "tag_required":
        key = params.get("key")
        tags = asset.get("tags") or {}
        if key not in tags:
            return f"missing required tag '{key}'"
        want = params.get("value")
        if want is not None and str(tags.get(key)) != str(want):
            return f"tag '{key}' is '{tags.get(key)}', expected '{want}'"
        return None

    if rtype == "encryption_required":
        if asset.get("encryption_enabled") is not True:
            return "encryption not enabled"
        return None

    if rtype == "no_public":
        if asset.get("is_public") is True:
            return "resource is publicly accessible"
        return None

    if rtype == "network_max":
        level = params.get("level", "private")
        cap = _EXPOSURE_RANK.get(level, 0)
        cur = _EXPOSURE_RANK.get(asset.get("network_exposure", "private"), 0)
        if cur > cap:
            return f"network exposure '{asset.get('network_exposure')}' exceeds max '{level}'"
        return None

    # Unknown rule type — don't fail assets on a policy we can't evaluate.
    return None


def evaluate(policies: list[dict[str, Any]], assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run every policy against every matching asset; return pass/fail findings."""
    findings: list[dict[str, Any]] = []
    for pol in policies:
        rtype = pol.get("resource_type")
        for asset in assets:
            if not _matches_type(asset.get("asset_type", ""), rtype):
                continue
            reason = _violates(pol.get("rule") or {}, asset)
            findings.append({
                "check_id": pol["policy_id"],
                "resource_id": asset.get("resource_id"),
                "status": "fail" if reason else "pass",
                "severity": pol.get("severity", "medium"),
                "category": "custom_policy",
                "message": f"{pol.get('name', pol['policy_id'])}: {reason}" if reason
                           else f"{pol.get('name', pol['policy_id'])}: ok",
            })
    return findings


def _demo() -> None:
    assets = [
        {"resource_id": "b1", "asset_type": "aws.s3.bucket", "tags": {"env": "prod"},
         "is_public": True, "encryption_enabled": False, "network_exposure": "public"},
        {"resource_id": "b2", "asset_type": "aws.s3.bucket", "tags": {"env": "prod", "owner": "x"},
         "is_public": False, "encryption_enabled": True, "network_exposure": "private"},
        {"resource_id": "i1", "asset_type": "aws.ec2.instance", "tags": {},
         "is_public": False, "encryption_enabled": True, "network_exposure": "vpc"},
    ]
    pol_tag = {"policy_id": "p_tag", "name": "owner tag", "severity": "low",
               "resource_type": None, "rule": {"type": "tag_required", "params": {"key": "owner"}},
               "frameworks": {}}
    pol_enc = {"policy_id": "p_enc", "name": "encrypt s3", "severity": "high",
               "resource_type": "aws.s3", "rule": {"type": "encryption_required", "params": {}},
               "frameworks": {}}
    pol_pub = {"policy_id": "p_pub", "name": "no public s3", "severity": "critical",
               "resource_type": "aws.s3.bucket", "rule": {"type": "no_public", "params": {}},
               "frameworks": {}}

    f = evaluate([pol_tag, pol_enc, pol_pub], assets)
    byid = {(x["check_id"], x["resource_id"]): x["status"] for x in f}

    # tag policy: b1 and i1 lack 'owner' → fail; b2 has it → pass
    assert byid[("p_tag", "b1")] == "fail"
    assert byid[("p_tag", "b2")] == "pass"
    assert byid[("p_tag", "i1")] == "fail"
    # encryption policy only matched the two S3 buckets (prefix match), not the EC2
    assert ("p_enc", "i1") not in byid
    assert byid[("p_enc", "b1")] == "fail" and byid[("p_enc", "b2")] == "pass"
    # public policy: b1 public → fail, b2 private → pass
    assert byid[("p_pub", "b1")] == "fail" and byid[("p_pub", "b2")] == "pass"

    # network_max: cap at vpc — public exceeds, vpc/private ok
    pol_net = {"policy_id": "p_net", "name": "max vpc", "severity": "medium",
               "resource_type": None, "rule": {"type": "network_max", "params": {"level": "vpc"}},
               "frameworks": {}}
    g = {x["resource_id"]: x["status"] for x in evaluate([pol_net], assets)}
    assert g["b1"] == "fail" and g["i1"] == "pass" and g["b2"] == "pass"
    print("policy_engine self-check passed")


if __name__ == "__main__":
    _demo()
