"""Cross-signal risk weighting for posture findings (gap analysis §4.2 + §4.5).

A raw rule verdict has a fixed severity. Real risk depends on *context* the
rule didn't see: is the resource internet-facing, and does DSPM say it holds
sensitive data? This module folds those two signals into one `risk_score` and
an `elevated` flag ("public AND sensitive" — the toxic combination).

Pure functions, no DB. The DB-side batch join lives in queries.list_findings.

Note the division of labour with ``reachability_layers``: ``elevated`` here is a
cheap two-signal ranking hint computed from labels, used to sort a findings
list. ``LayeredReachability.verdict == "toxic"`` is the stronger claim — three
layers each proven with evidence. Use this to order a list; use that to decide
something is genuinely exploitable.
"""

from __future__ import annotations

from typing import Any, Optional

# Severity → base weight. info=0 so it can't be elevated by multipliers.
_SEV_BASE = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0, "info": 0.0}
# network_exposure → multiplier.
_EXPOSURE_MULT = {"public": 1.5, "vpc": 1.1, "private": 1.0}
# DSPM label → multiplier.
_DATA_MULT = {"CRITICAL": 1.5, "HIGH": 1.5, "MEDIUM": 1.2, "LOW": 1.0, "NONE": 1.0}

_SENSITIVE = {"CRITICAL", "HIGH", "MEDIUM"}


def store_key(resource_id: Optional[str]) -> str:
    """Canonical key to join a Finding/Asset resource_id against a DspmFinding
    store_id, which use different formats for the same resource:
        arn:aws:s3:::bucket   (finding/asset)   ┐
        s3://bucket           (dspm)            ┘→ "bucket"
        arn:aws:rds:r:a:db:x  / rds://x         → "x"
        arn:...:table/orders  / dynamodb://orders → "orders"
    ponytail: last-segment match — two different-type stores sharing a tail
    name could collide; acceptable for a prioritization hint, not an identity.
    """
    if not resource_id:
        return ""
    s = resource_id.split("://", 1)[-1]   # drop scheme (s3://, rds://, …)
    s = s.split(":")[-1]                  # drop arn prefix → last colon segment
    s = s.split("/")[-1]                  # drop table/ path
    return s.lower()


def finding_risk(
    severity: str,
    *,
    exposure: Optional[str] = None,
    data_label: Optional[str] = None,
) -> dict[str, Any]:
    """base(severity) × exposure_mult × data_mult → risk_score. `elevated` is the
    toxic combo: internet-facing AND holding sensitive data."""
    base = _SEV_BASE.get((severity or "").lower(), 1.0)
    exp = (exposure or "private").lower()
    label = (data_label or "NONE").upper()
    em = _EXPOSURE_MULT.get(exp, 1.0)
    dm = _DATA_MULT.get(label, 1.0)
    return {
        "risk_score": round(base * em * dm, 2),
        "exposure": exp,
        "data_label": label,
        "elevated": exp == "public" and label in _SENSITIVE,
    }


if __name__ == "__main__":
    # store_key joins the two id formats for the same bucket.
    assert store_key("arn:aws:s3:::pii-bucket") == store_key("s3://pii-bucket") == "pii-bucket"
    assert store_key("arn:aws:rds:us-east-1:1:db:prod") == store_key("rds://prod") == "prod"
    assert store_key("arn:aws:dynamodb:r:1:table/orders") == store_key("dynamodb://orders") == "orders"

    # public + critical data beats a plain critical private finding.
    hot = finding_risk("high", exposure="public", data_label="CRITICAL")
    cold = finding_risk("critical", exposure="private", data_label="NONE")
    assert hot["risk_score"] > cold["risk_score"], (hot, cold)
    assert hot["elevated"] is True and cold["elevated"] is False
    # vpc is exposed but not "public" → not the toxic combo.
    assert finding_risk("high", exposure="vpc", data_label="HIGH")["elevated"] is False
    print("finding_risk self-check OK")
