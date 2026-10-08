"""Continuous + dynamic compliance: snapshot persistence + drift detection.

Feeds ComplianceRepository.snapshot the dict shape ComplianceMapper.score
emits, across two cycles, and asserts control transitions are recorded with
the right direction (regression / remediation) and noise is ignored.
"""
from __future__ import annotations

from odineyes.db.base import init_db, session_scope
from odineyes.inventory import queries
from odineyes.inventory.repository import ComplianceRepository


def _compliance(states: dict[str, str]) -> dict:
    """Build a one-framework ComplianceMapper.score-shaped dict from control
    id -> state, computing the score over assessed (pass+fail) controls."""
    controls = [{"id": cid, "title": f"control {cid}", "state": st} for cid, st in states.items()]
    assessed = [s for s in states.values() if s != "not_assessed"]
    passing = sum(1 for s in assessed if s == "pass")
    total = len(assessed)
    return {
        "CIS": {
            "name": "CIS test", "version": "1.0",
            "score": round(passing / total * 100) if total else 0,
            "passing": passing, "total": total,
            "not_assessed": len(states) - total,
            "controls": controls,
        }
    }


def _db(tmp_path):
    url = f"sqlite:///{tmp_path}/compliance.db"
    init_db(url)
    return url


def test_first_snapshot_has_no_drift(tmp_path):
    _db(tmp_path)
    with session_scope() as s:
        stats = ComplianceRepository.snapshot(
            s, compliance=_compliance({"1.1": "pass", "1.2": "fail"}))
    assert stats == {"snapshots": 1, "drifts": 0}
    with session_scope() as s:
        cur = queries.compliance_current(s)
    assert cur["total"] == 1
    assert cur["items"][0]["framework"] == "CIS"
    assert cur["items"][0]["score"] == 50  # 1 pass of 2 assessed


def test_drift_regression_and_remediation(tmp_path):
    _db(tmp_path)
    # cycle 1: 1.1 pass, 1.2 fail, 1.3 pass
    with session_scope() as s:
        ComplianceRepository.snapshot(
            s, compliance=_compliance({"1.1": "pass", "1.2": "fail", "1.3": "pass"}))
    # cycle 2: 1.1 -> fail (regression), 1.2 -> pass (remediation), 1.3 unchanged
    with session_scope() as s:
        stats = ComplianceRepository.snapshot(
            s, compliance=_compliance({"1.1": "fail", "1.2": "pass", "1.3": "pass"}))
    assert stats["snapshots"] == 1
    assert stats["drifts"] == 2

    with session_scope() as s:
        drift = queries.compliance_drift(s)
    assert drift["regressions"] == 1
    assert drift["remediations"] == 1
    by_ctrl = {d["control_id"]: d for d in drift["items"]}
    assert by_ctrl["1.1"]["direction"] == "regression"
    assert by_ctrl["1.1"]["from_state"] == "pass" and by_ctrl["1.1"]["to_state"] == "fail"
    assert by_ctrl["1.2"]["direction"] == "remediation"


def test_not_assessed_transitions_are_noise(tmp_path):
    _db(tmp_path)
    with session_scope() as s:
        ComplianceRepository.snapshot(
            s, compliance=_compliance({"1.1": "pass", "1.4": "not_assessed"}))
    # pass -> not_assessed and not_assessed -> pass are not posture drift
    with session_scope() as s:
        stats = ComplianceRepository.snapshot(
            s, compliance=_compliance({"1.1": "not_assessed", "1.4": "pass"}))
    assert stats["drifts"] == 0
    # but not_assessed -> fail IS a regression
    with session_scope() as s:
        stats = ComplianceRepository.snapshot(
            s, compliance=_compliance({"1.1": "fail", "1.4": "pass"}))
    assert stats["drifts"] == 1


def test_origin_provenance_persists(tmp_path):
    _db(tmp_path)
    with session_scope() as s:
        ComplianceRepository.snapshot(
            s, compliance=_compliance({"1.1": "pass"}), origin="steampipe")
    with session_scope() as s:
        cur = queries.compliance_current(s)
    assert cur["items"][0]["origin"] == "steampipe"


def test_history_trend_ordering(tmp_path):
    _db(tmp_path)
    for states in ({"1.1": "fail"}, {"1.1": "pass"}):
        with session_scope() as s:
            ComplianceRepository.snapshot(s, compliance=_compliance(states))
    with session_scope() as s:
        hist = queries.compliance_history(s, framework="CIS")
    scores = [p["score"] for p in hist["points"]]
    assert scores == [0, 100]  # oldest -> newest
