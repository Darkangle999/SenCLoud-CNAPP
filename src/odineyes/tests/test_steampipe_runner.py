"""Offline tests for the Steampipe compliance backend.

No binary, no AWS — feed a captured ``powerpipe benchmark run ... --output json``
tree to the pure parser and assert the contract the Compliance tab consumes, plus
the fall-back-to-Python-engine dispatch in server._run_cspm.
"""

from odineyes.core import steampipe_runner as sp


# A steampipe-shaped tree covering all three control states + nested sections,
# flat vs status-nested summaries, and an alarm result for findings.
FIXTURE = {
    "groups": [{
        "group_id": "aws_compliance.benchmark.cis_v300",
        "title": "CIS v3.0.0",
        "groups": [
            {
                "group_id": "aws_compliance.benchmark.cis_v300_1",
                "title": "1 IAM",
                "controls": [
                    {
                        "control_id": "control.cis_v300_1_1",
                        "title": "Contact details",
                        "severity": "low",
                        "summary": {"alarm": 2, "ok": 1, "error": 0, "info": 0, "skip": 0},
                        "results": [
                            {"status": "alarm", "resource": "a", "reason": "bad",
                             "dimensions": [{"key": "account_id", "value": "111"},
                                            {"key": "region", "value": "us-east-1"}]},
                            {"status": "alarm", "resource": "b", "reason": "bad"},
                            {"status": "ok", "resource": "c"},
                        ],
                    },
                    {
                        "control_id": "control.cis_v300_1_2",
                        "title": "MFA root",
                        "summary": {"status": {"alarm": 0, "ok": 3, "error": 0, "info": 0, "skip": 0}},
                        "results": [{"status": "ok", "resource": "root"}],
                    },
                ],
            },
            {
                "group_id": "aws_compliance.benchmark.cis_v300_2",
                "title": "2 Logging",
                "controls": [
                    {  # no summary -> counted from results -> only skip -> not_assessed
                        "control_id": "control.cis_v300_2_1",
                        "title": "Manual review",
                        "results": [{"status": "skip", "resource": "x"}],
                    },
                    {  # error counts as fail
                        "control_id": "control.cis_v300_2_2",
                        "title": "CloudTrail",
                        "summary": {"alarm": 0, "ok": 0, "error": 1, "info": 0, "skip": 0},
                        "results": [{"status": "error", "resource": "ct", "reason": "denied"}],
                    },
                ],
            },
        ],
    }],
}


def test_parse_maps_states_and_score():
    comp = sp._parse(FIXTURE, ["CIS"])
    cis = comp["CIS"]
    assert cis["name"] == "CIS AWS Foundations Benchmark"
    assert cis["version"] == "v3.0.0"
    # pass: 1_2 ; fail: 1_1 (alarm), 2_2 (error) ; not_assessed: 2_1
    assert cis["passing"] == 1
    assert cis["total"] == 3          # not_assessed excluded
    assert cis["score"] == 33         # round(1/3*100)
    states = {c["id"]: c["state"] for c in cis["controls"]}
    assert states == {
        "cis_v300_1_1": "fail",
        "cis_v300_1_2": "pass",
        "cis_v300_2_1": "not_assessed",
        "cis_v300_2_2": "fail",
    }


def test_parse_section_is_parent_group_title():
    cis = sp._parse(FIXTURE, ["CIS"])["CIS"]
    sections = {c["id"]: c["section"] for c in cis["controls"]}
    assert sections["cis_v300_1_1"] == "1 IAM"
    assert sections["cis_v300_2_2"] == "2 Logging"


def test_parse_ignores_unrequested_framework():
    assert sp._parse(FIXTURE, ["PCI-DSS"]) == {}


def test_findings_from_alarm_and_error_results():
    finds = sp._findings(FIXTURE)
    ids = sorted(f["control_id"] for f in finds)
    assert ids == ["cis_v300_1_1", "cis_v300_1_1", "cis_v300_2_2"]  # 2 alarms + 1 error
    first = next(f for f in finds if f["resource"] == "a")
    assert first["account"] == "111" and first["region"] == "us-east-1"
    assert first["severity"] == "low" and first["state"] == "fail"


def test_iter_json_splits_concatenated_docs():
    """`powerpipe benchmark run a b` emits one JSON root per benchmark, concatenated."""
    import json
    blob = json.dumps({"group_id": "a"}) + "\n" + json.dumps({"group_id": "b"})
    docs = list(sp._iter_json(blob))
    assert [d["group_id"] for d in docs] == ["a", "b"]
    # single doc still yields one
    assert len(list(sp._iter_json(json.dumps(FIXTURE)))) == 1


def test_run_rejects_frameworks_with_no_benchmark():
    import pytest
    with pytest.raises(ValueError):
        sp.run(["HIPAA", "GDPR"], "us-east-1", None)


def test_run_cspm_falls_back_when_binary_absent(monkeypatch):
    """D6: no steampipe binary -> Python engine path, same shape."""
    from odineyes.api import server
    monkeypatch.setattr(sp, "available", lambda: False)
    monkeypatch.setattr(server, "_run_cspm_python",
                        lambda r, p, f: {"engine": "python", "region": r})
    out = server._run_cspm("us-east-1", None, ["CIS"])
    assert out == {"engine": "python", "region": "us-east-1"}


def test_run_cspm_falls_back_when_steampipe_errors(monkeypatch):
    """D6: binary present but steampipe run blows up -> still falls back."""
    from odineyes.api import server

    def boom(*a, **k):
        raise RuntimeError("steampipe exploded")

    monkeypatch.setattr(sp, "available", lambda: True)
    monkeypatch.setattr(sp, "run", boom)
    monkeypatch.setattr(server, "_run_cspm_python",
                        lambda r, p, f: {"engine": "python"})
    assert server._run_cspm("us-east-1", None, ["CIS"]) == {"engine": "python"}
