"""Checkov IaC integration (§4.8): output normalization + the /iac/scan engine
switch, which must fall back to the in-tree scanner when checkov isn't installed.
"""

from __future__ import annotations

import json

from fastapi import FastAPI
from fastapi.testclient import TestClient

from odineyes.iac import checkov_runner


def test_parse_output_normalizes_and_defaults_severity():
    payload = json.dumps({
        "check_type": "terraform",
        "results": {"failed_checks": [
            {"check_id": "CKV_AWS_20", "check_name": "S3 not public",
             "resource": "aws_s3_bucket.b", "severity": "HIGH", "file_path": "/main.tf"},
            {"check_id": "CKV_AWS_18", "check_name": "S3 logging",
             "resource": "aws_s3_bucket.b"},  # no severity → medium
        ]},
    })
    fs = checkov_runner.parse_output(payload)
    assert [f["check_id"] for f in fs] == ["CKV_AWS_20", "CKV_AWS_18"]
    assert fs[0]["severity"] == "high" and fs[1]["severity"] == "medium"
    assert all(f["engine"] == "checkov" for f in fs)
    assert fs[0]["resource_type"] == "aws_s3_bucket"


def test_parse_output_handles_multi_framework_list():
    payload = json.dumps([
        {"check_type": "terraform", "results": {"failed_checks": [
            {"check_id": "CKV_AWS_1", "check_name": "x", "resource": "aws_x.y"}]}},
        {"check_type": "dockerfile", "results": {"failed_checks": []}},
    ])
    assert len(checkov_runner.parse_output(payload)) == 1


def _client():
    from odineyes.api.inventory_routes import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_iac_scan_checkov_falls_back_to_builtin_when_absent(monkeypatch):
    # Force "checkov not installed" → endpoint must still return the builtin result,
    # not 500, so a client asking for checkov never breaks.
    monkeypatch.setattr(checkov_runner, "available", lambda: False)
    tf = 'resource "aws_s3_bucket" "b" { acl = "public-read" }'
    r = _client().post("/api/inventory/iac/scan", json={"content": tf, "engine": "checkov"})
    assert r.status_code == 200
    body = r.json()
    # builtin scanner shape (no "engine" key; checkov adds one).
    assert "findings" in body and "by_severity" in body


def test_iac_scan_rejects_bad_engine():
    r = _client().post("/api/inventory/iac/scan", json={"content": "x", "engine": "nessus"})
    assert r.status_code == 422
