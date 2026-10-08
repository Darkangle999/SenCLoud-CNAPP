"""Trivy IaC integration: output normalization + the /iac/scan engine switch,
which must fall back to the in-tree scanner when trivy isn't installed."""

from __future__ import annotations

import json

from fastapi import FastAPI
from fastapi.testclient import TestClient

from odineyes.iac import trivy_runner


def _payload() -> str:
    return json.dumps([
        {
            "Target": "/main.tf", "Class": "config", "Type": "terraform",
            "Misconfigurations": [
                {"Type": "Terraform", "ID": "AVD-AWS-0086", "Title": "S3 public ACL",
                 "Description": "Bucket ACL grants public access.", "Resolution": "Remove it.",
                 "Severity": "HIGH", "Status": "FAIL",
                 "Causes": [{"Resource": "aws_s3_bucket.b",
                             "Occurrences": [{"Filename": "/main.tf", "LineNumber": 7}]}]},
                {"Type": "Terraform", "ID": "AVD-AWS-0020", "Title": "S3 logs",
                 "Description": "Buckets should have logging.", "Resolution": "Enable logs.",
                 "Severity": "MEDIUM", "Status": "PASS",
                 "Causes": [{"Resource": "aws_s3_bucket.logs", "Occurrences": []}]},
            ],
        },
    ])


def test_parse_output_normalizes_and_skips_pass():
    fs = trivy_runner.parse_output(_payload())
    assert [f["check_id"] for f in fs] == ["AVD-AWS-0086"]
    assert fs[0]["severity"] == "high"
    assert fs[0]["engine"] == "trivy"
    assert fs[0]["resource_type"] == "aws_s3_bucket"
    assert fs[0]["file"] == "/main.tf" and fs[0]["lines"] == [7]


def test_parse_output_defaults_missing_severity_to_medium():
    payload = json.dumps([
        {"Target": "/m.tf", "Type": "cloudformation", "Misconfigurations": [
            {"ID": "AVD-AWS-0001", "Title": "x", "Status": "FAIL",
             "Causes": [{"Resource": "AWS::S3::Bucket.b", "Occurrences": []}]},
        ]},
    ])
    fs = trivy_runner.parse_output(payload)
    assert fs[0]["severity"] == "medium"
    assert fs[0]["resource"] == "AWS::S3::Bucket.b"
    assert fs[0]["resource_type"] == "AWS::S3::Bucket"


def test_parse_output_handles_multi_result_list():
    payload = json.dumps([
        {"Target": "/a.tf", "Type": "terraform", "Misconfigurations": [
            {"ID": "AVD-AWS-1", "Title": "x", "Status": "FAIL",
             "Causes": [{"Resource": "aws_x.y", "Occurrences": []}]}]},
        {"Target": "/b.tf", "Type": "dockerfile", "Misconfigurations": []},
    ])
    assert len(trivy_runner.parse_output(payload)) == 1


def _client():
    from odineyes.api.inventory_routes import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_iac_scan_trivy_falls_back_to_builtin_when_absent(monkeypatch):
    # Force "trivy not installed" → the endpoint must still return the builtin
    # result, not 500, so a client asking for trivy never breaks.
    monkeypatch.setattr(trivy_runner, "available", lambda: False)
    tf = 'resource "aws_s3_bucket" "b" { acl = "public-read" }'
    r = _client().post("/api/inventory/iac/scan", json={"content": tf, "engine": "trivy"})
    assert r.status_code == 200
    assert "findings" in r.json() and "by_severity" in r.json()


def test_iac_scan_trivy_uses_trivy_runner_when_installed(monkeypatch):
    recorded: dict = {}

    def fake_available():
        return True

    def fake_scan_content(content, filename=None):
        recorded["content"] = content
        return {"engine": "trivy", "format": None, "findings": [], "total": 0, "by_severity": {}}

    monkeypatch.setattr(trivy_runner, "available", fake_available)
    monkeypatch.setattr(trivy_runner, "scan_content", fake_scan_content)
    tf = 'resource "aws_s3_bucket" "b" { acl = "public-read" }'
    r = _client().post("/api/inventory/iac/scan", json={"content": tf, "engine": "trivy"})
    assert r.status_code == 200
    assert r.json()["engine"] == "trivy"
    assert recorded["content"] == tf


def test_iac_scan_rejects_unknown_engine():
    r = _client().post("/api/inventory/iac/scan", json={"content": "x", "engine": "nessus"})
    assert r.status_code == 422
