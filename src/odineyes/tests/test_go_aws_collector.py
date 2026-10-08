from __future__ import annotations

import json

import pytest

from odineyes.inventory.collection import CollectionError
from odineyes.inventory.go_aws_collector import (
    GoAwsCollector,
    ShadowAwsCollector,
    _decode_response,
)
from odineyes.inventory.orchestrator import (
    AccountRef,
    MultiAccountOrchestrator,
    _aws_scanner_backend,
)


def _response(**overrides):
    payload = {
        "schema_version": "1.0",
        "collector": "odineyes-go-aws/v1",
        "account_identifier": "111122223333",
        "resources": [
            {
                "source_type": "aws.ec2.instance",
                "raw": {"InstanceId": "i-1", "Region": "us-east-1"},
            }
        ],
        "authoritative_scopes": [
            {"source_type": "aws.ec2.instance", "region": "us-east-1"},
            {"source_type": "aws.iam.role", "region": None},
        ],
        "collection_errors": [
            {
                "source_type": "aws.s3.bucket",
                "operation": "s3.ListBuckets",
                "message": "AccessDenied",
                "region": None,
            }
        ],
        "metrics": {
            "regions_scanned": 1,
            "operations": 3,
            "resources": 1,
            "by_type": {"aws.ec2.instance": 1},
            "duration_ms": 25,
        },
    }
    payload.update(overrides)
    return json.dumps(payload).encode()


def test_decode_response_preserves_inventory_contract():
    resources, scopes, errors, metrics = _decode_response(
        _response(),
        expected_account="111122223333",
    )

    assert resources == [
        (
            "aws.ec2.instance",
            {"InstanceId": "i-1", "Region": "us-east-1"},
        )
    ]
    assert scopes == {
        ("aws.ec2.instance", "us-east-1"),
        ("aws.iam.role", None),
    }
    assert errors == [
        CollectionError(
            source_type="aws.s3.bucket",
            operation="s3.ListBuckets",
            message="AccessDenied",
            region=None,
        )
    ]
    assert metrics["by_type"] == {"aws.ec2.instance": 1}


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"schema_version": "2.0"}, "schema_version"),
        ({"account_identifier": "999900001111"}, "account mismatch"),
        ({"resources": [{"source_type": "aws.ec2.instance", "raw": []}]}, "raw value"),
        (
            {"resources": [{"source_type": "aws.unknown.resource", "raw": {}}]},
            "unsupported source_type",
        ),
        ({"authoritative_scopes": "invalid"}, "authoritative_scopes"),
        ({"collection_errors": "invalid"}, "collection_errors"),
    ],
)
def test_decode_response_rejects_contract_drift(overrides, message):
    with pytest.raises(RuntimeError, match=message):
        _decode_response(
            _response(**overrides),
            expected_account="111122223333",
        )


def test_decode_response_surfaces_fatal_error():
    with pytest.raises(RuntimeError, match="AssumeRole failed"):
        _decode_response(
            _response(fatal_error="AssumeRole failed"),
            expected_account="111122223333",
        )


class _Collector:
    def __init__(self, resources, scopes=(), errors=()):
        self.resources = resources
        self.authoritative_scopes = set(scopes)
        self.collection_errors = list(errors)

    def collect(self):
        return list(self.resources)


def test_shadow_returns_python_results_and_completeness():
    primary = _Collector(
        [("aws.ec2.instance", {"InstanceId": "i-1"})],
        scopes={("aws.ec2.instance", "us-east-1")},
    )
    shadow = _Collector(
        [("aws.ec2.instance", {"InstanceId": "i-1"})],
        scopes={("aws.ec2.instance", "us-east-1")},
    )
    shadow.account_identifier = "111122223333"

    collector = ShadowAwsCollector(primary, shadow)
    assert collector.collect() == primary.resources
    assert collector.authoritative_scopes == primary.authoritative_scopes
    assert collector.collection_errors == primary.collection_errors


def test_shadow_failure_never_replaces_python_results(caplog):
    primary = _Collector([("aws.ec2.instance", {"InstanceId": "i-1"})])

    class _FailedShadow:
        account_identifier = "111122223333"

        def collect(self):
            raise RuntimeError("shadow unavailable")

    collector = ShadowAwsCollector(primary, _FailedShadow())
    assert collector.collect() == primary.resources
    assert "shadow scan failed" in caplog.text


def test_orchestrator_go_backend_does_not_create_boto_session(monkeypatch):
    monkeypatch.setenv("ODINEYES_AWS_SCANNER_BACKEND", "go")
    orchestrator = MultiAccountOrchestrator()
    monkeypatch.setattr(
        orchestrator,
        "_default_session",
        lambda _account: pytest.fail("Go backend must own AWS authentication"),
    )
    account = AccountRef(
        "111122223333",
        "customer",
        "arn:aws:iam::111122223333:role/OdineyesReadOnly",
        "aws",
        "external-id",
    )

    collector = orchestrator._make_collector(account)

    assert isinstance(collector, GoAwsCollector)
    assert collector.account_identifier == account.identifier
    assert collector.role_arn == account.role_arn
    assert collector.external_id == account.external_id


def test_orchestrator_go_backend_passes_excluded_regions(monkeypatch):
    monkeypatch.setenv("ODINEYES_AWS_SCANNER_BACKEND", "go")
    orchestrator = MultiAccountOrchestrator()
    monkeypatch.setattr(
        orchestrator,
        "_default_session",
        lambda _account: pytest.fail("Go backend must own AWS authentication"),
    )
    account = AccountRef(
        "111122223333",
        "customer",
        "arn:aws:iam::111122223333:role/OdineyesReadOnly",
        "aws",
        "external-id",
        excluded_regions=("af-south-1", "ap-northeast-3"),
    )

    collector = orchestrator._make_collector(account)

    assert isinstance(collector, GoAwsCollector)
    assert collector.excluded_regions == ["af-south-1", "ap-northeast-3"]


def test_orchestrator_rejects_unknown_backend(monkeypatch):
    monkeypatch.setenv("ODINEYES_AWS_SCANNER_BACKEND", "rust")
    orchestrator = MultiAccountOrchestrator()
    with pytest.raises(RuntimeError, match="python, go, shadow"):
        orchestrator._make_collector(
            AccountRef("111122223333", None, None, "aws")
        )


def test_scanner_backend_allowlist_keeps_other_accounts_on_python(monkeypatch):
    monkeypatch.setenv("ODINEYES_AWS_SCANNER_BACKEND", "go")
    monkeypatch.setenv(
        "ODINEYES_AWS_SCANNER_ACCOUNT_ALLOWLIST",
        "111122223333,444455556666",
    )

    assert _aws_scanner_backend("111122223333") == "go"
    assert _aws_scanner_backend("999900001111") == "python"


def test_scanner_backend_rejects_invalid_allowlist(monkeypatch):
    monkeypatch.setenv("ODINEYES_AWS_SCANNER_BACKEND", "shadow")
    monkeypatch.setenv("ODINEYES_AWS_SCANNER_ACCOUNT_ALLOWLIST", "not-an-account")

    with pytest.raises(RuntimeError, match="12-digit AWS account ids"):
        _aws_scanner_backend("111122223333")
