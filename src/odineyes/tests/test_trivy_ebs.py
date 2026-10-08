"""Offline coverage for the opt-in Trivy EBS Direct scanner."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

from odineyes.cloud.trivy_scanner import EbsSnapshotScanResult, TrivyScanner


class _Credentials:
    access_key = "ASIAEXAMPLE"
    secret_key = "not-a-real-secret"
    token = "test-session-token"

    def get_frozen_credentials(self):
        return self


class _Session:
    def get_credentials(self):
        return _Credentials()


def test_ebs_vm_rejects_non_snapshot_identifier(monkeypatch):
    scanner = TrivyScanner(region="us-east-1", session=_Session())
    monkeypatch.setattr(TrivyScanner, "available", staticmethod(lambda: True))
    monkeypatch.setattr(TrivyScanner, "verify_binary", staticmethod(lambda: (True, "ok")))

    result = scanner.scan_ebs_snapshot("--output=/tmp/pwn")

    assert result.scanned is False
    assert result.skipped_reason == "invalid EBS snapshot id"


def test_ebs_vm_uses_temporary_role_credentials_and_vulnerability_only(monkeypatch):
    scanner = TrivyScanner(region="ap-south-1", session=_Session())
    monkeypatch.setattr(TrivyScanner, "available", staticmethod(lambda: True))
    monkeypatch.setattr(TrivyScanner, "verify_binary", staticmethod(lambda: (True, "ok")))
    captured: dict = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs["env"]
        return SimpleNamespace(returncode=0, stderr="", stdout="""{
          \"Results\": [{
            \"Target\": \"ebs:snap-0123456789abcdef0 (debian 12)\",
            \"Type\": \"debian\",
            \"Vulnerabilities\": [{
              \"VulnerabilityID\": \"CVE-2026-1234\",
              \"PkgName\": \"openssl\",
              \"InstalledVersion\": \"3.0.0\",
              \"FixedVersion\": \"3.0.1\",
              \"Severity\": \"HIGH\"
            }]
          }]
        }""")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setenv("AWS_PROFILE", "wrong-profile")

    result = scanner.scan_ebs_snapshot("snap-0123456789abcdef0")

    assert result.scanned is True
    assert result.component_count == 1
    assert result.vulnerabilities[0].scanner_source == "trivy-ebs"
    assert captured["args"][-1] == "ebs:snap-0123456789abcdef0"
    assert "--scanners" in captured["args"]
    assert captured["args"][captured["args"].index("--scanners") + 1] == "vuln"
    assert captured["env"]["AWS_ACCESS_KEY_ID"] == "ASIAEXAMPLE"
    assert captured["env"]["AWS_REGION"] == "ap-south-1"
    assert "AWS_PROFILE" not in captured["env"]


def test_ebs_vm_skip_does_not_run_subprocess_without_binary(monkeypatch):
    scanner = TrivyScanner(region="us-east-1", session=_Session())
    monkeypatch.setattr(TrivyScanner, "available", staticmethod(lambda: False))

    result = scanner.scan_ebs_snapshot("snap-0123456789abcdef0")

    assert result.scanned is False
    assert result.skipped_reason == "trivy binary not installed"


def test_service_records_unconfigured_disk_scan_as_coverage_gap(tmp_path):
    """A missing opt-in role is visible but cannot mutate vulnerability state."""
    from sqlalchemy import select

    from odineyes.db.base import get_sessionmaker
    from odineyes.db.models import SecurityScanRun
    from odineyes.inventory.service import InventoryService

    service = InventoryService(f"sqlite:///{tmp_path}/odineyes.db")
    result = service.scan_ebs_snapshot_vulnerabilities(
        "aws", "123456789012", snapshot_id="snap-0123456789abcdef0", region="us-east-1",
    )

    assert result.scanned is False
    assert "not enabled" in result.skipped_reason
    with get_sessionmaker()() as session:
        run = session.execute(select(SecurityScanRun)).scalar_one()
    assert run.scanner == "trivy-ebs"
    assert run.status == "skipped"
    assert run.evidence["mode"] == "ebs_direct"


def test_instance_lifecycle_scans_root_volume_and_deletes_snapshot(monkeypatch, tmp_path):
    from sqlalchemy import select

    from odineyes.db.base import get_sessionmaker, session_scope
    from odineyes.db.models import SecurityScanRun
    from odineyes.inventory.repository import AccountRepository
    from odineyes.inventory.service import InventoryService

    calls: list[tuple[str, object]] = []

    class _Waiter:
        def wait(self, **kwargs):
            calls.append(("wait", kwargs))

    class _EC2:
        def describe_instances(self, **kwargs):
            return {
                "Reservations": [{"Instances": [{
                    "RootDeviceName": "/dev/xvda",
                    "BlockDeviceMappings": [
                        {"DeviceName": "/dev/xvdf", "Ebs": {"VolumeId": "vol-data0001"}},
                        {"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-root0001"}},
                    ],
                }]}],
            }

        def describe_volumes(self, **kwargs):
            calls.append(("describe_volumes", kwargs["VolumeIds"]))
            return {"Volumes": [{"Size": 30}]}

        def create_snapshot(self, **kwargs):
            calls.append(("create_snapshot", kwargs))
            return {"SnapshotId": "snap-0123456789abcdef0"}

        def get_waiter(self, name):
            assert name == "snapshot_completed"
            return _Waiter()

        def delete_snapshot(self, **kwargs):
            calls.append(("delete_snapshot", kwargs["SnapshotId"]))

    class _DiskSession:
        def client(self, service, region_name=None):
            assert service == "ec2"
            assert region_name == "us-east-1"
            return _EC2()

    database_url = f"sqlite:///{tmp_path}/odineyes.db"
    service = InventoryService(database_url)
    with session_scope(database_url) as session:
        account = AccountRepository.get_or_create(session, "aws", "123456789012")
        account.disk_scan_role_arn = "arn:aws:iam::123456789012:role/OdineyesReadOnly-DiskScan"
        account.external_id = "cs-test-external-id"

    monkeypatch.setattr(
        TrivyScanner, "assume_role_session", staticmethod(lambda **kwargs: _DiskSession()),
    )
    monkeypatch.setattr(
        TrivyScanner,
        "scan_ebs_snapshot",
        lambda self, snapshot_id: EbsSnapshotScanResult(snapshot_id=snapshot_id, scanned=True),
    )

    result = service.scan_ec2_instance_vulnerabilities(
        "aws", "123456789012", instance_id="i-0123456789abcdef0", region="us-east-1",
    )

    assert result.scanned is True
    assert result.volume_id == "vol-root0001"
    assert result.snapshot_deleted is True
    create = next(value for name, value in calls if name == "create_snapshot")
    assert create["VolumeId"] == "vol-root0001"
    assert {t["Key"]: t["Value"] for t in create["TagSpecifications"][0]["Tags"]}["ManagedBy"] == "CSPM-G3"
    assert ("delete_snapshot", "snap-0123456789abcdef0") in calls
    with get_sessionmaker()() as session:
        run = session.execute(select(SecurityScanRun)).scalar_one()
    assert run.resource_id.endswith("instance/i-0123456789abcdef0")
    assert run.evidence["root_volume_only"] is True
    assert run.evidence["snapshot_deleted"] is True


def test_instance_lifecycle_deletes_snapshot_when_trivy_fails(monkeypatch, tmp_path):
    from odineyes.db.base import session_scope
    from odineyes.inventory.repository import AccountRepository
    from odineyes.inventory.service import InventoryService

    deleted: list[str] = []

    class _Waiter:
        def wait(self, **kwargs):
            return None

    class _EC2:
        def describe_instances(self, **kwargs):
            return {"Reservations": [{"Instances": [{
                "RootDeviceName": "/dev/xvda",
                "BlockDeviceMappings": [{
                    "DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-root0001"},
                }],
            }]}]}

        def describe_volumes(self, **kwargs):
            return {"Volumes": [{"Size": 20}]}

        def create_snapshot(self, **kwargs):
            return {"SnapshotId": "snap-0123456789abcdef0"}

        def get_waiter(self, name):
            return _Waiter()

        def delete_snapshot(self, **kwargs):
            deleted.append(kwargs["SnapshotId"])

    class _DiskSession:
        def client(self, service, region_name=None):
            return _EC2()

    database_url = f"sqlite:///{tmp_path}/odineyes.db"
    service = InventoryService(database_url)
    with session_scope(database_url) as session:
        account = AccountRepository.get_or_create(session, "aws", "123456789012")
        account.disk_scan_role_arn = "arn:aws:iam::123456789012:role/OdineyesReadOnly-DiskScan"
        account.external_id = "cs-test-external-id"

    monkeypatch.setattr(
        TrivyScanner, "assume_role_session", staticmethod(lambda **kwargs: _DiskSession()),
    )
    monkeypatch.setattr(
        TrivyScanner,
        "scan_ebs_snapshot",
        lambda self, snapshot_id: EbsSnapshotScanResult(
            snapshot_id=snapshot_id, scanned=False, skipped_reason="trivy failed",
        ),
    )

    result = service.scan_ec2_instance_vulnerabilities(
        "aws", "123456789012", instance_id="i-0123456789abcdef0", region="us-east-1",
    )

    assert result.scanned is False
    assert result.skipped_reason == "trivy failed"
    assert result.snapshot_deleted is True
    assert deleted == ["snap-0123456789abcdef0"]
