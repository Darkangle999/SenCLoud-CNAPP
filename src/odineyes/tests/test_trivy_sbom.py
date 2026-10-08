"""SBOM generation guards — offline, no trivy binary, no AWS."""

from __future__ import annotations

from odineyes.cloud.trivy_scanner import TrivyScanner


def test_sbom_skips_when_trivy_absent(monkeypatch):
    monkeypatch.setattr(TrivyScanner, "available", staticmethod(lambda: False))
    res = TrivyScanner().sbom_image("repo/app:latest")
    assert res.generated is False
    assert "not installed" in res.skipped_reason


def test_sbom_rejects_flag_smuggling_ref(monkeypatch):
    # binary present + trusted, but a ref that looks like a flag must be refused
    # before it reaches trivy's argv.
    monkeypatch.setattr(TrivyScanner, "available", staticmethod(lambda: True))
    monkeypatch.setattr(TrivyScanner, "verify_binary", staticmethod(lambda: (True, "ok")))
    res = TrivyScanner().sbom_image("--output=/tmp/pwn")
    assert res.generated is False
    assert "starts with" in res.skipped_reason


def test_trivy_parser_preserves_component_target_and_package_path():
    rows = TrivyScanner._parse({
        "Results": [{
            "Target": "registry.example/app:1.2.3 (debian 12.4)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2026-1000",
                "PkgName": "openssl",
                "InstalledVersion": "3.0.1",
                "FixedVersion": "3.0.2",
                "PkgPath": "/usr/lib/x86_64-linux-gnu/libssl.so.3",
                "Severity": "HIGH",
            }],
        }],
    })

    assert len(rows) == 1
    assert rows[0].scanner_source == "trivy"
    assert rows[0].ecosystem == "debian"
    assert rows[0].target == "registry.example/app:1.2.3 (debian 12.4)"
    assert rows[0].package_path == "/usr/lib/x86_64-linux-gnu/libssl.so.3"
