"""Detection-engine unit tests — pure Python, no BCC, no AWS.

Covers the signature rules, the kill-chain sequences (including the window
timeout), the post-learning baseline anomaly, and the learning gate.
"""
from __future__ import annotations

from odineyes.sensor.detection import DetectionEngine
from odineyes.sensor.detection.rules import RuleEngine


def ev(**kw):
    """Build an enriched event with sane defaults."""
    base = {"type": "execve", "pid": 1000, "ppid": 900, "uid": 1000, "comm": "sh"}
    base.update(kw)
    return base


def ids(findings):
    return [f.rule_id for f in findings]


# ── single-event rules ──────────────────────────────────────────────
def test_rt001_web_shell_fires():
    findings = RuleEngine().evaluate(ev(type="execve", parent_comm="nginx", comm="sh"))
    assert "RT-001" in ids(findings)


def test_rt001_negative_sshd_parent():
    findings = RuleEngine().evaluate(ev(type="execve", parent_comm="sshd", comm="sh"))
    assert "RT-001" not in ids(findings)


def test_rt002_c2_public_fires():
    findings = RuleEngine().evaluate(
        ev(type="connect", parent_comm="bash", comm="bash", dst_ip="1.2.3.4", dst_port=4444))
    assert "RT-002" in ids(findings)


def test_rt002_negative_rfc1918():
    findings = RuleEngine().evaluate(
        ev(type="connect", parent_comm="bash", comm="bash", dst_ip="10.0.0.1", dst_port=4444))
    assert "RT-002" not in ids(findings)


def test_rt003_credential_file_access():
    findings = RuleEngine().evaluate(ev(type="openat", comm="cat", path="/etc/shadow"))
    assert "RT-003" in ids(findings)


def test_rt005_container_escape_nsenter():
    findings = RuleEngine().evaluate(ev(
        type="execve", comm="nsenter", exe="/usr/bin/nsenter",
        args=["--target", "1", "--mount", "--", "bash"]))
    assert "RT-005" in ids(findings)


# ── multi-event sequences ───────────────────────────────────────────
def test_seq001_download_execute_within_window():
    eng = DetectionEngine(baseline_learning=False)
    out = []
    out += eng.feed(ev(type="execve", comm="curl", tree_root=5000, ts=0))
    out += eng.feed(ev(type="openat", comm="curl", write=True, path="/tmp/x", tree_root=5000, ts=2))
    out += eng.feed(ev(type="execve", comm="x", tree_root=5000, ts=30))
    assert "SEQ-001" in ids(out)


def test_seq001_times_out_after_window():
    eng = DetectionEngine(baseline_learning=False)
    out = []
    out += eng.feed(ev(type="execve", comm="curl", tree_root=5001, ts=0))
    out += eng.feed(ev(type="openat", comm="curl", write=True, path="/tmp/x", tree_root=5001, ts=2))
    out += eng.feed(ev(type="execve", comm="x", tree_root=5001, ts=61))
    assert "SEQ-001" not in ids(out)


# ── baseline anomaly + learning gate ────────────────────────────────
def test_anomaly001_new_external_ip_after_learning():
    eng = DetectionEngine(baseline_learning=True)
    # learning: curl normally talks to 1.1.1.1:443
    assert eng.feed(ev(type="connect", comm="curl", dst_ip="1.1.1.1", dst_port=443)) == []
    eng.end_learning()
    out = eng.feed(ev(type="connect", comm="curl", dst_ip="8.8.8.8", dst_port=443))
    assert "ANOMALY-001" in ids(out)


def test_no_findings_emitted_during_learning():
    eng = DetectionEngine(baseline_learning=True)
    # a blatantly malicious event during learning must stay silent
    out = eng.feed(ev(type="execve", comm="nsenter", exe="/usr/bin/nsenter",
                      args=["--target", "1"]))
    assert out == []


def test_findings_emitted_after_end_learning():
    eng = DetectionEngine(baseline_learning=True)
    eng.end_learning()
    out = eng.feed(ev(type="execve", comm="nsenter", exe="/usr/bin/nsenter",
                      args=["--target", "1"]))
    assert "RT-005" in ids(out)
