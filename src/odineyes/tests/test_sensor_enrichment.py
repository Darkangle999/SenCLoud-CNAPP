"""Sensor enrichment + detection-normalizer tests — pure Python, no kernel/BCC.

The eBPF run loop itself can only be exercised on a Linux host with BTF + bcc;
these cover the parts that don't need a kernel: the event normalizer that feeds
the detection engine, and the SUID/exe-mode helper.
"""
from __future__ import annotations

import os
import stat
import sys

from odineyes.sensor import tetragon_shipper as a
from odineyes.sensor.detection import DetectionEngine


def test_normalize_execve():
    det = a.normalize_for_detection({
        "event_type": "process_execution", "syscall": "execve",
        "comm": "sh", "parent": "nginx", "exe": "/bin/sh",
        "command": "sh -c id", "pid": 10, "ppid": 9, "uid": 33,
    })
    assert det["type"] == "execve"
    assert det["comm"] == "sh" and det["parent_comm"] == "nginx"
    assert det["args"] == ["sh", "-c", "id"]


def test_normalize_connect_splits_dest():
    det = a.normalize_for_detection({
        "event_type": "reverse_shell", "syscall": "connect",
        "comm": "bash", "parent": "bash", "dest": "203.0.113.9:4444",
    })
    assert det["type"] == "connect"
    assert det["dst_ip"] == "203.0.113.9" and det["dst_port"] == 4444


def test_normalize_mmap_flags():
    det = a.normalize_for_detection({
        "event_type": "fileless_execution", "syscall": "mmap",
        "comm": "x", "prot_exec": True, "prot_write": True, "map_anonymous": True,
    })
    assert det["type"] == "mmap"
    assert det["prot_exec"] and det["prot_write"] and det["map_anonymous"]


def test_normalized_event_drives_detection_engine():
    # the full path: a sensor connect → normalize → engine fires RT-002
    eng = DetectionEngine(baseline_learning=False)
    det = a.normalize_for_detection({
        "event_type": "reverse_shell", "syscall": "connect",
        "comm": "bash", "parent": "bash", "dest": "1.2.3.4:4444",
    })
    assert any(f.rule_id == "RT-002" for f in eng.feed(det))


def test_exe_mode_detects_suid(tmp_path):
    if sys.platform == "win32":
        import pytest
        pytest.skip("Windows does not expose Unix SUID mode bits")
    plain = tmp_path / "plain"
    plain.write_text("x")
    assert a.exe_mode_of(str(plain)) == ""
    suid = tmp_path / "suid"
    suid.write_text("x")
    os.chmod(suid, 0o4755)  # setuid bit
    assert a.exe_mode_of(str(suid)) == "SUID"
    assert os.stat(suid).st_mode & stat.S_ISUID


def test_exe_mode_missing_path_is_empty():
    assert a.exe_mode_of(None) == ""
    assert a.exe_mode_of("/nonexistent/binary/xyz") == ""

def test_parse_tetragon_event():
    import json
    
    # Exec
    exec_json = json.dumps({
        "process_exec": {
            "process": {
                "binary": "/bin/bash",
                "arguments": "-c id",
                "pid": 1234,
                "pod": {"name": "nginx-pod"}
            }
        }
    })
    
    parsed = a.parse_tetragon_event(exec_json)
    assert parsed is not None
    assert parsed["event_type"] == "process_execution"
    assert parsed["comm"] == "bash"
    assert parsed["pid"] == 1234
    assert parsed["workload"] == "nginx-pod"
    assert "process_exec" in parsed["raw"]

    # Kprobe connect
    kprobe_json = json.dumps({
        "process_kprobe": {
            "function_name": "tcp_connect",
            "process": {
                "binary": "/usr/bin/curl",
                "pid": 5678,
                "pod": {"name": "curl-pod"}
            }
        }
    })
    parsed2 = a.parse_tetragon_event(kprobe_json)
    assert parsed2 is not None
    assert parsed2["event_type"] == "network_connection"
    assert parsed2["comm"] == "curl"
    assert parsed2["pid"] == 5678

