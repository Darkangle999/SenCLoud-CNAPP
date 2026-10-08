"""Signature-based single-event detection (MITRE ATT&CK tagged).

Each rule's ``match`` is a small declarative predicate over an enriched event.
``event_type`` ties the rule to the runtime-event vocabulary so a fired rule is
persisted + correlated like any other runtime signal.

Supported match keys:
  type              event type: execve | connect | openat | mmap | clone
  comm / parent_comm / exe   membership in a list
  exe_mode          "SUID"
  uid_not           reject when uid equals this (e.g. 0 = root)
  dst_ip            "NOT_RFC1918" (public) or a literal address
  dst_port          membership in a list
  path_prefix       path startswith / contains any entry
  args_contains     ALL tokens present in argv/command
  args_contains_any ANY token present (alternatives, e.g. -p / --pid)
  prot_exec / prot_write / map_anonymous   boolean flag equals
"""
from __future__ import annotations

import ipaddress
from typing import Any

from odineyes.sensor.detection.finding import Finding

RULES: list[dict[str, Any]] = [
    {
        "id": "RT-001",
        "name": "Web shell — shell spawned from web process",
        "severity": "critical",
        "tactic": "Execution",
        "technique": "T1059.004",
        "event_type": "reverse_shell",
        "match": {
            "type": "execve",
            "parent_comm": ["nginx", "apache2", "httpd", "gunicorn", "uvicorn", "node", "php-fpm"],
            "comm": ["sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby", "lua"],
        },
    },
    {
        "id": "RT-002",
        "name": "C2 callback — shell connecting outbound",
        "severity": "critical",
        "tactic": "Command and Control",
        "technique": "T1071",
        "event_type": "reverse_shell",
        "match": {
            "type": "connect",
            "parent_comm": ["sh", "bash", "dash"],
            "dst_ip": "NOT_RFC1918",
        },
    },
    {
        "id": "RT-003",
        "name": "Credential file access",
        "severity": "high",
        "tactic": "Credential Access",
        "technique": "T1552",
        "event_type": "sensitive_file_access",
        "match": {
            "type": "openat",
            "path_prefix": ["/etc/shadow", "/root/.ssh", "/.aws/credentials",
                            "/.aws/config", "/proc/1/mem", "/etc/gshadow"],
        },
    },
    {
        "id": "RT-004",
        "name": "SUID binary execution by non-root",
        "severity": "high",
        "tactic": "Privilege Escalation",
        "technique": "T1548.001",
        "event_type": "privilege_escalation",
        "match": {
            "type": "execve",
            "exe_mode": "SUID",
            "uid_not": 0,
        },
    },
    {
        "id": "RT-005",
        "name": "Container escape via nsenter",
        "severity": "critical",
        "tactic": "Privilege Escalation",
        "technique": "T1611",
        "event_type": "container_escape",
        "match": {
            "type": "execve",
            "exe": ["/usr/bin/nsenter", "/bin/nsenter"],
            "args_contains": ["--target", "1"],
        },
    },
    {
        "id": "RT-006",
        "name": "Fileless malware — anonymous exec memory",
        "severity": "critical",
        "tactic": "Defense Evasion",
        "technique": "T1620",
        "event_type": "fileless_execution",
        "match": {
            "type": "mmap",
            "prot_exec": True,
            "prot_write": True,
            "map_anonymous": True,
        },
    },
    {
        "id": "RT-007",
        "name": "Crypto miner indicators",
        "severity": "high",
        "tactic": "Impact",
        "technique": "T1496",
        "event_type": "network_connection",
        "match": {
            "type": "connect",
            "dst_port": [3333, 4444, 5555, 7777, 14444, 45700],
            "dst_ip": "NOT_RFC1918",
        },
    },
    {
        "id": "RT-008",
        "name": "Process injection via ptrace",
        "severity": "critical",
        "tactic": "Defense Evasion",
        "technique": "T1055",
        "event_type": "process_injection",
        # NOTE: -p and --pid are alternatives — match ANY (the spec's list is
        # the set of flags that indicate attach-to-pid, not a conjunction).
        "match": {
            "type": "execve",
            "comm": ["gdb", "strace", "ltrace"],
            "args_contains_any": ["--pid", "-p"],
        },
    },
]


def _is_external(ip: str | None) -> bool:
    """True only for routable public addresses (the spec's NOT_RFC1918)."""
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_reserved or a.is_unspecified)


def _arg_has(ev: dict, token: str) -> bool:
    args = ev.get("args") or []
    if token in args:
        return True
    cmd = ev.get("command") or ""
    return bool(cmd) and token in cmd


def _path_hit(path: str | None, prefixes: list[str]) -> bool:
    if not path:
        return False
    return any(path.startswith(p) or p in path for p in prefixes)


def match(m: dict, ev: dict) -> bool:
    """Evaluate one declarative ``match`` predicate against an enriched event."""
    if m.get("type") and ev.get("type") != m["type"]:
        return False
    if "parent_comm" in m and ev.get("parent_comm") not in m["parent_comm"]:
        return False
    if "comm" in m and ev.get("comm") not in m["comm"]:
        return False
    if "exe" in m and ev.get("exe") not in m["exe"]:
        return False
    if "exe_mode" in m and ev.get("exe_mode") != m["exe_mode"]:
        return False
    if "uid_not" in m and ev.get("uid") == m["uid_not"]:
        return False
    if "dst_ip" in m:
        if m["dst_ip"] == "NOT_RFC1918":
            if not _is_external(ev.get("dst_ip")):
                return False
        elif ev.get("dst_ip") != m["dst_ip"]:
            return False
    if "dst_port" in m and ev.get("dst_port") not in m["dst_port"]:
        return False
    if "path_prefix" in m and not _path_hit(ev.get("path"), m["path_prefix"]):
        return False
    if "write" in m and bool(ev.get("write")) != bool(m["write"]):
        return False
    if "args_contains" in m and not all(_arg_has(ev, a) for a in m["args_contains"]):
        return False
    if "args_contains_any" in m and not any(_arg_has(ev, a) for a in m["args_contains_any"]):
        return False
    for flag in ("prot_exec", "prot_write", "map_anonymous"):
        if flag in m and bool(ev.get(flag)) != bool(m[flag]):
            return False
    return True


def _summarize(rule: dict, ev: dict) -> str:
    bits = []
    if ev.get("parent_comm"):
        bits.append(f"{ev['parent_comm']}→{ev.get('comm')}")
    elif ev.get("comm"):
        bits.append(ev["comm"])
    if ev.get("path"):
        bits.append(ev["path"])
    if ev.get("dst_ip"):
        bits.append(f"{ev['dst_ip']}:{ev.get('dst_port')}")
    detail = " ".join(bits)
    return f"{rule['name']}" + (f" [{detail}]" if detail else "")


class RuleEngine:
    def __init__(self, rules: list[dict] | None = None) -> None:
        self.rules = rules if rules is not None else RULES

    def evaluate(self, ev: dict) -> list[Finding]:
        out: list[Finding] = []
        for r in self.rules:
            if match(r["match"], ev):
                out.append(Finding(
                    rule_id=r["id"], name=r["name"], severity=r["severity"],
                    tactic=r["tactic"], technique=r["technique"],
                    event_type=r["event_type"], summary=_summarize(r, ev), source=ev,
                ))
        return out
