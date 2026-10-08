"""Per-process behavioural baseline + anomaly detection.

During the learning period the engine calls :meth:`learn` for every event and
emits nothing. After :meth:`freeze` (driven by ``DetectionEngine.end_learning``)
``learn`` becomes a no-op and :meth:`detect` compares each event against the
frozen baseline, flagging first-occurrence novelty (then recording it so the
same value does not re-fire).

Baseline is keyed per ``comm``:
  children    child process names this comm has spawned
  net_ips     external IPs this comm has connected to
  net_ports   ports this comm has connected to
  open_paths  path prefixes this comm has opened
  syscalls    Counter of event types
"""
from __future__ import annotations

import json
import logging
import time
from collections import Counter
from typing import Any

from odineyes.sensor.detection.finding import Finding
from odineyes.sensor.detection.rules import _is_external

logger = logging.getLogger("odineyes.sensor.baseline")

SERVICE_PARENTS = {"nginx", "apache2", "httpd", "gunicorn", "uvicorn", "node", "php-fpm"}
DANGEROUS_CHILDREN = {"sh", "bash", "curl", "wget"}
COMMON_PORTS = {53, 80, 123, 443, 587, 993, 995}

_DEFAULT_PATH = "/tmp/cs_baseline.json"


def _prefix(path: str) -> str:
    head = path.rsplit("/", 1)[0]
    return (head + "/") if head else path


class BaselineDetector:
    def __init__(self) -> None:
        self._base: dict[str, dict[str, Any]] = {}
        self._frozen = False

    def _b(self, comm: str) -> dict[str, Any]:
        b = self._base.get(comm)
        if b is None:
            b = {"children": set(), "net_ips": set(), "net_ports": set(),
                 "open_paths": set(), "syscalls": Counter()}
            self._base[comm] = b
        return b

    # ── learning ───────────────────────────────────────────────────
    def learn(self, ev: dict) -> None:
        if self._frozen:
            return
        self._observe(ev)

    def freeze(self) -> None:
        self._frozen = True

    def _observe(self, ev: dict) -> None:
        comm = ev.get("comm")
        if not comm:
            return
        b = self._b(comm)
        b["syscalls"][ev.get("type", "?")] += 1
        typ = ev.get("type")
        if typ == "connect":
            ip, port = ev.get("dst_ip"), ev.get("dst_port")
            if ip and _is_external(ip):
                b["net_ips"].add(ip)
            if port is not None:
                b["net_ports"].add(port)
        elif typ == "execve":
            parent = ev.get("parent_comm")
            if parent:
                self._b(parent)["children"].add(comm)
        elif typ == "openat":
            p = ev.get("path")
            if p:
                b["open_paths"].add(_prefix(p))

    # ── detection (after learning) ─────────────────────────────────
    def detect(self, ev: dict) -> list[Finding]:
        out: list[Finding] = []
        comm = ev.get("comm")
        if not comm:
            return out
        typ = ev.get("type")
        if typ == "connect":
            b = self._b(comm)
            ip, port = ev.get("dst_ip"), ev.get("dst_port")
            if ip and _is_external(ip) and ip not in b["net_ips"]:
                out.append(Finding(
                    "ANOMALY-001", "New external destination never seen in baseline",
                    "high", "Command and Control", "T1071", "network_connection",
                    f"{comm} → new external IP {ip}", ev))
            if port is not None and port not in b["net_ports"] and port not in COMMON_PORTS:
                out.append(Finding(
                    "ANOMALY-003", "New non-standard port connection",
                    "medium", "Command and Control", "T1071", "network_connection",
                    f"{comm} → new port {port}", ev))
            if ip and _is_external(ip):
                b["net_ips"].add(ip)
            if port is not None:
                b["net_ports"].add(port)
        elif typ == "execve":
            parent = ev.get("parent_comm")
            if parent in SERVICE_PARENTS and comm in DANGEROUS_CHILDREN:
                pb = self._b(parent)
                if comm not in pb["children"]:
                    out.append(Finding(
                        "ANOMALY-002", "New dangerous child of service process",
                        "high", "Execution", "T1059", "process_execution",
                        f"{parent} spawned previously-unseen {comm}", ev))
                pb["children"].add(comm)
        return out

    # ── persistence ────────────────────────────────────────────────
    def save(self, path: str = _DEFAULT_PATH) -> None:
        try:
            data = {"ts": time.time(), "baselines": {
                c: {"children": sorted(b["children"]), "net_ips": sorted(b["net_ips"]),
                    "net_ports": sorted(b["net_ports"]), "open_paths": sorted(b["open_paths"]),
                    "syscalls": dict(b["syscalls"])}
                for c, b in self._base.items()}}
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
        except OSError as e:
            logger.warning("baseline save failed: %s", e)

    def load(self, path: str = _DEFAULT_PATH, max_age_h: float = 24.0) -> bool:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return False
        if time.time() - data.get("ts", 0) > max_age_h * 3600:
            return False
        for c, b in data.get("baselines", {}).items():
            self._base[c] = {
                "children": set(b.get("children", [])),
                "net_ips": set(b.get("net_ips", [])),
                "net_ports": set(b.get("net_ports", [])),
                "open_paths": set(b.get("open_paths", [])),
                "syscalls": Counter(b.get("syscalls", {})),
            }
        return True
