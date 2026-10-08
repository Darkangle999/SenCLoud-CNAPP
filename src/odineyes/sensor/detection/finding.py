"""The shape every detector emits. Kept in its own module so rules/sequences/
baseline/engine can all import it without a cycle.

``event_type`` is deliberately drawn from the existing runtime-event vocabulary
(reverse_shell / privilege_escalation / container_escape / sensitive_file_access
/ network_connection / fileless_execution / process_injection) so a Finding,
once POSTed, is persisted and picked up by the Step-4 exploitation correlation
exactly like a sensor-classified event.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str          # critical | high | medium | low
    tactic: str            # MITRE ATT&CK tactic
    technique: str         # MITRE technique id
    event_type: str        # runtime-event vocabulary (drives correlation)
    summary: str
    source: dict[str, Any] = field(default_factory=dict)

    def to_event(self) -> dict[str, Any]:
        """Render as the enriched runtime-event dict the ingest endpoint expects.

        Carries the detection metadata (rule_id/technique/tactic) under the same
        keys the existing pipeline already tolerates in the event ``raw`` blob.
        """
        s = self.source
        dst = None
        if s.get("dst_ip"):
            dst = f"{s['dst_ip']}:{s['dst_port']}" if s.get("dst_port") else s["dst_ip"]
        return {
            "event_type": self.event_type,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "rule_name": self.name,
            "tactic": self.tactic,
            "technique": self.technique,
            "summary": self.summary,
            "comm": s.get("comm"),
            "command": s.get("command"),
            "filename": s.get("path") or s.get("exe"),
            "dest": dst,
            "pid": s.get("pid"),
            "ppid": s.get("ppid"),
            "uid": s.get("uid"),
            "parent": s.get("parent_comm"),
            "container": s.get("container_id"),
            "instance_id": s.get("host"),
            "node": s.get("hostname"),
            "process_tree": s.get("process_tree"),
            "benign": False,
        }
