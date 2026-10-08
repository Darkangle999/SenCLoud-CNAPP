"""Multi-event kill-chain detection.

A state machine per process tree (keyed by the tree root pid the enricher
stamps as ``tree_root``; falls back to ``pid``). Each sequence advances only on
its next expected step; the whole chain must complete within ``window`` seconds
of step 1 or the partial state is evicted. Event time is taken from ``ev['ts']``
(monotonic seconds) when present so detection is deterministic under test.
"""
from __future__ import annotations

import time
from typing import Any

from odineyes.sensor.detection import rules
from odineyes.sensor.detection.finding import Finding

SEQUENCES: list[dict[str, Any]] = [
    {
        "id": "SEQ-001",
        "name": "Download and execute",
        "severity": "critical",
        "tactic": "Execution",
        "technique": "T1105",
        "event_type": "reverse_shell",
        "window": 60,
        "steps": [
            {"type": "execve", "comm": ["curl", "wget"]},
            {"type": "openat", "write": True},
            {"type": "execve"},
        ],
    },
    {
        "id": "SEQ-002",
        "name": "Web shell full chain",
        "severity": "critical",
        "tactic": "Execution",
        "technique": "T1059.004",
        "event_type": "reverse_shell",
        "window": 60,
        "steps": [
            {"type": "execve",
             "parent_comm": ["nginx", "apache2", "httpd", "gunicorn", "uvicorn", "node", "php-fpm"],
             "comm": ["sh", "bash", "dash", "zsh"]},
            {"type": "execve", "comm": ["curl", "wget", "python", "python3"]},
            {"type": "connect", "dst_ip": "NOT_RFC1918"},
        ],
    },
    {
        "id": "SEQ-003",
        "name": "Recon then exfil",
        "severity": "high",
        "tactic": "Exfiltration",
        "technique": "T1041",
        "event_type": "network_connection",
        "window": 300,
        "steps": [
            {"type": "openat", "path_prefix": ["/etc/", "/proc/", "/.aws/"]},
            {"type": "connect", "dst_ip": "NOT_RFC1918"},
        ],
    },
]

_MAX_TREES = 4096


def _tree_key(ev: dict) -> Any:
    return ev.get("tree_root") if ev.get("tree_root") is not None else ev.get("pid")


def _now(ev: dict) -> float:
    ts = ev.get("ts")
    return float(ts) if ts is not None else time.monotonic()


class SequenceDetector:
    def __init__(self, sequences: list[dict] | None = None) -> None:
        self.sequences = sequences if sequences is not None else SEQUENCES
        self._max_window = max((s["window"] for s in self.sequences), default=0)
        # tree_key -> { seq_id -> {"step": int, "t0": float} }
        self._state: dict[Any, dict[str, dict]] = {}

    def _evict(self, now: float) -> None:
        for key in list(self._state.keys()):
            seqs = self._state[key]
            for sid, prog in list(seqs.items()):
                window = next((s["window"] for s in self.sequences if s["id"] == sid), self._max_window)
                if now - prog["t0"] > window:
                    seqs.pop(sid, None)
            if not seqs:
                self._state.pop(key, None)
        if len(self._state) > _MAX_TREES:  # bound memory: drop oldest activity
            oldest = sorted(
                self._state.items(),
                key=lambda kv: min((p["t0"] for p in kv[1].values()), default=now),
            )
            for key, _ in oldest[: len(self._state) - _MAX_TREES]:
                self._state.pop(key, None)

    def feed(self, ev: dict) -> Finding | None:
        now = _now(ev)
        self._evict(now)
        st = self._state.setdefault(_tree_key(ev), {})
        completed: Finding | None = None

        for seq in self.sequences:
            steps = seq["steps"]
            prog = st.get(seq["id"])
            nextidx = prog["step"] if prog else 0
            if not rules.match(steps[nextidx], ev):
                continue
            if nextidx == 0:
                st[seq["id"]] = {"step": 1, "t0": now}
            elif now - prog["t0"] <= seq["window"]:
                prog["step"] = nextidx + 1
            else:
                # chain timed out — restart only if this event is a fresh step 1
                if rules.match(steps[0], ev):
                    st[seq["id"]] = {"step": 1, "t0": now}
                else:
                    st.pop(seq["id"], None)
                continue
            cur = st.get(seq["id"])
            if cur and cur["step"] >= len(steps):
                completed = Finding(
                    rule_id=seq["id"], name=seq["name"], severity=seq["severity"],
                    tactic=seq["tactic"], technique=seq["technique"],
                    event_type=seq["event_type"],
                    summary=f"{seq['name']} (kill chain, {len(steps)} steps)",
                    source=ev,
                )
                st.pop(seq["id"], None)
        return completed
