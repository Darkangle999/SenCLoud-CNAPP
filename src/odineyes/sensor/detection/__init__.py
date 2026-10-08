"""Runtime detection engine — pure-Python, no BCC/AWS.

Consumes *enriched* events (the schema produced by ``sensor.enricher`` /
``ebpf_agent``) and emits :class:`Finding` objects. Three layers, wired by
:class:`DetectionEngine`:

  rules      — single-event signatures (MITRE-tagged), ``rules.RuleEngine``
  sequences  — multi-event kill chains per process tree, ``sequences.SequenceDetector``
  baseline   — per-process anomaly vs a learned baseline, ``baseline.BaselineDetector``

Findings map to the existing runtime-event vocabulary (``event_type``) so they
flow through the persisted ``/api/internal/runtime-events`` pipeline and the
Step-4 exploitation correlation — no parallel store.
"""
from odineyes.sensor.detection.engine import DetectionEngine
from odineyes.sensor.detection.finding import Finding

__all__ = ["DetectionEngine", "Finding"]
