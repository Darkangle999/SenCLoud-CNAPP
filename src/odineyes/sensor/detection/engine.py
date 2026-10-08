"""Detection engine — wires rules + sequences + baseline.

    engine = DetectionEngine(baseline_learning=True)
    for ev in stream:
        for finding in engine.feed(ev):   # [] during the learning period
            post(finding.to_event())
    ...
    engine.end_learning()                 # baseline frozen, detection live

``feed`` always trains the baseline (so it keeps a complete picture) but emits
nothing until the learning period ends.
"""
from __future__ import annotations

from odineyes.sensor.detection.baseline import BaselineDetector
from odineyes.sensor.detection.finding import Finding
from odineyes.sensor.detection.rules import RuleEngine
from odineyes.sensor.detection.sequences import SequenceDetector


class DetectionEngine:
    def __init__(self, baseline_learning: bool = True) -> None:
        self.rules = RuleEngine()
        self.sequences = SequenceDetector()
        self.baseline = BaselineDetector()
        self.learning = baseline_learning

    def feed(self, event: dict) -> list[Finding]:
        self.baseline.learn(event)
        if self.learning:
            return []
        findings: list[Finding] = []
        findings += self.rules.evaluate(event)
        seq = self.sequences.feed(event)
        if seq:
            findings.append(seq)
        findings += self.baseline.detect(event)
        return findings

    def end_learning(self) -> None:
        self.learning = False
        self.baseline.freeze()
