"""
Odineyes DSPM engine — discover sensitive data, score store risk, and
enrich the security graph so attack paths inherit data blast-radius.

Read-only. S3 sampling uses list_objects_v2 + ranged get_object (first 64 KB of
prioritized objects). Nothing is created or modified. When no AWS creds /
objects are available, name+tag heuristics still produce a (lower-confidence)
sensitivity verdict so the dashboard always has data.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from odineyes.dspm.classifier import (
    DataFinding, SENSITIVITY_WEIGHT, classify,
)

logger = logging.getLogger("odineyes.dspm")

# Object extensions worth sampling, in priority order.
_SAMPLE_EXT = (".csv", ".json", ".jsonl", ".txt", ".sql", ".tsv", ".log", ".xml")
_MAX_OBJECTS = 25
_RANGE_BYTES = 64 * 1024


def _volume_multiplier(records: int) -> float:
    if records >= 1_000_000:
        return 2.0
    if records >= 10_000:
        return 1.6
    if records >= 100:
        return 1.3
    return 1.0


@dataclass
class StoreSensitivity:
    store_id: str                       # graph node id, e.g. s3://bucket
    store_name: str
    store_type: str = "S3"              # S3|RDS|RDSSnapshot|EBSSnapshot|DynamoDB|Secret|SSMParameter
    findings: list[DataFinding] = field(default_factory=list)
    posture_findings: list[str] = field(default_factory=list)  # config/exposure issues
    record_estimate: int = 0
    sensitivity_score: float = 0.0      # 0..1, type weight × confidence
    exposure_score: float = 0.0         # 0..1
    controls_penalty: float = 0.0       # additive, higher = worse
    risk_score: float = 0.0             # final 0..1
    objects_sampled: int = 0
    engine: str = ""                    # DB engine (mysql/postgres/...) when relevant
    public: bool = False                # internet-reachable / publicly shared

    @property
    def pii_types(self) -> list[str]:
        return sorted({f.type for f in self.findings})

    @property
    def taxonomies(self) -> list[str]:
        return sorted({f.taxonomy for f in self.findings})

    @property
    def label(self) -> str:
        if not self.findings and not self.posture_findings:
            return "NONE"
        s = self.risk_score
        if s >= 0.8:
            return "CRITICAL"
        if s >= 0.55:
            return "HIGH"
        if s >= 0.3:
            return "MEDIUM"
        return "LOW"

    @property
    def frameworks(self) -> list[str]:
        out: set[str] = set()
        for f in self.findings:
            out.update(f.frameworks)
        return sorted(out)

    def to_dict(self) -> dict:
        return {
            "store_id": self.store_id, "store_name": self.store_name,
            "store_type": self.store_type,
            "label": self.label, "risk_score": round(self.risk_score, 3),
            "sensitivity_score": round(self.sensitivity_score, 3),
            "exposure_score": round(self.exposure_score, 3),
            "controls_penalty": round(self.controls_penalty, 3),
            "record_estimate": self.record_estimate,
            "objects_sampled": self.objects_sampled,
            "engine": self.engine, "public": self.public,
            "pii_types": self.pii_types, "taxonomies": self.taxonomies,
            "posture_findings": self.posture_findings,
            "frameworks": self.frameworks,
            "findings": [f.to_dict() for f in self.findings],
        }


class DspmEngine:
    """Classify data stores and fold results back into the SecurityGraph."""

    # ── scoring ─────────────────────────────────────────────────
    def score_store(self, findings: list[DataFinding], *, exposure: float,
                    controls_penalty: float, records: int) -> tuple[float, float]:
        """Return (sensitivity_score, final_risk_score), each 0..1."""
        if not findings:
            return 0.0, 0.0
        sensitivity = max(
            SENSITIVITY_WEIGHT.get(f.type, 0.3) * f.confidence for f in findings)
        sensitivity = min(sensitivity * _volume_multiplier(records), 1.0)
        controls_factor = min(1.0 + controls_penalty, 2.0)
        risk = min(sensitivity * max(exposure, 0.1) * controls_factor, 1.0)
        return sensitivity, risk

    def score_posture(self, *, exposure: float, controls_penalty: float,
                      baseline: float, force_critical: bool = False) -> float:
        """Risk for stores scored on POSTURE (no content sampled), e.g. an RDS
        instance or a snapshot. `baseline` = assumed sensitivity of the store
        type (a prod DB is assumed PII-bearing). force_critical pins ≥0.9
        (used for publicly-shared snapshots — CRITICAL regardless of content).
        """
        controls_factor = min(1.0 + controls_penalty, 2.0)
        risk = min(baseline * max(exposure, 0.1) * controls_factor, 1.0)
        if force_critical:
            risk = max(risk, 0.9)
        return risk

    # ── S3 ──────────────────────────────────────────────────────
    def scan_bucket(self, s3_client, bucket: str, *, is_public: bool,
                    encrypted: bool, region: str = "") -> StoreSensitivity:
        findings: list[DataFinding] = []
        sampled = 0
        record_estimate = 0
        try:
            resp = s3_client.list_objects_v2(Bucket=bucket, MaxKeys=200)
            objs = resp.get("Contents", [])
        except Exception as e:                       # access denied / no creds
            logger.info("DSPM list_objects %s failed: %s", bucket, e)
            objs = []

        # Prioritize data-bearing extensions, then largest.
        objs.sort(key=lambda o: (
            0 if o["Key"].lower().endswith(_SAMPLE_EXT) else 1, -o.get("Size", 0)))

        for o in objs[:_MAX_OBJECTS]:
            key = o["Key"]
            if not key.lower().endswith(_SAMPLE_EXT):
                continue
            try:
                body = s3_client.get_object(
                    Bucket=bucket, Key=key, Range=f"bytes=0-{_RANGE_BYTES - 1}")
                text = body["Body"].read().decode("utf-8", "ignore")
            except Exception as e:
                logger.debug("DSPM get_object %s/%s failed: %s", bucket, key, e)
                continue
            sampled += 1
            record_estimate += max(text.count("\n"), 1)
            findings.extend(classify(text, path=key))

        findings = _merge(findings)
        exposure, penalty = self._s3_posture(is_public, encrypted)
        sens, risk = self.score_store(
            findings, exposure=exposure, controls_penalty=penalty,
            records=record_estimate)
        return StoreSensitivity(
            store_id=f"s3://{bucket}", store_name=bucket, store_type="S3",
            findings=findings, public=is_public,
            record_estimate=record_estimate, sensitivity_score=sens,
            exposure_score=exposure, controls_penalty=penalty,
            risk_score=risk, objects_sampled=sampled)

    def _s3_posture(self, is_public: bool, encrypted: bool) -> tuple[float, float]:
        exposure = 1.0 if is_public else 0.3
        penalty = 0.0
        if not encrypted:
            penalty += 0.4
        if is_public:
            penalty += 0.5
        return exposure, penalty

    # ── name/tag heuristic (no object access) ───────────────────
    def heuristic_store(self, store_id: str, name: str, *, sensitive_hint: bool,
                        is_public: bool, encrypted: bool) -> StoreSensitivity | None:
        """Fallback when objects can't be read: infer from name/tags only."""
        if not sensitive_hint:
            return None
        findings = classify("", path=name) or [DataFinding(
            type="PERSON_NAME", taxonomy="PII", count=0, confidence=0.45,
            validated=False, evidence={"heuristic": "name/tag flagged sensitive"})]
        exposure, penalty = self._s3_posture(is_public, encrypted)
        sens, risk = self.score_store(
            findings, exposure=exposure, controls_penalty=penalty, records=0)
        return StoreSensitivity(
            store_id=store_id, store_name=name, store_type="S3",
            findings=findings, public=is_public,
            sensitivity_score=sens, exposure_score=exposure,
            controls_penalty=penalty, risk_score=risk)

    # ── inventory runner ────────────────────────────────────────
    def scan_s3_inventory(self, s3_records, s3_client=None) -> list[StoreSensitivity]:
        """Classify every bucket in an AwsInventory.s3 list.

        Tries live sampling when an s3_client is given; falls back to
        name/tag heuristics for buckets with no readable objects.
        """
        stores: list[StoreSensitivity] = []
        for b in s3_records:
            store = None
            if s3_client is not None:
                store = self.scan_bucket(
                    s3_client, b.name, is_public=b.is_public,
                    encrypted=b.encrypted, region=getattr(b, "region", ""))
            if store is None or not store.findings:
                heur = self.heuristic_store(
                    f"s3://{b.name}", b.name,
                    sensitive_hint=getattr(b, "sensitive", False),
                    is_public=b.is_public, encrypted=b.encrypted)
                store = heur if (store is None or not store.findings) else store
            if store and store.findings:
                stores.append(store)
        return stores

    # ── graph enrichment ────────────────────────────────────────
    # store_type → graph node label for data stores discovered by DSPM only
    # (S3Bucket / RDSDatabase already exist from the collector).
    _NODE_LABEL = {
        "S3": "S3Bucket", "RDS": "RDSDatabase", "RDSSnapshot": "RDSSnapshot",
        "EBSSnapshot": "EBSSnapshot", "DynamoDB": "DynamoDBTable",
        "Secret": "Secret", "SSMParameter": "SSMParameter",
    }


def _merge(findings: list[DataFinding]) -> list[DataFinding]:
    """Collapse duplicate types, summing counts and keeping max confidence."""
    agg: dict[str, DataFinding] = {}
    for f in findings:
        cur = agg.get(f.type)
        if cur is None:
            agg[f.type] = f
        else:
            agg[f.type] = DataFinding(
                type=f.type, taxonomy=f.taxonomy, count=cur.count + f.count,
                confidence=max(cur.confidence, f.confidence),
                validated=cur.validated or f.validated,
                weight=f.weight, frameworks=f.frameworks,
                evidence=cur.evidence)
    return sorted(agg.values(), key=lambda x: -x.confidence)
