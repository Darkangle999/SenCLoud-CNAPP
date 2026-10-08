"""
Odineyes DSPM — multi-store discovery & classification.

Extends DSPM beyond S3 to the data stores that most often hold PII / secrets.
Every call here is read-only (Describe*/List*/Get*/Scan with a Limit). Nothing
is created, modified, or deleted. Each scanner is independently guarded so a
missing IAM permission degrades to "skipped", never a crash.

Coverage (Sprint 1):
  RDS instances   — posture (public endpoint / unencrypted / IAM-auth). No row
                    sampling (needs customer DB creds + a driver — deferred).
  RDS snapshots   — public-restore = CRITICAL; unencrypted flagged.
  EBS snapshots   — public createVolumePermission = CRITICAL; unencrypted flagged.
  DynamoDB        — schema inference + Scan(Limit) row sampling → classify.
  Secrets Manager — rotation age + (opt-in) GetSecretValue classification.
  SSM Parameters  — SecureString rotation + (opt-in) value classification.

Content-bearing stores (DynamoDB, Secrets, SSM) run the shared classifier and
are scored on content. Posture-only stores (RDS, snapshots) are scored on
exposure + controls via DspmEngine.score_posture.
"""

from __future__ import annotations

import logging

from odineyes.dspm.classifier import classify
from odineyes.dspm.engine import DspmEngine, StoreSensitivity

logger = logging.getLogger("odineyes.dspm.stores")

# Assumed sensitivity of a store TYPE when we can't read its content.
_BASELINE = {"RDS": 0.85, "RDSSnapshot": 0.85, "EBSSnapshot": 0.7}
_ROTATION_MAX_DAYS = 90
_DDB_SCAN_LIMIT = 100
_SECRET_MAX = 200


# ── RDS instances (posture only) ────────────────────────────────
def scan_rds_instances(rds_client) -> list[StoreSensitivity]:
    eng = DspmEngine()
    out: list[StoreSensitivity] = []
    try:
        pages = rds_client.get_paginator("describe_db_instances").paginate()
        dbs = [d for p in pages for d in p.get("DBInstances", [])]
    except Exception as e:
        logger.info("DSPM rds describe_db_instances skipped: %s", e)
        return out

    for db in dbs:
        public = db.get("PubliclyAccessible", False)
        encrypted = db.get("StorageEncrypted", False)
        iam_auth = db.get("IAMDatabaseAuthenticationEnabled", False)
        posture: list[str] = []
        penalty = 0.0
        if public:
            posture.append("publicly accessible endpoint")
            penalty += 0.5
        if not encrypted:
            posture.append("storage not encrypted at rest")
            penalty += 0.4
        if not iam_auth:
            posture.append("IAM database authentication disabled")
        posture.append("content not sampled (needs DB credentials)")
        risk = eng.score_posture(
            exposure=1.0 if public else 0.3, controls_penalty=penalty,
            baseline=_BASELINE["RDS"])
        out.append(StoreSensitivity(
            store_id=f"rds://{db.get('DBInstanceIdentifier','')}",
            store_name=db.get("DBInstanceIdentifier", ""), store_type="RDS",
            engine=db.get("Engine", ""), public=public,
            posture_findings=posture, exposure_score=1.0 if public else 0.3,
            controls_penalty=penalty, sensitivity_score=_BASELINE["RDS"],
            risk_score=risk))
    return out


# ── RDS snapshots ───────────────────────────────────────────────
def scan_rds_snapshots(rds_client) -> list[StoreSensitivity]:
    eng = DspmEngine()
    out: list[StoreSensitivity] = []
    try:
        pages = rds_client.get_paginator("describe_db_snapshots").paginate()
        snaps = [s for p in pages for s in p.get("DBSnapshots", [])]
    except Exception as e:
        logger.info("DSPM rds describe_db_snapshots skipped: %s", e)
        return out

    for s in snaps:
        sid = s.get("DBSnapshotIdentifier", "")
        encrypted = s.get("Encrypted", False)
        public = _rds_snapshot_public(rds_client, sid)
        posture: list[str] = []
        penalty = 0.0
        if public:
            posture.append("snapshot shared with ALL AWS accounts (public)")
            penalty += 0.6
        if not encrypted:
            posture.append("snapshot not encrypted")
            penalty += 0.4
        if not posture:
            posture.append("private encrypted snapshot")
        risk = eng.score_posture(
            exposure=1.0 if public else 0.3, controls_penalty=penalty,
            baseline=_BASELINE["RDSSnapshot"], force_critical=public)
        out.append(StoreSensitivity(
            store_id=f"rds-snapshot://{sid}", store_name=sid,
            store_type="RDSSnapshot", engine=s.get("Engine", ""), public=public,
            posture_findings=posture, exposure_score=1.0 if public else 0.3,
            controls_penalty=penalty, sensitivity_score=_BASELINE["RDSSnapshot"],
            risk_score=risk))
    return out


def _rds_snapshot_public(rds_client, snapshot_id: str) -> bool:
    try:
        attrs = rds_client.describe_db_snapshot_attributes(
            DBSnapshotIdentifier=snapshot_id
        )["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]
        for a in attrs:
            if a.get("AttributeName") == "restore" and "all" in a.get("AttributeValues", []):
                return True
    except Exception as e:
        logger.debug("rds snapshot attrs %s: %s", snapshot_id, e)
    return False


# ── EBS snapshots ───────────────────────────────────────────────
def scan_ebs_snapshots(ec2_client) -> list[StoreSensitivity]:
    eng = DspmEngine()
    out: list[StoreSensitivity] = []
    try:
        pages = ec2_client.get_paginator("describe_snapshots").paginate(OwnerIds=["self"])
        snaps = [s for p in pages for s in p.get("Snapshots", [])]
    except Exception as e:
        logger.info("DSPM ec2 describe_snapshots skipped: %s", e)
        return out

    for s in snaps:
        sid = s.get("SnapshotId", "")
        encrypted = s.get("Encrypted", False)
        public = _ebs_snapshot_public(ec2_client, sid)
        posture: list[str] = []
        penalty = 0.0
        if public:
            posture.append("snapshot createVolumePermission = all (public)")
            penalty += 0.6
        if not encrypted:
            posture.append("snapshot not encrypted")
            penalty += 0.4
        if not posture:
            posture.append("private encrypted snapshot")
        risk = eng.score_posture(
            exposure=1.0 if public else 0.3, controls_penalty=penalty,
            baseline=_BASELINE["EBSSnapshot"], force_critical=public)
        out.append(StoreSensitivity(
            store_id=f"ebs-snapshot://{sid}", store_name=sid,
            store_type="EBSSnapshot", public=public, posture_findings=posture,
            exposure_score=1.0 if public else 0.3, controls_penalty=penalty,
            sensitivity_score=_BASELINE["EBSSnapshot"], risk_score=risk))
    return out


def _ebs_snapshot_public(ec2_client, snapshot_id: str) -> bool:
    try:
        perms = ec2_client.describe_snapshot_attribute(
            SnapshotId=snapshot_id, Attribute="createVolumePermission"
        ).get("CreateVolumePermissions", [])
        return any(p.get("Group") == "all" for p in perms)
    except Exception as e:
        logger.debug("ebs snapshot attr %s: %s", snapshot_id, e)
        return False


# ── DynamoDB (schema + row sampling) ────────────────────────────
def scan_dynamodb(ddb_client) -> list[StoreSensitivity]:
    eng = DspmEngine()
    out: list[StoreSensitivity] = []
    try:
        pages = ddb_client.get_paginator("list_tables").paginate()
        tables = [t for p in pages for t in p.get("TableNames", [])]
    except Exception as e:
        logger.info("DSPM dynamodb list_tables skipped: %s", e)
        return out

    try:
        from boto3.dynamodb.types import TypeDeserializer
        deser = TypeDeserializer()
    except Exception:
        deser = None

    for name in tables:
        item_count = 0
        try:
            desc = ddb_client.describe_table(TableName=name)["Table"]
            item_count = desc.get("ItemCount", 0)
        except Exception as e:
            logger.debug("describe_table %s: %s", name, e)
        text = _dynamodb_sample_text(ddb_client, name, deser)
        if not text:
            continue
        findings = classify(text, path=f"dynamodb/{name}")
        # DynamoDB is IAM-gated, not internet-public → moderate exposure.
        exposure, penalty = 0.3, 0.0
        sens, risk = eng.score_store(
            findings, exposure=exposure, controls_penalty=penalty,
            records=item_count or _DDB_SCAN_LIMIT)
        if not findings:
            continue
        out.append(StoreSensitivity(
            store_id=f"dynamodb://{name}", store_name=name, store_type="DynamoDB",
            findings=findings, record_estimate=item_count,
            objects_sampled=_DDB_SCAN_LIMIT, exposure_score=exposure,
            controls_penalty=penalty, sensitivity_score=sens, risk_score=risk))
    return out


def _dynamodb_sample_text(ddb_client, table: str, deser) -> str:
    try:
        items = ddb_client.scan(TableName=table, Limit=_DDB_SCAN_LIMIT).get("Items", [])
    except Exception as e:
        logger.debug("scan %s: %s", table, e)
        return ""
    parts: list[str] = []
    for it in items:
        if deser is not None:
            try:
                it = {k: deser.deserialize(v) for k, v in it.items()}
            except Exception:
                pass
        parts.append(_flatten(it))
    return "\n".join(parts)


def _flatten(obj) -> str:
    """Flatten nested dict/list (DynamoDB item) to a single text line."""
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(f"{k}={_flatten(v)}")
    elif isinstance(obj, (list, tuple, set)):
        out.extend(_flatten(x) for x in obj)
    else:
        out.append(str(obj))
    return " ".join(out)


# ── Secrets Manager ─────────────────────────────────────────────
def scan_secrets(sm_client, read_values: bool = False) -> list[StoreSensitivity]:
    import datetime
    eng = DspmEngine()
    out: list[StoreSensitivity] = []
    try:
        pages = sm_client.get_paginator("list_secrets").paginate()
        secrets = [s for p in pages for s in p.get("SecretList", [])][:_SECRET_MAX]
    except Exception as e:
        logger.info("DSPM secretsmanager list_secrets skipped: %s", e)
        return out

    now = datetime.datetime.now(datetime.timezone.utc)
    for s in secrets:
        name = s.get("Name", "")
        arn = s.get("ARN", name)
        posture: list[str] = []
        last_rot = s.get("LastRotatedDate")
        if not s.get("RotationEnabled", False):
            posture.append("automatic rotation disabled")
        elif last_rot and (now - last_rot).days > _ROTATION_MAX_DAYS:
            posture.append(f"not rotated in {(now - last_rot).days} days")

        findings = []
        if read_values:
            findings = _classify_secret_value(sm_client, arn, name)

        # A secret is CREDENTIAL-sensitive by definition (baseline) even unread.
        if findings:
            sens, risk = eng.score_store(
                findings, exposure=0.3, controls_penalty=0.0, records=1)
        else:
            risk = eng.score_posture(exposure=0.3, controls_penalty=0.0, baseline=0.7)
            sens = 0.7
            posture.append("value not read (use --read-secret-values to classify)")
        out.append(StoreSensitivity(
            store_id=f"secret://{name}", store_name=name, store_type="Secret",
            findings=findings, posture_findings=posture, exposure_score=0.3,
            sensitivity_score=sens, risk_score=risk))
    return out


def _classify_secret_value(sm_client, arn: str, name: str):
    try:
        val = sm_client.get_secret_value(SecretId=arn).get("SecretString", "")
    except Exception as e:
        logger.debug("get_secret_value %s: %s", name, e)
        return []
    return classify(val, column=name, path=f"secret/{name}")


# ── SSM Parameter Store ─────────────────────────────────────────
def scan_ssm_parameters(ssm_client, read_values: bool = False) -> list[StoreSensitivity]:
    eng = DspmEngine()
    out: list[StoreSensitivity] = []
    try:
        pages = ssm_client.get_paginator("describe_parameters").paginate()
        params = [p for pg in pages for p in pg.get("Parameters", [])]
    except Exception as e:
        logger.info("DSPM ssm describe_parameters skipped: %s", e)
        return out

    for p in params:
        name = p.get("Name", "")
        is_secure = p.get("Type") == "SecureString"
        findings = []
        if read_values and is_secure:
            findings = _classify_ssm_value(ssm_client, name)
        if findings:
            sens, risk = eng.score_store(
                findings, exposure=0.3, controls_penalty=0.0, records=1)
            posture = []
        elif is_secure:
            risk, sens = eng.score_posture(exposure=0.3, controls_penalty=0.0, baseline=0.7), 0.7
            posture = ["SecureString value not read (use --read-secret-values)"]
        else:
            continue  # plain String params: skip unless they classify
        out.append(StoreSensitivity(
            store_id=f"ssm://{name}", store_name=name, store_type="SSMParameter",
            findings=findings, posture_findings=posture, exposure_score=0.3,
            sensitivity_score=sens, risk_score=risk))
    return out


def _classify_ssm_value(ssm_client, name: str):
    try:
        val = ssm_client.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    except Exception as e:
        logger.debug("get_parameter %s: %s", name, e)
        return []
    return classify(val, column=name, path=f"ssm/{name}")


# ── orchestrator ────────────────────────────────────────────────
def scan_data_stores(session, region: str, *,
                     read_secret_values: bool = False) -> list[StoreSensitivity]:
    """Run every feasible Sprint-1 scanner against a boto3 Session.

    Read-only. Each scanner is guarded; missing perms → that store skipped.
    Returns a combined list of StoreSensitivity (S3 handled separately by the
    caller via DspmEngine.scan_s3_inventory).
    """
    rds = session.client("rds", region_name=region)
    ec2 = session.client("ec2", region_name=region)
    ddb = session.client("dynamodb", region_name=region)
    sm = session.client("secretsmanager", region_name=region)
    ssm = session.client("ssm", region_name=region)

    stores: list[StoreSensitivity] = []
    stores += scan_rds_instances(rds)
    stores += scan_rds_snapshots(rds)
    stores += scan_ebs_snapshots(ec2)
    stores += scan_dynamodb(ddb)
    stores += scan_secrets(sm, read_values=read_secret_values)
    stores += scan_ssm_parameters(ssm, read_values=read_secret_values)
    return stores
