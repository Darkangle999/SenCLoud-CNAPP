#!/usr/bin/env python3
"""Odineyes red-team lab — deploy intentionally-vulnerable AWS resources,
verify the scanner detects them, then tear it all down.

    python scripts/redteam_lab.py deploy   [--with-rds] [--with-redshift] [--region us-east-1]
    python scripts/redteam_lab.py verify   [--region us-east-1] [--db sqlite:///lab.db]
    python scripts/redteam_lab.py destroy  [--region us-east-1]

╔══════════════════════════════════════════════════════════════════════════╗
║  SAFETY                                                                     ║
║  This creates REAL, internet-exposed, misconfigured resources: a public    ║
║  S3 bucket, an admin IAM role trusted by ANY AWS account, a security group ║
║  open to 0.0.0.0/0, a public EC2 box that can act as admin, a public       ║
║  Lambda URL, optionally a public unencrypted RDS / Redshift.               ║
║                                                                            ║
║  • Run ONLY in a throwaway / sandbox AWS account you own.                   ║
║  • Everything is tagged odineyes:lab=true and name-prefixed           ║
║    'odineyes-lab' / 'Odineyes-Lab-'. `destroy` removes it all.    ║
║  • Buckets hold one dummy object, no real data. No SSH key is created.      ║
║  • `deploy` requires you to type the account id to confirm.                 ║
║  • TEAR IT DOWN when done: `destroy`. Leaving it up is a real exposure.     ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import argparse
import json
import secrets
import string
import sys
import time

import boto3
from botocore.exceptions import ClientError

PREFIX = "odineyes-lab"           # taggable / S3 / EC2 name prefix
IAM_PREFIX = "Odineyes-Lab-"      # IAM role / profile prefix
TAG_KEY, TAG_VAL = "odineyes:lab", "true"
LAB_TAGS = [{"Key": TAG_KEY, "Value": TAG_VAL}]

ADMIN_ROLE = f"{IAM_PREFIX}AdminRole"        # name == instance-profile name (graph binds by name)
PRIVESC_ROLE = f"{IAM_PREFIX}PrivescRole"
LAMBDA_ROLE = f"{IAM_PREFIX}LambdaRole"
SG_NAME = f"{PREFIX}-open-sg"
LAMBDA_FN = f"{PREFIX}-public-fn"
RDS_ID = f"{PREFIX}-public-db"
REDSHIFT_ID = f"{PREFIX}-public-wh"


def _lab_db_password() -> str:
    """Use a fresh password for each disposable lab database."""
    return "Lab1" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20)) + "!"

# Each lab resource → the Odineyes rule_ids + issue_types it should trigger.
EXPECTED = {
    "public S3 bucket (sensitive name, unencrypted)": {
        "rules": ["PUBLIC_BUCKET"], "issues": ["PUBLIC_S3_EXPOSURE"]},
    "admin role, wildcard trust": {
        "rules": ["PUBLIC_ADMIN_ROLE"], "issues": ["CROSS_ACCOUNT_LATERAL"]},
    "privilege-escalation role": {
        "rules": [], "issues": ["IAM_PRIVILEGE_ESCALATION"]},
    "security group open to 0.0.0.0/0": {
        "rules": ["WORLD_OPEN_SENSITIVE_PORT"], "issues": []},
    "public EC2 with admin instance profile": {
        "rules": ["PUBLIC_COMPUTE"], "issues": ["PUBLIC_COMPUTE_TO_ADMIN"]},
    "public Lambda function URL": {
        "rules": ["PUBLIC_LAMBDA_URL"], "issues": []},
}
EXPECTED_RDS = {"public unencrypted RDS": {
    "rules": ["PUBLIC_UNENCRYPTED_DB"], "issues": ["PUBLIC_DATABASE_PATH"]}}
EXPECTED_REDSHIFT = {"public unencrypted Redshift": {
    "rules": ["PUBLIC_WAREHOUSE"], "issues": []}}


def _c(region):
    s = boto3.Session(region_name=region)
    return {
        "sts": s.client("sts"), "s3": s.client("s3"), "iam": s.client("iam"),
        "ec2": s.client("ec2"), "ssm": s.client("ssm"), "lam": s.client("lambda"),
        "rds": s.client("rds"), "redshift": s.client("redshift"),
    }


def _account(c) -> str:
    return c["sts"].get_caller_identity()["Account"]


def _swallow(fn, *codes):
    """Run fn(); ignore the named ClientError codes (idempotent create / destroy)."""
    try:
        return fn()
    except ClientError as e:
        if e.response["Error"]["Code"] in codes:
            return None
        raise


# ── DEPLOY ──────────────────────────────────────────────────────

def deploy(region, with_rds, with_redshift):
    c = _c(region)
    acct = _account(c)
    print(f"\n  Target account: {acct}   region: {region}")
    print("  About to create REAL internet-exposed vulnerable resources here.")
    typed = input(f"  Type the account id ({acct}) to proceed: ").strip()
    if typed != acct:
        print("  Aborted — account id mismatch.")
        return

    _deploy_bucket(c, acct)
    _deploy_admin_role(c)
    _deploy_privesc_role(c)
    sg_id = _deploy_sg(c)
    _deploy_ec2(c, region, sg_id)
    _deploy_lambda(c, acct, region)
    if with_rds:
        _deploy_rds(c)
    if with_redshift:
        _deploy_redshift(c)

    print("\n  Deploy complete. Wait ~2-3 min for EC2/RDS to settle, then:")
    print("    python scripts/redteam_lab.py verify --region", region)
    print("  TEAR DOWN when done:  python scripts/redteam_lab.py destroy --region", region)


def _deploy_bucket(c, acct):
    name = f"{PREFIX}-customer-data-{acct}"
    print(f"  [s3]      public sensitive bucket  {name}")
    _swallow(lambda: c["s3"].create_bucket(Bucket=name), "BucketAlreadyOwnedByYou", "BucketAlreadyExists")
    c["s3"].put_bucket_tagging(Bucket=name, Tagging={"TagSet": LAB_TAGS})
    # turn OFF every public-access guard, then attach a public-read policy
    c["s3"].put_public_access_block(Bucket=name, PublicAccessBlockConfiguration={
        "BlockPublicAcls": False, "IgnorePublicAcls": False,
        "BlockPublicPolicy": False, "RestrictPublicBuckets": False})
    c["s3"].put_bucket_policy(Bucket=name, Policy=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
            "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{name}/*"}]}))
    c["s3"].put_object(Bucket=name, Key="dummy.txt", Body=b"lab placeholder - no real data")


def _deploy_admin_role(c):
    print(f"  [iam]     admin role + instance profile  {ADMIN_ROLE}")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"},
        {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}  # wildcard = public
    _swallow(lambda: c["iam"].create_role(
        RoleName=ADMIN_ROLE, AssumeRolePolicyDocument=json.dumps(trust), Tags=LAB_TAGS),
        "EntityAlreadyExists")
    _swallow(lambda: c["iam"].attach_role_policy(
        RoleName=ADMIN_ROLE, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"),
        "NoSuchEntity")
    # instance profile name == role name so the graph binds EC2 → role
    _swallow(lambda: c["iam"].create_instance_profile(
        InstanceProfileName=ADMIN_ROLE, Tags=LAB_TAGS), "EntityAlreadyExists")
    _swallow(lambda: c["iam"].add_role_to_instance_profile(
        InstanceProfileName=ADMIN_ROLE, RoleName=ADMIN_ROLE), "LimitExceeded")


def _deploy_privesc_role(c):
    print(f"  [iam]     privesc role  {PRIVESC_ROLE}")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    _swallow(lambda: c["iam"].create_role(
        RoleName=PRIVESC_ROLE, AssumeRolePolicyDocument=json.dumps(trust), Tags=LAB_TAGS),
        "EntityAlreadyExists")
    c["iam"].put_role_policy(RoleName=PRIVESC_ROLE, PolicyName="escalate", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": [
            "iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:CreatePolicyVersion"],
            "Resource": "*"}]}))


def _deploy_sg(c):
    vpc = c["ec2"].describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"][0]["VpcId"]
    existing = c["ec2"].describe_security_groups(
        Filters=[{"Name": "group-name", "Values": [SG_NAME]}])["SecurityGroups"]
    if existing:
        sg_id = existing[0]["GroupId"]
    else:
        sg_id = c["ec2"].create_security_group(
            GroupName=SG_NAME, Description="odineyes lab - intentionally open", VpcId=vpc,
            TagSpecifications=[{"ResourceType": "security-group", "Tags": LAB_TAGS}])["GroupId"]
    print(f"  [ec2]     security group open to world  {sg_id}")
    for port in (22, 3389, 3306):
        _swallow(lambda p=port: c["ec2"].authorize_security_group_ingress(
            GroupId=sg_id, IpPermissions=[{"IpProtocol": "tcp", "FromPort": p, "ToPort": p,
                                           "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]),
            "InvalidPermission.Duplicate")
    return sg_id


def _deploy_ec2(c, region, sg_id):
    if c["ec2"].describe_instances(Filters=[
            {"Name": "tag:" + TAG_KEY, "Values": [TAG_VAL]},
            {"Name": "instance-state-name", "Values": ["pending", "running"]}])["Reservations"]:
        print("  [ec2]     instance already running, skipping")
        return
    ami = c["ssm"].get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")["Parameter"]["Value"]
    print(f"  [ec2]     public t3.micro w/ admin profile  (ami {ami})")
    c["ec2"].run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        IamInstanceProfile={"Name": ADMIN_ROLE},
        NetworkInterfaces=[{"DeviceIndex": 0, "AssociatePublicIpAddress": True,
                            "Groups": [sg_id], "DeleteOnTermination": True}],
        TagSpecifications=[{"ResourceType": "instance",
                            "Tags": LAB_TAGS + [{"Key": "Name", "Value": f"{PREFIX}-public-box"}]}])


def _deploy_lambda(c, acct, region):
    print(f"  [lambda]  public function URL  {LAMBDA_FN}")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    _swallow(lambda: c["iam"].create_role(
        RoleName=LAMBDA_ROLE, AssumeRolePolicyDocument=json.dumps(trust), Tags=LAB_TAGS),
        "EntityAlreadyExists")
    _swallow(lambda: c["iam"].attach_role_policy(
        RoleName=LAMBDA_ROLE,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"), "NoSuchEntity")
    time.sleep(8)  # let the new role propagate before Lambda assumes it
    code = b"def handler(e,c):\n    return {'statusCode':200,'body':'lab'}\n"
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.py", code.decode())
    _swallow(lambda: c["lam"].create_function(
        FunctionName=LAMBDA_FN, Runtime="python3.12", Role=f"arn:aws:iam::{acct}:role/{LAMBDA_ROLE}",
        Handler="index.handler", Code={"ZipFile": buf.getvalue()}, Tags={TAG_KEY: TAG_VAL}),
        "ResourceConflictException")
    _swallow(lambda: c["lam"].create_function_url_config(
        FunctionName=LAMBDA_FN, AuthType="NONE"), "ResourceConflictException")  # NONE = unauthenticated
    _swallow(lambda: c["lam"].add_permission(
        FunctionName=LAMBDA_FN, StatementId="public-url", Action="lambda:InvokeFunctionUrl",
        Principal="*", FunctionUrlAuthType="NONE"), "ResourceConflictException")


def _deploy_rds(c):
    print(f"  [rds]     public unencrypted postgres  {RDS_ID}  (costs $)")
    _swallow(lambda: c["rds"].create_db_instance(
        DBInstanceIdentifier=RDS_ID, DBInstanceClass="db.t3.micro", Engine="postgres",
        MasterUsername="labadmin", MasterUserPassword=_lab_db_password(),
        AllocatedStorage=20, PubliclyAccessible=True, StorageEncrypted=False,
        BackupRetentionPeriod=0, Tags=LAB_TAGS), "DBInstanceAlreadyExists")


def _deploy_redshift(c):
    print(f"  [redshift] public unencrypted cluster  {REDSHIFT_ID}  (costs $$)")
    _swallow(lambda: c["redshift"].create_cluster(
        ClusterIdentifier=REDSHIFT_ID, NodeType="dc2.large", ClusterType="single-node",
        MasterUsername="labadmin", MasterUserPassword=_lab_db_password(),
        PubliclyAccessible=True, Encrypted=False, Tags=LAB_TAGS), "ClusterAlreadyExists")


# ── VERIFY (the real test) ──────────────────────────────────────

def verify(region, db_url):
    """Scan the live account with Odineyes, then assert each planted vuln
    was detected. Prints a coverage matrix and exits non-zero on any miss."""
    sys.path.insert(0, "src")
    import os
    os.environ.setdefault("ODINEYES_DATABASE_URL", db_url)
    from odineyes.inventory.aws_raw_collector import AwsRawCollector
    from odineyes.inventory.service import InventoryService
    from odineyes.db.base import session_scope
    from odineyes.inventory import queries

    c = _c(region)
    acct = _account(c)
    print(f"\n  Scanning account {acct} ({region}) with Odineyes…")
    svc = InventoryService(database_url=db_url)
    resources = AwsRawCollector(region=region).collect()
    scan = svc.persist_scan("aws", acct, resources)
    f = svc.evaluate_findings("aws", acct)
    i = svc.evaluate_issues("aws", acct)
    print(f"  Inventory: {scan.found} assets · findings: {f.total} · attack paths: {i.total}")

    with session_scope(db_url) as s:
        from odineyes.db.models import CloudAccount
        acc = s.query(CloudAccount).filter_by(provider="aws", account_identifier=acct).one()
        found_rules = {x["rule_id"] for x in queries.list_findings(s, account_id=acc.id, status="open")["items"]}
        found_issues = {x["issue_type"] for x in queries.list_issues(s, account_id=acc.id, status="open")["items"]}

    # Expand expected set only for the optional resources that actually exist.
    # Any ClientError on the probe (NotFound, OptInRequired, AccessDenied, …)
    # means "not deployed / not available here" — skip the expectation.
    def _exists(fn) -> bool:
        try:
            return fn() is not None
        except ClientError:
            return False

    expected = dict(EXPECTED)
    if _exists(lambda: c["rds"].describe_db_instances(DBInstanceIdentifier=RDS_ID)):
        expected |= EXPECTED_RDS
    if _exists(lambda: c["redshift"].describe_clusters(ClusterIdentifier=REDSHIFT_ID)):
        expected |= EXPECTED_REDSHIFT

    print("\n  ── Detection coverage ───────────────────────────────────────")
    misses = 0
    for label, exp in expected.items():
        want = [("rule", r) for r in exp["rules"]] + [("issue", t) for t in exp["issues"]]
        marks = []
        for kind, name in want:
            hit = name in (found_rules if kind == "rule" else found_issues)
            misses += 0 if hit else 1
            marks.append(f"{'✓' if hit else '✗'} {name}")
        print(f"   {'PASS' if all('✓' in m for m in marks) else 'MISS'}  {label}")
        for m in marks:
            print(f"          {m}")
    total = sum(len(e["rules"]) + len(e["issues"]) for e in expected.values())
    print("  ─────────────────────────────────────────────────────────────")
    print(f"   {total - misses}/{total} expected detections fired"
          + (f"   ⚠ {misses} MISSED" if misses else "   ✅ full coverage"))
    sys.exit(1 if misses else 0)


# ── DESTROY ─────────────────────────────────────────────────────

def destroy(region):
    c = _c(region)
    print(f"\n  Tearing down lab in {region}…")
    # Each step is isolated: a failure in one (e.g. an opt-in service the account
    # isn't subscribed to) must never abort the rest and strand exposed resources.
    failures = []
    for step in (_destroy_ec2, _destroy_lambda, _destroy_rds, _destroy_redshift,
                 _destroy_sg, _destroy_iam, _destroy_buckets):   # SG/IAM/buckets after instance
        try:
            step(c)
        except Exception as e:  # noqa: BLE001 — best-effort cleanup, keep going
            failures.append(f"{step.__name__}: {e}")
            print(f"  [warn]    {step.__name__} failed, continuing: {e}")
    if failures:
        print(f"\n  Teardown finished with {len(failures)} non-fatal error(s):")
        for f in failures:
            print("   -", f)
        print("  Re-run `destroy` to retry; resources are idempotent.")
    else:
        print("  Teardown complete.")


def _destroy_ec2(c):
    ids = [i["InstanceId"] for r in c["ec2"].describe_instances(Filters=[
        {"Name": "tag:" + TAG_KEY, "Values": [TAG_VAL]},
        {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}
    ])["Reservations"] for i in r["Instances"]]
    if not ids:
        return
    print(f"  [ec2]     terminating {ids}")
    c["ec2"].terminate_instances(InstanceIds=ids)
    c["ec2"].get_waiter("instance_terminated").wait(InstanceIds=ids)


def _destroy_sg(c):
    for sg in c["ec2"].describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [SG_NAME]}])["SecurityGroups"]:
        print(f"  [ec2]     deleting SG {sg['GroupId']}")
        _swallow(lambda g=sg: c["ec2"].delete_security_group(GroupId=g["GroupId"]), "DependencyViolation")


def _destroy_iam(c):
    # instance profile first (detach role), then roles (detach/delete policies)
    _swallow(lambda: c["iam"].remove_role_from_instance_profile(
        InstanceProfileName=ADMIN_ROLE, RoleName=ADMIN_ROLE), "NoSuchEntity")
    _swallow(lambda: c["iam"].delete_instance_profile(InstanceProfileName=ADMIN_ROLE), "NoSuchEntity")
    for role in (ADMIN_ROLE, PRIVESC_ROLE, LAMBDA_ROLE):
        attached = _swallow(lambda r=role: c["iam"].list_attached_role_policies(
            RoleName=r)["AttachedPolicies"], "NoSuchEntity") or []
        for p in attached:
            c["iam"].detach_role_policy(RoleName=role, PolicyArn=p["PolicyArn"])
        inline = _swallow(lambda r=role: c["iam"].list_role_policies(RoleName=r)["PolicyNames"], "NoSuchEntity") or []
        for pn in inline:
            c["iam"].delete_role_policy(RoleName=role, PolicyName=pn)
        if _swallow(lambda r=role: c["iam"].delete_role(RoleName=r), "NoSuchEntity") is not None:
            print(f"  [iam]     deleted role {role}")


def _destroy_lambda(c):
    _swallow(lambda: c["lam"].delete_function_url_config(FunctionName=LAMBDA_FN), "ResourceNotFoundException")
    if _swallow(lambda: c["lam"].delete_function(FunctionName=LAMBDA_FN), "ResourceNotFoundException") is not None:
        print(f"  [lambda]  deleted {LAMBDA_FN}")


def _destroy_rds(c):
    if _swallow(lambda: c["rds"].delete_db_instance(
            DBInstanceIdentifier=RDS_ID, SkipFinalSnapshot=True, DeleteAutomatedBackups=True),
            "DBInstanceNotFound", "InvalidDBInstanceState", "OptInRequired") is not None:
        print(f"  [rds]     deleting {RDS_ID}")


def _destroy_redshift(c):
    if _swallow(lambda: c["redshift"].delete_cluster(
            ClusterIdentifier=REDSHIFT_ID, SkipFinalClusterSnapshot=True),
            "ClusterNotFound", "InvalidClusterState", "OptInRequired") is not None:
        print(f"  [redshift] deleting {REDSHIFT_ID}")


def _destroy_buckets(c):
    for b in c["s3"].list_buckets()["Buckets"]:
        name = b["Name"]
        if not name.startswith(f"{PREFIX}-customer-data-"):
            continue
        print(f"  [s3]      emptying + deleting {name}")
        try:
            objs = c["s3"].list_objects_v2(Bucket=name).get("Contents", [])
            if objs:
                c["s3"].delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
            c["s3"].delete_bucket(Bucket=name)
        except ClientError as e:
            print(f"            skip {name}: {e.response['Error']['Code']}")


# ── CLI ─────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Odineyes red-team lab")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("deploy"); d.add_argument("--with-rds", action="store_true")
    d.add_argument("--with-redshift", action="store_true"); d.add_argument("--region", default="us-east-1")
    v = sub.add_parser("verify"); v.add_argument("--region", default="us-east-1")
    v.add_argument("--db", default="sqlite:///lab.db")
    x = sub.add_parser("destroy"); x.add_argument("--region", default="us-east-1")
    a = ap.parse_args()
    if a.cmd == "deploy":
        deploy(a.region, a.with_rds, a.with_redshift)
    elif a.cmd == "verify":
        verify(a.region, a.db)
    elif a.cmd == "destroy":
        destroy(a.region)


if __name__ == "__main__":
    main()
