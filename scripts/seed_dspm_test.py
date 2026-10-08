#!/usr/bin/env python3
"""
DSPM live smoke-test harness — one command to verify the DSPM engine against
real AWS, safely.

Creates a PRIVATE throwaway S3 bucket, uploads a SYNTHETIC-PII CSV (fake but
Luhn-valid cards / fake SSNs — no real data), runs DspmEngine.scan_bucket, prints
the verdict, then tears everything down. Net-zero account change.

Usage:
    python scripts/seed_dspm_test.py                 # seed → scan → teardown
    python scripts/seed_dspm_test.py --keep          # leave bucket up
    python scripts/seed_dspm_test.py --teardown BKT  # delete a left-up bucket
    python scripts/seed_dspm_test.py --region us-west-2 --encrypt

Safety: bucket is always private (public access block ON). Data is synthetic.
The DSPM scanner itself is read-only; this harness performs the only writes.
"""
from __future__ import annotations

import argparse
import json
import sys
import time

# Synthetic rows. Cards are Luhn-valid test numbers; SSNs/emails are fake.
SYNTHETIC_CSV = """name,ssn,card_number,email
John Smith,123-45-6789,4532015112830366,john@example.com
Jane Roe,213-45-6780,5500005555555559,jane@example.com
Bob Lee,321-54-9870,340000000000009,bob@example.com
Amy Tan,412-34-5678,6011000000000004,amy@example.com
Sam Fox,512-34-5670,4111111111111111,sam@example.com
"""
KEY = "exports/customers.csv"


def _client(region: str):
    import boto3
    return boto3.client("s3", region_name=region)


def _create_private_bucket(s3, bucket: str, region: str, encrypt: bool) -> None:
    kw = {"Bucket": bucket}
    if region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kw)
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    if encrypt:
        s3.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={"Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})


def teardown(bucket: str, region: str) -> None:
    s3 = _client(region)
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)
        print(f"[teardown] deleted bucket {bucket} (+{len(objs)} objects)")
    except Exception as e:
        print(f"[teardown] failed for {bucket}: {e}", file=sys.stderr)


def run(region: str, keep: bool, encrypt: bool) -> int:
    from odineyes.dspm.engine import DspmEngine

    bucket = f"odineyes-dspm-test-{int(time.time())}"
    s3 = _client(region)

    print(f"[seed] creating private bucket {bucket} (region={region}, "
          f"encrypted={encrypt})")
    _create_private_bucket(s3, bucket, region, encrypt)
    s3.put_object(Bucket=bucket, Key=KEY, Body=SYNTHETIC_CSV.encode())
    print(f"[seed] uploaded synthetic PII → s3://{bucket}/{KEY}")

    try:
        print("[scan] running DspmEngine.scan_bucket …")
        store = DspmEngine().scan_bucket(
            s3, bucket, is_public=False, encrypted=encrypt, region=region)
        d = store.to_dict()
        print(json.dumps(d, indent=2))

        # Assertions — the smoke test passes only if it found the seeded PII.
        types = set(d["pii_types"])
        ok = {"SSN", "CREDIT_CARD"} <= types and d["objects_sampled"] >= 1
        card = next((f for f in d["findings"] if f["type"] == "CREDIT_CARD"), None)
        ok = ok and card is not None and card["validated"]
        print(f"\n[result] {'PASS' if ok else 'FAIL'} — "
              f"label={d['label']} risk={d['risk_score']} types={sorted(types)}")
        rc = 0 if ok else 1
    finally:
        if keep:
            print(f"[keep] bucket left up: {bucket} "
                  f"(delete with: python scripts/seed_dspm_test.py --teardown {bucket})")
        else:
            teardown(bucket, region)
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description="DSPM live smoke test (synthetic PII).")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--keep", action="store_true", help="leave the bucket up")
    ap.add_argument("--encrypt", action="store_true",
                    help="enable SSE-S3 default encryption (lower risk score)")
    ap.add_argument("--teardown", metavar="BUCKET",
                    help="delete a previously-kept bucket and exit")
    args = ap.parse_args()

    if args.teardown:
        teardown(args.teardown, args.region)
        return 0
    return run(args.region, args.keep, args.encrypt)


if __name__ == "__main__":
    sys.exit(main())
