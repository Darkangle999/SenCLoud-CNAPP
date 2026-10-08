#!/usr/bin/env python3
"""Drain the eBPF S3 spool queue into the local Odineyes API.

The EC2 sensor spools real kernel events to S3 (one object per shipper run,
under a per-node prefix). This daemon is the collector side: it lists the
prefix, downloads each object, POSTs every JSON line to the API ingest
endpoint, then deletes the object (S3 prefix == at-least-once queue).

Because the buffer lives in S3, the sensor keeps running and accumulating even
while this collector (and the dashboard) are offline; events drain in when it
next runs. Run it as a loop (default) or once (--once) from cron.

  python scripts/s3_ingest_daemon.py \
    --bucket odineyes-lab-customer-data-123456789012 \
    --prefix ebpf/ --interval 30
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import urllib.request

import boto3


def ingest_line(api_url: str, line: str) -> bool:
    req = urllib.request.Request(
        f"{api_url}/api/internal/runtime-events",
        data=line.encode(),
        headers={"Content-Type": "application/json", "X-Tenant-ID": "default"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=5).read()
    return True


def drain_once(s3, bucket: str, prefix: str, api_url: str) -> tuple[int, int]:
    objects = 0
    events = 0
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(".jsonl"):
                continue
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode()
            n = 0
            for line in body.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ingest_line(api_url, line)
                    n += 1
                except Exception as e:  # noqa: BLE001
                    sys.stderr.write(f"ingest failed ({key}): {e}\n")
            # Delete only after the whole object ingested (at-least-once).
            s3.delete_object(Bucket=bucket, Key=key)
            objects += 1
            events += n
    return objects, events


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bucket", required=True)
    ap.add_argument("--prefix", default="ebpf/")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--api-url", default=os.environ.get("ODINEYES_API", "http://localhost:8000"))
    ap.add_argument("--interval", type=float, default=30, help="seconds between polls")
    ap.add_argument("--once", action="store_true", help="drain once and exit")
    args = ap.parse_args()

    s3 = boto3.Session(region_name=args.region).client("s3")
    print(f"draining s3://{args.bucket}/{args.prefix} -> {args.api_url} "
          f"({'once' if args.once else f'every {args.interval:.0f}s'})")
    while True:
        try:
            objs, evs = drain_once(s3, args.bucket, args.prefix, args.api_url)
            if objs:
                print(f"  drained {objs} object(s), {evs} event(s)")
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"poll error: {e}\n")
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
