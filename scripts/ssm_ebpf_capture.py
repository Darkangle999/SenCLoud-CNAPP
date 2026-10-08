#!/usr/bin/env python3
"""Deploy the Odineyes eBPF sensor onto a running EC2 instance over SSM,
capture real kernel security events for a bounded window, and ingest them into
a local Odineyes API so they surface on the Threats page.

eBPF is host-level: it must run *on* the workload, not against an AWS account.
This is the bridge — no inbound access to the instance is required (SSM only),
and the API does not need to be reachable from the instance (events come back
via S3, not a network POST from the host).

Flow:
  1. SSM: install python3-bcc + matching kernel-devel (idempotent).
  2. SSM: push the sensor (base64), run `--duration N --output <file>` as root,
     optionally generate benign activity so the classifiers have something to
     see on an otherwise-idle box.
  3. SSM: upload the JSON-lines capture to S3 (instance profile creds).
  4. Local: download from S3 and POST each event to the API ingest endpoint.

Prereqs: instance is SSM-managed (Online), caller can SendCommand + read the
S3 bucket, and the instance profile can write the bucket.

SAFETY: --activity runs benign-but-suspicious-looking commands (reads
/etc/shadow, attempts outbound connects to documentation IPs) ONLY to exercise
detections in a lab. Do not point --activity at production hosts.
"""
from __future__ import annotations

import argparse
import base64
import os
import pathlib
import sys
import time
import urllib.request

import boto3

AGENT = pathlib.Path(__file__).resolve().parent.parent / "src" / "odineyes" / "sensor" / "ebpf_agent.py"

# Benign activity to trip the classifiers on an idle lab host. Connects target
# documentation/test IPs on C2-ish ports; nothing actually listens.
ACTIVITY = (
    "cat /etc/shadow >/dev/null 2>&1; "
    "bash -c 'cat /etc/shadow >/dev/null 2>&1; sudo -n id >/dev/null 2>&1'; "
    "sudo -n true 2>/dev/null; "
    "timeout 2 bash -c 'cat </dev/tcp/45.33.32.156/4444' 2>/dev/null; "
    "timeout 2 bash -c 'exec 3<>/dev/tcp/8.8.8.8/9001' 2>/dev/null; "
    "sh -c 'id >/dev/null 2>&1'"
)


def run_ssm(ssm, instance_id: str, commands: list[str], timeout: int = 600) -> str:
    cmd = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        TimeoutSeconds=timeout,
        Parameters={"commands": commands},
    )["Command"]["CommandId"]
    while True:
        time.sleep(5)
        try:
            inv = ssm.get_command_invocation(CommandId=cmd, InstanceId=instance_id)
        except ssm.exceptions.InvocationDoesNotExist:
            continue
        if inv["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            if inv["Status"] != "Success":
                sys.stderr.write(inv.get("StandardErrorContent", "") + "\n")
            return inv["StandardOutputContent"]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--instance-id", required=True)
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--bucket", required=True, help="S3 bucket to relay the capture through")
    ap.add_argument("--key", default="ebpf/ev.jsonl")
    ap.add_argument("--duration", type=float, default=30, help="capture window seconds")
    ap.add_argument("--node", default=None, help="node label on events (default: instance-id)")
    ap.add_argument("--api-url", default=os.environ.get("ODINEYES_API", "http://localhost:8000"))
    ap.add_argument("--activity", action="store_true", help="generate benign activity (LAB ONLY)")
    ap.add_argument("--skip-install", action="store_true", help="assume bcc already installed")
    args = ap.parse_args()

    node = args.node or args.instance_id
    session = boto3.Session(region_name=args.region)
    ssm = session.client("ssm")

    if not args.skip_install:
        print("[1/4] installing bcc + kernel-devel via SSM …")
        out = run_ssm(ssm, args.instance_id, [
            "set +e",
            "dnf install -y python3-bcc bcc kernel-devel-$(uname -r) "
            "|| dnf install -y python3-bcc bcc kernel-devel",
            "python3 -c 'import bcc; print(\"bcc\", bcc.__version__)'",
        ])
        print(out.strip())

    print(f"[2/4] shipping sensor + capturing {args.duration:.0f}s on {node} …")
    b64 = base64.b64encode(AGENT.read_bytes()).decode()
    activity = ACTIVITY if args.activity else "true"
    script = "\n".join([
        "set +e",
        f"cat > /tmp/agent.b64 <<'B64EOF'\n{b64}\nB64EOF",
        "base64 -d /tmp/agent.b64 > /tmp/cs_agent.py",
        "rm -f /tmp/cs_ev.jsonl",
        f"nohup python3 /tmp/cs_agent.py --output /tmp/cs_ev.jsonl "
        f"--duration {args.duration:.0f} --node {node} >/tmp/cs_sensor.log 2>&1 &",
        "SPID=$!",
        "sleep 7",
        activity,
        f"sleep {max(0, int(args.duration) - 7)}",
        "wait $SPID 2>/dev/null",
        f"aws s3 cp /tmp/cs_ev.jsonl s3://{args.bucket}/{args.key} --region {args.region}",
        "wc -l /tmp/cs_ev.jsonl",
    ])
    out = run_ssm(ssm, args.instance_id, [script], timeout=int(args.duration) + 180)
    print(out.strip())

    print("[3/4] downloading capture from S3 …")
    body = session.client("s3").get_object(Bucket=args.bucket, Key=args.key)["Body"].read().decode()

    print("[4/4] ingesting into", args.api_url, "…")
    ok = fail = 0
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            req = urllib.request.Request(
                f"{args.api_url}/api/internal/runtime-events",
                data=line.encode(),
                headers={"Content-Type": "application/json", "X-Tenant-ID": "default"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5).read()
            ok += 1
        except Exception as e:  # noqa: BLE001
            fail += 1
            print("  ingest failed:", e)
    print(f"done — ingested {ok} real eBPF events ({fail} failed). View on /threats.")


if __name__ == "__main__":
    main()
