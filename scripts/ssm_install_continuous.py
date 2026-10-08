#!/usr/bin/env python3
"""Install the Odineyes eBPF sensor as a *continuous* systemd service on a
running EC2 instance over SSM (no inbound access required).

On the instance it sets up:
  - odineyes-sensor.service   — eBPF sensor, runs forever, Restart=always,
                                      spools real events to /var/lib/odineyes/spool.jsonl
  - odineyes-shipper.service  — ships new spool bytes to S3 (incremental)
  - odineyes-shipper.timer    — fires the shipper every 60s

The local side is the drain daemon (scripts/s3_ingest_daemon.py), which pulls
the S3 queue into the API. Sensor + S3 buffer keep running regardless of
whether the dashboard is up.

  python scripts/ssm_install_continuous.py \
    --instance-id i-0bc1b63d0cf3206a3 \
    --bucket odineyes-lab-customer-data-123456789012 \
    --node lab-ec2
"""
from __future__ import annotations

import argparse
import base64
import pathlib
import sys
import time

import boto3

ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENT = ROOT / "src" / "odineyes" / "sensor" / "ebpf_agent.py"
EC2 = ROOT / "deploy" / "ec2"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def write_file_cmd(path: str, content: bytes, mode: str | None = None) -> str:
    enc = b64(content)
    cmd = (
        f"mkdir -p $(dirname {path}) && "
        f"echo '{enc}' | base64 -d > {path}"
    )
    if mode:
        cmd += f" && chmod {mode} {path}"
    return cmd


def run_ssm(ssm, instance_id: str, commands: list[str], timeout: int = 600) -> tuple[str, str]:
    cid = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        TimeoutSeconds=timeout,
        Parameters={"commands": commands},
    )["Command"]["CommandId"]
    while True:
        time.sleep(5)
        try:
            inv = ssm.get_command_invocation(CommandId=cid, InstanceId=instance_id)
        except ssm.exceptions.InvocationDoesNotExist:
            continue
        if inv["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            return inv["Status"], inv["StandardOutputContent"] + inv["StandardErrorContent"]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--instance-id", required=True)
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--bucket", required=True)
    ap.add_argument("--node", default=None, help="event node label (default: instance-id)")
    ap.add_argument("--prefix", default=None, help="S3 prefix (default: ebpf/<node>)")
    args = ap.parse_args()

    node = args.node or args.instance_id
    prefix = (args.prefix or f"ebpf/{node}").rstrip("/")

    sensor_unit = (EC2 / "odineyes-sensor.service").read_text().replace("@NODE@", node)
    shipper_unit = (EC2 / "odineyes-shipper.service").read_text()
    timer_unit = (EC2 / "odineyes-shipper.timer").read_text()
    ship_sh = (EC2 / "cs-ship.sh").read_bytes()
    ship_env = (
        "SPOOL=/var/lib/odineyes/spool.jsonl\n"
        "OFFSET=/var/lib/odineyes/.offset\n"
        f"BUCKET={args.bucket}\n"
        f"PREFIX={prefix}\n"
        f"AWS_REGION={args.region}\n"
    )

    commands = [
        "set -e",
        # deps (idempotent)
        "dnf install -y python3-bcc bcc kernel-devel-$(uname -r) "
        "|| dnf install -y python3-bcc bcc kernel-devel",
        "python3 -c 'import bcc' || { echo 'bcc import failed'; exit 1; }",
        "[ -f /sys/kernel/btf/vmlinux ] || { echo 'no kernel BTF'; exit 1; }",
        # files
        write_file_cmd("/opt/odineyes/ebpf_agent.py", AGENT.read_bytes()),
        write_file_cmd("/usr/local/bin/cs-ship.sh", ship_sh, mode="755"),
        write_file_cmd("/etc/odineyes/ship.env", ship_env.encode()),
        write_file_cmd("/etc/systemd/system/odineyes-sensor.service", sensor_unit.encode()),
        write_file_cmd("/etc/systemd/system/odineyes-shipper.service", shipper_unit.encode()),
        write_file_cmd("/etc/systemd/system/odineyes-shipper.timer", timer_unit.encode()),
        "mkdir -p /var/lib/odineyes",
        # start
        "systemctl daemon-reload",
        "systemctl enable odineyes-sensor.service",
        "systemctl enable odineyes-shipper.timer",
        # restart (not just start) so a redeploy reloads the new agent code
        "systemctl restart odineyes-sensor.service",
        "systemctl start odineyes-shipper.timer",
        "sleep 3",
        "echo '=== sensor ==='; systemctl is-active odineyes-sensor.service",
        "echo '=== timer ==='; systemctl is-active odineyes-shipper.timer",
        "echo '=== sensor log ==='; journalctl -u odineyes-sensor.service -n 8 --no-pager 2>&1 || true",
    ]

    ssm = boto3.Session(region_name=args.region).client("ssm")
    print(f"installing continuous sensor on {args.instance_id} (node={node}, "
          f"queue=s3://{args.bucket}/{prefix}/) …")
    status, out = run_ssm(ssm, args.instance_id, commands, timeout=900)
    print(out.strip())
    print(f"\nSSM status: {status}")
    if status != "Success":
        sys.exit(1)
    print(
        "\nsensor is live and continuous. start the local collector:\n"
        f"  python scripts/s3_ingest_daemon.py --bucket {args.bucket} "
        f"--prefix ebpf/ --region {args.region} --interval 30\n"
        "events surface on http://localhost:5173/threats"
    )


if __name__ == "__main__":
    main()
