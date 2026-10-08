#!/usr/bin/env python3
"""Live inventory scan: AwsRawCollector -> normalizers -> persisted inventory.

Read-only against the target AWS account. Collects EC2/SG/S3/IAM/RDS as native
dicts, runs them through InventoryService.persist_scan (normalize + upsert +
drift/soft-delete), and prints a summary.

Usage:
    python scripts/scan_inventory.py [--region us-east-1] [--profile NAME]
                                     [--db sqlite:///odineyes.db]
"""

from __future__ import annotations

import argparse
import sys

from odineyes.inventory.aws_raw_collector import AwsRawCollector
from odineyes.inventory.service import InventoryService


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--profile", default=None)
    ap.add_argument("--db", default=None, help="SQLAlchemy URL (default: env or sqlite file)")
    args = ap.parse_args()

    collector = AwsRawCollector(region=args.region, profile=args.profile)
    account_id = collector.account_id()
    if account_id == "unknown":
        print("ERROR: could not resolve AWS account (check credentials).", file=sys.stderr)
        return 1

    print(f"Scanning account {account_id} in {args.region} (read-only)...")
    resources = collector.collect()
    by_type: dict[str, int] = {}
    for source_type, _ in resources:
        by_type[source_type] = by_type.get(source_type, 0) + 1
    print(f"Collected {len(resources)} raw resources:")
    for t, n in sorted(by_type.items()):
        print(f"  {t:<28} {n}")

    service = InventoryService(database_url=args.db)
    result = service.persist_scan(
        provider="aws",
        account_identifier=account_id,
        resources=resources,
        scan_type="config",
    )
    print(
        f"\nScan job #{result.scan_job_id} [{result.status}]: "
        f"found={result.found} new={result.new} changed={result.changed} "
        f"deleted={result.deleted} reactivated={result.reactivated} errors={result.errors}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
