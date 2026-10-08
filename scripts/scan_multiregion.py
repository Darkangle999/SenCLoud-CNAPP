#!/usr/bin/env python3
"""Live multi-region inventory scan — the shadow-IT lens.

Read-only against the target AWS account. Discovers every enabled region (or a
list you pass), fans the collector across them, and prints the per-region asset
spread so resources in regions you didn't expect stand out. Optionally persists
through InventoryService.persist_scan.

Usage:
    python scripts/scan_multiregion.py                       # all enabled regions
    python scripts/scan_multiregion.py --regions us-east-1,eu-west-1
    python scripts/scan_multiregion.py --profile NAME --persist
"""

from __future__ import annotations

import argparse
import sys
import time

from odineyes.inventory.aws_raw_collector import AwsRawCollector
from odineyes.inventory.service import InventoryService


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--home", default="us-east-1", help="home region (STS + global services)")
    ap.add_argument("--regions", default=None, help="comma list to scope; omit = all enabled")
    ap.add_argument("--profile", default=None)
    ap.add_argument("--persist", action="store_true", help="write to the inventory store")
    ap.add_argument("--db", default=None, help="SQLAlchemy URL (default: env or sqlite file)")
    args = ap.parse_args()

    regions = [r.strip() for r in args.regions.split(",") if r.strip()] if args.regions else None
    collector = AwsRawCollector(region=args.home, profile=args.profile, regions=regions)

    account_id = collector.account_id()
    if account_id == "unknown":
        print("ERROR: could not resolve AWS account (check credentials).", file=sys.stderr)
        return 1

    swept = collector.resolve_regions()
    print(f"Account {account_id} — sweeping {len(swept)} region(s) (read-only):")
    print(f"  {', '.join(swept)}\n")

    t0 = time.time()
    resources = collector.collect()
    dt = time.time() - t0

    by_region: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for source_type, raw in resources:
        r = raw.get("Region", "global")
        by_region[r] = by_region.get(r, 0) + 1
        by_type[source_type] = by_type.get(source_type, 0) + 1

    print(f"Collected {len(resources)} raw resources in {dt:.1f}s\n")
    print("By region (shadow-IT lens — sparse/unexpected regions matter):")
    for r, n in sorted(by_region.items(), key=lambda kv: -kv[1]):
        bar = "#" * min(n, 40)
        print(f"  {r:<16} {n:>4}  {bar}")
    print("\nBy type:")
    for t, n in sorted(by_type.items()):
        print(f"  {t:<28} {n}")

    # Sanity: global services must not multiply across regions.
    for gt in ("aws.iam.role", "aws.s3.bucket"):
        n = by_type.get(gt, 0)
        regs = {raw.get("Region") for st, raw in resources if st == gt}
        flag = "  <-- LEAKED PER-REGION?" if len(swept) > 1 and len(regs) > 1 and "global" not in regs else ""
        print(f"\n  [check] {gt}: {n} item(s), region(s)={sorted(regs)}{flag}")

    if args.persist:
        service = InventoryService(database_url=args.db)
        result = service.persist_scan(
            provider="aws", account_identifier=account_id,
            resources=resources, scan_type="config",
        )
        print(
            f"\nScan job #{result.scan_job_id} [{result.status}]: "
            f"found={result.found} new={result.new} changed={result.changed} "
            f"deleted={result.deleted} reactivated={result.reactivated} errors={result.errors}"
        )
    else:
        print("\n(dry run — pass --persist to write to the inventory store)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
