"""Shared collection completeness contract.

A CSPM scan is often partial: one AWS API may be denied while every other API
succeeds.  Callers must distinguish "the service returned no resources" from
"the service could not be inspected" before retiring inventory rows.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# ``region=None`` means the operation is authoritative for every region (for
# example S3 list_buckets, Azure storage_accounts.list, or GCP list_buckets).
CollectionScope = tuple[str, Optional[str]]


@dataclass(frozen=True)
class CollectionError:
    source_type: str
    operation: str
    message: str
    region: Optional[str] = None

    def scan_message(self) -> str:
        where = self.region or "all regions"
        return f"{self.operation} ({where}): {self.message}"
