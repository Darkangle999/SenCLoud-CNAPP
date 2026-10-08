"""The unified asset contract.

Every normalizer, regardless of resource type, produces a ``NormalizedAsset``
with the same standard fields. Type-specific data lives in ``properties``. The
standard fields are what the Phase 2 rules engine queries against, so they must
stay consistent across all resource types.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

NetworkExposure = str  # "private" | "vpc" | "public" (public requires path evidence)


@dataclass
class NormalizedAsset:
    resource_id: str
    cloud_provider: str            # aws | azure | gcp
    account_identifier: str        # AWS account id / Azure sub / GCP project
    asset_type: str                # e.g. aws.s3.bucket
    name: Optional[str] = None
    region: str = "global"
    tags: dict[str, Any] = field(default_factory=dict)
    is_public: bool = False
    encryption_enabled: Optional[bool] = None
    network_exposure: NetworkExposure = "private"
    properties: dict[str, Any] = field(default_factory=dict)
    relationships: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    resource_created_at: Optional[datetime] = None

    def normalized_dict(self) -> dict[str, Any]:
        """Canonical normalized projection used for storage and drift compares.

        Excludes the raw payload and scan-time metadata so re-scanning an
        unchanged resource compares equal (idempotency + honest drift signal).
        """
        return {
            "resource_id": self.resource_id,
            "cloud_provider": self.cloud_provider,
            "asset_type": self.asset_type,
            "name": self.name,
            "region": self.region,
            "tags": self.tags,
            "is_public": self.is_public,
            "encryption_enabled": self.encryption_enabled,
            "network_exposure": self.network_exposure,
            "properties": self.properties,
            "relationships": self.relationships,
        }
