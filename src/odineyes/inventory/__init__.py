"""Phase 1 inventory: normalize raw cloud resources and persist them.

Flow: collector emits raw resource dicts → a normalizer maps each to a
``NormalizedAsset`` → ``InventoryService`` upserts them under a tracked scan job,
recording deltas and soft-deleting resources that disappeared.
"""

from odineyes.inventory.schema import NormalizedAsset
from odineyes.inventory.service import InventoryService, ScanResult

__all__ = ["NormalizedAsset", "InventoryService", "ScanResult"]
