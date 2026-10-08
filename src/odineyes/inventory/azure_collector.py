"""Read-only Azure collector for the inventory persistence path.

Mirrors ``AwsRawCollector``: every call is read-only, and each resource is
shaped into the exact raw dict the matching normalizer consumes, so the
normalizer layer stays pure and SDK-agnostic. The management client is
injectable so the collector runs under test without Azure or credentials.

Auth (production): ``DefaultAzureCredential`` — env vars, managed identity,
or ``az login`` — scoped to one subscription id (the account identifier).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from odineyes.inventory.collection import CollectionError, CollectionScope

logger = logging.getLogger(__name__)

# (source_type, native_raw_dict)
RawResource = tuple[str, dict[str, Any]]


class AzureCollector:
    """Collect Azure resource dicts ready for the normalizer layer."""

    def __init__(self, subscription_id: str, *, client: Optional[Any] = None):
        self.subscription_id = subscription_id
        self._client = client or self._default_client(subscription_id)
        self.authoritative_scopes: set[CollectionScope] = set()
        self.collection_errors: list[CollectionError] = []

    @staticmethod
    def _default_client(subscription_id: str) -> Any:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.storage import StorageManagementClient

        return StorageManagementClient(DefaultAzureCredential(), subscription_id)

    def collect(self) -> list[RawResource]:
        self.authoritative_scopes.clear()
        self.collection_errors.clear()
        out: list[RawResource] = []
        out += self._storage_accounts()
        return out

    def _storage_accounts(self) -> list[RawResource]:
        out: list[RawResource] = []
        try:
            for acct in self._client.storage_accounts.list():
                out.append(("azure.storage.account", self._shape_account(acct)))
            self.authoritative_scopes.add(("azure.storage.account", None))
        except Exception as exc:  # noqa: BLE001 — SDK raises a broad ServiceError tree
            logger.error("azure storage_accounts.list failed: %s", exc)
            self.collection_errors.append(CollectionError(
                source_type="azure.storage.account",
                operation="storage_accounts.list",
                message=str(exc),
            ))
        return out

    @staticmethod
    def _shape_account(acct: Any) -> dict[str, Any]:
        """StorageAccount model → the nested raw dict normalize_azure_storage_account
        expects. Azure flattens its REST 'properties' onto the model, so we
        re-nest the few fields the normalizer reads."""
        sku = getattr(acct, "sku", None)
        enc = getattr(acct, "encryption", None)
        blob_enc = None
        if enc is not None:
            services = getattr(enc, "services", None)
            blob = getattr(services, "blob", None) if services is not None else None
            # Azure storage is always encrypted at rest; None reads as enabled.
            blob_enc = getattr(blob, "enabled", True) if blob is not None else True
        return {
            "name": getattr(acct, "name", None),
            "id": getattr(acct, "id", None),
            "location": getattr(acct, "location", None),
            "tags": getattr(acct, "tags", None) or {},
            "kind": getattr(acct, "kind", None),
            "sku": {"name": getattr(sku, "name", None) if sku is not None else None},
            "properties": {
                "allowBlobPublicAccess": bool(getattr(acct, "allow_blob_public_access", False)),
                "supportsHttpsTrafficOnly": bool(getattr(acct, "enable_https_traffic_only", True)),
                "minimumTlsVersion": getattr(acct, "minimum_tls_version", None),
                "encryption": {"services": {"blob": {"enabled": bool(blob_enc)}}},
            },
        }
