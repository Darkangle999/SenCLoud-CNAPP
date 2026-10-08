"""Read-only GCP collector for the inventory persistence path.

Mirrors ``AwsRawCollector``: read-only, shapes each resource into the raw dict
``normalize_gcp_bucket`` consumes, storage client injectable for offline tests.

Public detection: a bucket is public when its IAM policy binds ``allUsers`` or
``allAuthenticatedUsers`` to any role — surfaced as the ``PublicBinding`` flag,
since the bucket object itself does not carry it.

Auth (production): application-default credentials — ``GOOGLE_APPLICATION_CREDENTIALS``,
metadata server, or ``gcloud auth application-default login`` — scoped to one
project id (the account identifier).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from odineyes.inventory.collection import CollectionError, CollectionScope

logger = logging.getLogger(__name__)

# (source_type, native_raw_dict)
RawResource = tuple[str, dict[str, Any]]

_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


class GcpCollector:
    """Collect GCP resource dicts ready for the normalizer layer."""

    def __init__(self, project: str, *, client: Optional[Any] = None):
        self.project = project
        self._client = client or self._default_client(project)
        self.authoritative_scopes: set[CollectionScope] = set()
        self.collection_errors: list[CollectionError] = []

    @staticmethod
    def _default_client(project: str) -> Any:
        from google.cloud import storage

        return storage.Client(project=project)

    def collect(self) -> list[RawResource]:
        self.authoritative_scopes.clear()
        self.collection_errors.clear()
        out: list[RawResource] = []
        out += self._buckets()
        return out

    def _buckets(self) -> list[RawResource]:
        out: list[RawResource] = []
        try:
            for bucket in self._client.list_buckets():
                out.append(("gcp.storage.bucket", self._shape_bucket(bucket)))
            self.authoritative_scopes.add(("gcp.storage.bucket", None))
        except Exception as exc:  # noqa: BLE001 — google api raises a broad error tree
            logger.error("gcp list_buckets failed: %s", exc)
            self.collection_errors.append(CollectionError(
                source_type="gcp.storage.bucket",
                operation="storage.list_buckets",
                message=str(exc),
            ))
        return out

    def _shape_bucket(self, bucket: Any) -> dict[str, Any]:
        iam = getattr(bucket, "iam_configuration", None)
        return {
            "name": getattr(bucket, "name", None),
            "location": getattr(bucket, "location", None),
            "labels": dict(getattr(bucket, "labels", None) or {}),
            "storageClass": getattr(bucket, "storage_class", None),
            "versioning": {"enabled": bool(getattr(bucket, "versioning_enabled", False))},
            "iamConfiguration": {
                "uniformBucketLevelAccess": {
                    "enabled": bool(getattr(iam, "uniform_bucket_level_access_enabled", False))
                    if iam is not None else False,
                },
                "publicAccessPrevention": getattr(iam, "public_access_prevention", None)
                if iam is not None else None,
            },
            "PublicBinding": self._has_public_binding(bucket),
        }

    @staticmethod
    def _has_public_binding(bucket: Any) -> bool:
        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
        except Exception as exc:  # noqa: BLE001
            logger.debug("get_iam_policy(%s) failed: %s", getattr(bucket, "name", "?"), exc)
            return False
        for binding in getattr(policy, "bindings", []) or []:
            members = binding.get("members", []) if isinstance(binding, dict) else []
            if _PUBLIC_MEMBERS & set(members):
                return True
        return False
