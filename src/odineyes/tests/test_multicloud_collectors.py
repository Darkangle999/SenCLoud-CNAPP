"""Live Azure + GCP collectors — offline coverage with fake SDK clients.

Verifies the collector glue (SDK object → raw dict shaping, public detection)
and the round-trip through the existing normalizers, plus the orchestrator's
per-provider collector dispatch. No Azure/GCP credentials or network.
"""

from __future__ import annotations

import pytest

from odineyes.inventory.azure_collector import AzureCollector
from odineyes.inventory.gcp_collector import GcpCollector
from odineyes.inventory.normalizers import get_normalizer
from odineyes.inventory.orchestrator import AccountRef, MultiAccountOrchestrator


# ── Azure ───────────────────────────────────────────────────────

class _AzSku:
    def __init__(self, name):
        self.name = name


class _AzBlob:
    def __init__(self, enabled):
        self.enabled = enabled


class _AzServices:
    def __init__(self, blob):
        self.blob = blob


class _AzEncryption:
    def __init__(self, blob_enabled):
        self.services = _AzServices(_AzBlob(blob_enabled))


class _AzAccount:
    def __init__(self, name, public, location="westeurope"):
        self.name = name
        self.id = f"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/{name}"
        self.location = location
        self.tags = {"env": "prod"}
        self.kind = "StorageV2"
        self.sku = _AzSku("Standard_LRS")
        self.allow_blob_public_access = public
        self.enable_https_traffic_only = True
        self.minimum_tls_version = "TLS1_2"
        self.encryption = _AzEncryption(True)


class _AzStorageOps:
    def __init__(self, accounts):
        self._accounts = accounts

    def list(self):
        return iter(self._accounts)


class _FakeAzureClient:
    def __init__(self, accounts):
        self.storage_accounts = _AzStorageOps(accounts)


def test_azure_collector_shapes_and_normalizes():
    client = _FakeAzureClient([_AzAccount("public1", public=True), _AzAccount("locked", public=False)])
    resources = AzureCollector("sub-1", client=client).collect()
    assert [t for t, _ in resources] == ["azure.storage.account", "azure.storage.account"]

    # round-trip the public one through the real normalizer
    src, raw = resources[0]
    asset = get_normalizer(src)(raw, "sub-1")
    assert asset.cloud_provider == "azure"
    assert asset.is_public and asset.network_exposure == "public"
    assert asset.encryption_enabled is True
    assert asset.region == "westeurope"
    assert asset.properties["minimum_tls"] == "TLS1_2"

    locked = get_normalizer(*resources[1][:1])(resources[1][1], "sub-1")
    assert not locked.is_public


def test_azure_collector_swallows_list_error(caplog):
    class _Boom:
        @property
        def storage_accounts(self):
            raise RuntimeError("AuthorizationFailed")

    # constructor takes the client as-is; the error surfaces inside collect()
    coll = AzureCollector("sub-1", client=_Boom())
    assert coll.collect() == []


# ── GCP ─────────────────────────────────────────────────────────

class _GcpIam:
    def __init__(self, uniform=True, prevention="inherited"):
        self.uniform_bucket_level_access_enabled = uniform
        self.public_access_prevention = prevention


class _GcpPolicy:
    def __init__(self, bindings):
        self.bindings = bindings


class _GcpBucket:
    def __init__(self, name, members, location="EU", boom=False):
        self.name = name
        self.location = location
        self.labels = {"team": "data"}
        self.storage_class = "STANDARD"
        self.versioning_enabled = True
        self.iam_configuration = _GcpIam()
        self._members = members
        self._boom = boom

    def get_iam_policy(self, requested_policy_version=1):
        if self._boom:
            raise RuntimeError("permission denied")
        return _GcpPolicy([{"role": "roles/storage.objectViewer", "members": self._members}])


class _FakeGcpClient:
    def __init__(self, buckets):
        self._buckets = buckets

    def list_buckets(self):
        return iter(self._buckets)


def test_gcp_collector_detects_public_binding():
    client = _FakeGcpClient([
        _GcpBucket("open", ["allUsers"]),
        _GcpBucket("team-only", ["user:alice@example.com"]),
    ])
    resources = GcpCollector("proj-1", client=client).collect()
    assert [t for t, _ in resources] == ["gcp.storage.bucket", "gcp.storage.bucket"]

    pub = get_normalizer("gcp.storage.bucket")(resources[0][1], "proj-1")
    assert pub.cloud_provider == "gcp" and pub.is_public
    assert pub.encryption_enabled is True               # GCS always encrypts
    assert pub.region == "eu"
    assert pub.properties["uniform_bucket_level_access"] is True

    priv = get_normalizer("gcp.storage.bucket")(resources[1][1], "proj-1")
    assert not priv.is_public


def test_gcp_collector_iam_error_is_not_public():
    client = _FakeGcpClient([_GcpBucket("x", [], boom=True)])
    raw = GcpCollector("proj-1", client=client).collect()[0][1]
    assert raw["PublicBinding"] is False


# ── orchestrator per-provider dispatch ──────────────────────────

def test_orchestrator_dispatches_collector_by_provider(monkeypatch):
    orch = MultiAccountOrchestrator()   # no injected factory → real dispatch

    import odineyes.inventory.azure_collector as az
    import odineyes.inventory.gcp_collector as gc

    monkeypatch.setattr(az, "AzureCollector", lambda subscription_id: ("azure", subscription_id))
    monkeypatch.setattr(gc, "GcpCollector", lambda project: ("gcp", project))

    assert orch._make_collector(AccountRef("sub-9", None, None, "azure")) == ("azure", "sub-9")
    assert orch._make_collector(AccountRef("proj-9", None, None, "gcp")) == ("gcp", "proj-9")


def test_orchestrator_unknown_provider_fails_cleanly():
    orch = MultiAccountOrchestrator()
    result = orch.scan_account(AccountRef("x", None, None, "oracle"))
    assert result.status == "failed" and "oracle" in result.error
