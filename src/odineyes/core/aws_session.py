"""Shared, warm boto3 clients for the live check engine.

Each check used to build its own ``boto3.Session(...).client(...)`` inside
``execute()``. The first call on a fresh client pays ~2.5s of warmup (TLS +
endpoint resolution + credential resolution); a warm client answers in ~0.3s.
With ~32 checks each creating fresh clients, the whole CSPM sweep was basically
warmup — ~80s cold.

This hands every check a *cached* client instead: each (profile, service, region)
is created and warmed once, then reused for the rest of the scan. boto3 client
*method calls* are thread-safe, so sharing a client across the check engine's
thread pool is fine; only client *creation* isn't thread-safe, so get-or-create
is serialized with a lock.

``shared_session`` is a drop-in for ``boto3.Session(profile_name=..., region_name=...)``
for the checks' usage (they only ever call ``.client(...)``).
"""

from __future__ import annotations

import threading
from typing import Any, Optional

import boto3


class _ClientPool:
    """Stands in for a boto3.Session: hands out cached, warm clients keyed by
    (service, region). One real Session underneath so credentials resolve once."""

    def __init__(self, profile: str, region: Optional[str]):
        self._session = (
            boto3.Session(profile_name=profile, region_name=region)
            if region else boto3.Session(profile_name=profile)
        )
        self._region = region
        self._clients: dict[tuple[str, Optional[str]], Any] = {}
        self._lock = threading.Lock()

    def client(self, service_name: str, region_name: Optional[str] = None, **kw: Any) -> Any:
        region = region_name or self._region
        key = (service_name, region)
        with self._lock:
            c = self._clients.get(key)
            if c is None:
                c = self._session.client(service_name, region_name=region, **kw)
                self._clients[key] = c
            return c


_pools: dict[tuple[str, Optional[str]], _ClientPool] = {}
_pools_lock = threading.Lock()


def shared_session(profile: str = "default", region: Optional[str] = None) -> _ClientPool:
    """Cached client pool per (profile, region). Drop-in for
    ``boto3.Session(profile_name=profile[, region_name=region])`` in the checks."""
    key = (profile, region)
    with _pools_lock:
        p = _pools.get(key)
        if p is None:
            p = _ClientPool(profile, region)
            _pools[key] = p
        return p


if __name__ == "__main__":
    # Offline self-check: same (profile, region) -> same pool; a pool hands back
    # the *same* client object for repeat asks (that reuse is the whole point).
    import types

    a, b = shared_session("default"), shared_session("default")
    assert a is b, "pools must be cached per (profile, region)"
    assert shared_session("default", "us-east-1") is not a, "region keys a distinct pool"

    pool = _ClientPool.__new__(_ClientPool)  # bypass real boto3 in the check
    pool._session = types.SimpleNamespace(client=lambda *a, **k: object())
    pool._region = None
    pool._clients = {}
    pool._lock = threading.Lock()
    c1 = pool.client("s3")
    c2 = pool.client("s3")
    assert c1 is c2, "same (service, region) must reuse the warm client"
    assert pool.client("iam") is not c1, "different service -> different client"
    print("aws_session self-check OK: pools + clients cached and reused")
