"""/api/live/cspm caching — TTL expiry, refresh bust, and input validation.

The real engine (_run_cspm) is patched to a counter so these run offline and
fast; the point under test is the cache/validation glue around it, which is what
made the compliance score look "frozen" (a permanent cache that never expired).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from odineyes.api import server


@pytest.fixture()
def client(monkeypatch):
    calls = {"n": 0}

    def fake_run(region, profile, frameworks):
        calls["n"] += 1
        return {"region": region, "summary": {"pass_rate": 50.0}, "risk_score": 1.0,
                "risk_level": "LOW", "findings": [], "compliance": {}, "generated_at": "now",
                "_call": calls["n"]}

    monkeypatch.setattr(server, "_run_cspm", fake_run)
    server._cspm_cache.clear()
    return TestClient(server.app), calls


def test_cache_hit_within_ttl(client):
    c, calls = client
    a = c.get("/api/live/cspm?region=us-east-1").json()
    b = c.get("/api/live/cspm?region=us-east-1").json()
    assert calls["n"] == 1                 # second call served from cache
    assert a["_call"] == b["_call"] == 1


def test_ttl_expiry_recomputes(client, monkeypatch):
    c, calls = client
    c.get("/api/live/cspm?region=us-east-1")
    assert calls["n"] == 1
    # age the cached entry past the TTL
    key = next(iter(server._cspm_cache))
    _, result = server._cspm_cache[key]
    server._cspm_cache[key] = (0.0, result)        # epoch 0 = ancient
    c.get("/api/live/cspm?region=us-east-1")
    assert calls["n"] == 2                          # stale -> recomputed


def test_refresh_busts_cache(client):
    c, calls = client
    c.get("/api/live/cspm?region=us-east-1")
    c.get("/api/live/cspm?region=us-east-1&refresh=true")
    assert calls["n"] == 2                          # refresh forces recompute


def test_validation_rejects_before_engine(client):
    c, calls = client
    assert c.get("/api/live/cspm?region=bad;rm -rf /").status_code == 400
    assert c.get("/api/live/cspm?region=us-east-1&profile=../etc").status_code == 400
    assert c.get("/api/live/cspm?region=us-east-1&frameworks=EVIL").status_code == 400
    assert calls["n"] == 0                          # never reached the engine
