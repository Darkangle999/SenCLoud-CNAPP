"""eBPF agent derivation: OS categorization + status (online/stale/no_sensor/
unsupported) from EC2 inventory overlaid with runtime events.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from odineyes.db.base import get_sessionmaker, init_db, session_scope
from odineyes.db.models import Asset, CloudAccount, RuntimeEvent
from odineyes.inventory import queries


def _ec2(account_id, iid, *, platform=None, platform_details=None):
    raw = {"InstanceId": iid}
    if platform:
        raw["Platform"] = platform
    if platform_details:
        raw["PlatformDetails"] = platform_details
    return Asset(
        resource_id=f"arn:aws:ec2:us-east-1:123456789012:instance/{iid}",
        cloud_provider="aws", account_id=account_id, asset_type="aws.ec2.instance",
        name=iid, region="us-east-1", raw=raw)


def test_agents_by_os_and_status(tmp_path):
    url = f"sqlite:///{tmp_path}/agents.db"
    init_db(url)
    with session_scope(url) as s:
        acct = CloudAccount(provider="aws", account_identifier="123456789012")
        s.add(acct); s.flush()
        s.add(_ec2(acct.id, "i-0aaaa1111", platform_details="Ubuntu Pro"))   # linux, online
        s.add(_ec2(acct.id, "i-0bbbb2222", platform_details="Linux/UNIX"))   # linux, no_sensor
        s.add(_ec2(acct.id, "i-0cccc3333", platform="windows"))             # windows, unsupported
        # fresh runtime event on the first host (a detection finding)
        s.add(RuntimeEvent(
            account_id=acct.id, event_type="process_execution",
            resource_id="i-0aaaa1111", observed_at=datetime.now(timezone.utc),
            raw={"rule_id": "T1059"}))

    with get_sessionmaker(url)() as s:
        res = queries.runtime_agents(s, fresh_minutes=60)

    by = {a["host"]: a for a in res["items"]}
    assert by["i-0aaaa1111"]["os"] == "linux" and by["i-0aaaa1111"]["status"] == "online"
    assert by["i-0aaaa1111"]["findings"] == 1
    assert by["i-0bbbb2222"]["status"] == "no_sensor"
    assert by["i-0cccc3333"]["os"] == "windows" and by["i-0cccc3333"]["status"] == "unsupported"
    assert res["by_os"] == {"linux": 2, "windows": 1}


def test_stale_when_events_are_old(tmp_path):
    url = f"sqlite:///{tmp_path}/agents2.db"
    init_db(url)
    with session_scope(url) as s:
        acct = CloudAccount(provider="aws", account_identifier="123456789012")
        s.add(acct); s.flush()
        s.add(_ec2(acct.id, "i-0dddd4444", platform_details="Linux/UNIX"))
        s.add(RuntimeEvent(
            account_id=acct.id, event_type="process_execution",
            resource_id="i-0dddd4444",
            observed_at=datetime.now(timezone.utc) - timedelta(hours=6)))
    with get_sessionmaker(url)() as s:
        res = queries.runtime_agents(s, fresh_minutes=60)
    assert res["items"][0]["status"] == "stale"
