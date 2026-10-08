"""Maintain regional EventBridge ingress permissions for real-time telemetry."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass


_ROLE_RE = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]+$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z0-9-]+-\d$")
_EVENT_BUS_RE = re.compile(
    r"^arn:aws[a-z-]*:events:([a-z]{2}(?:-gov)?-[a-z0-9-]+-\d+):(\d{12}):event-bus/[A-Za-z0-9_.-]{1,256}$"
)
_SID_PREFIX = "OdineyesTenant"


@dataclass(frozen=True)
class RegionalQueue:
    region: str
    url: str
    arn: str
    event_bus_arn: str = ""

    @property
    def event_bus_name(self) -> str:
        """Return the name AWS EventBridge APIs require for this bus."""
        if not self.event_bus_arn:
            raise RuntimeError("regional realtime ingress bus is not configured")
        # regional_queues() validates the ARN before constructing this object.
        return self.event_bus_arn.rsplit("/", 1)[1]


def regional_queues() -> dict[str, RegionalQueue]:
    """Return the explicitly configured EventBridge ingestion queues.

    ``ODINEYES_REALTIME_QUEUES_JSON`` is a region-keyed object, for example::

        {"us-east-1": {"url": "https://...", "arn": "arn:...",
                       "event_bus_arn": "arn:...:event-bus/..."}}

    The legacy single-queue variables remain a compatible us-east-1 fallback.
    A queue or ingress bus is never inferred for another Region: EventBridge
    targets must remain regional, and an accidental fallback would silently
    lose events.
    """
    raw = os.environ.get("ODINEYES_REALTIME_QUEUES_JSON", "").strip()
    entries: dict[str, object] = {}
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("ODINEYES_REALTIME_QUEUES_JSON must be valid JSON") from exc
        if not isinstance(parsed, dict):
            raise RuntimeError("ODINEYES_REALTIME_QUEUES_JSON must be an object keyed by AWS Region")
        entries = parsed
    else:
        url = os.environ.get("ODINEYES_REALTIME_QUEUE_URL", "").strip()
        arn = os.environ.get("ODINEYES_REALTIME_QUEUE_ARN", "").strip()
        if url and arn:
            entries = {os.environ.get("AWS_REGION", "us-east-1").strip() or "us-east-1": {"url": url, "arn": arn}}

    queues: dict[str, RegionalQueue] = {}
    for region, value in entries.items():
        if not isinstance(region, str) or not _REGION_RE.fullmatch(region):
            raise RuntimeError(f"invalid realtime queue Region {region!r}")
        if not isinstance(value, dict):
            raise RuntimeError(f"realtime queue configuration for {region} must be an object")
        url = str(value.get("url") or "").strip()
        arn = str(value.get("arn") or "").strip()
        event_bus_arn = str(value.get("event_bus_arn") or "").strip()
        if not url or not arn:
            raise RuntimeError(f"realtime queue configuration for {region} needs url and arn")
        if f":sqs:{region}:" not in arn:
            raise RuntimeError(f"realtime queue ARN is not in configured Region {region}")
        if event_bus_arn:
            bus_match = _EVENT_BUS_RE.fullmatch(event_bus_arn)
            if not bus_match or bus_match.group(1) != region:
                raise RuntimeError(f"realtime event bus ARN is not in configured Region {region}")
        queues[region] = RegionalQueue(
            region=region, url=url, arn=arn, event_bus_arn=event_bus_arn,
        )
    return queues


def queue_for_region(region: str) -> RegionalQueue:
    if not _REGION_RE.fullmatch(region):
        raise ValueError("invalid AWS Region")
    queue = regional_queues().get(region)
    if queue is None:
        raise RuntimeError(f"Odineyes has no regional realtime queue configured for {region}")
    return queue


def event_bus_for_region(region: str) -> RegionalQueue:
    """Return the customer-facing EventBridge ingress bus for one Region."""
    queue = queue_for_region(region)
    if not queue.event_bus_arn:
        raise RuntimeError(
            f"Odineyes has no regional realtime ingress bus configured for {region}"
        )
    return queue


def register_delivery_role(role_arn: str, region: str | None = None) -> None:
    """Allow a customer's account to put events on its regional ingress bus.

    The customer EventBridge rule uses ``role_arn`` as its execution role, but
    EventBridge event-bus resource policies grant cross-account access by AWS
    account. The customer stack constrains that role to its one ingress bus and
    its one source rule, while this registration keeps the platform bus closed
    to every other account.
    """
    target_region = region or os.environ.get("AWS_REGION", "us-east-1")
    plane = event_bus_for_region(target_region)
    if not _ROLE_RE.fullmatch(role_arn):
        raise ValueError("invalid EventBridge delivery role ARN")

    import boto3

    account_id = role_arn.split(":")[4]
    sid = _SID_PREFIX + hashlib.sha256(role_arn.encode()).hexdigest()[:20]
    client = boto3.client("events", region_name=plane.region)
    client.put_permission(
        # PutPermission accepts an event-bus *name*, unlike some EventBridge
        # APIs that accept an ARN. Supplying the ARN produces a 500 from the
        # onboarding callback and makes CloudFormation roll the stack back.
        EventBusName=plane.event_bus_name,
        StatementId=sid,
        Action="events:PutEvents",
        Principal=account_id,
    )
