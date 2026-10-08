from unittest.mock import MagicMock

import pytest

from odineyes.core.realtime_policy import (
    event_bus_for_region,
    queue_for_region,
    regional_queues,
    register_delivery_role,
)


def test_regional_queues_require_an_explicit_same_region_arn(monkeypatch):
    monkeypatch.setenv(
        "ODINEYES_REALTIME_QUEUES_JSON",
        '{"ap-south-1":{"url":"https://sqs.ap-south-1.amazonaws.com/123456789012/odineyes-example-queue","arn":"arn:aws:sqs:ap-south-1:123456789012:odineyes-example-queue"}}',
    )

    queue = queue_for_region("ap-south-1")

    assert queue.region == "ap-south-1"
    assert queue.url.endswith("/ingest")


def test_regional_queues_reject_cross_region_mapping(monkeypatch):
    monkeypatch.setenv(
        "ODINEYES_REALTIME_QUEUES_JSON",
        '{"ap-south-1":{"url":"https://sqs.us-east-1.amazonaws.com/123456789012/odineyes-example-queue","arn":"arn:aws:sqs:us-east-1:123456789012:odineyes-example-queue"}}',
    )

    with pytest.raises(RuntimeError, match="not in configured Region"):
        regional_queues()


def test_event_bus_must_match_the_configured_region(monkeypatch):
    monkeypatch.setenv(
        "ODINEYES_REALTIME_QUEUES_JSON",
        '{"ap-south-1":{"url":"https://sqs.ap-south-1.amazonaws.com/123456789012/odineyes-example-queue",'
        '"arn":"arn:aws:sqs:ap-south-1:123456789012:odineyes-example-queue",'
        '"event_bus_arn":"arn:aws:events:us-east-1:123456789012:event-bus/odineyes-example"}}',
    )

    with pytest.raises(RuntimeError, match="event bus ARN is not in configured Region"):
        regional_queues()


def test_register_delivery_role_grants_customer_account_on_event_bus(monkeypatch):
    monkeypatch.setenv(
        "ODINEYES_REALTIME_QUEUES_JSON",
        '{"ap-south-1":{"url":"https://sqs.ap-south-1.amazonaws.com/123456789012/odineyes-example-queue",'
        '"arn":"arn:aws:sqs:ap-south-1:123456789012:odineyes-example-queue",'
        '"event_bus_arn":"arn:aws:events:ap-south-1:123456789012:event-bus/odineyes-example"}}',
    )
    events = MagicMock()
    import boto3

    monkeypatch.setattr(boto3, "client", lambda service, region_name: events)
    role_arn = "arn:aws:iam::123456789012:role/OdineyesRealtimeDelivery"

    register_delivery_role(role_arn, "ap-south-1")

    assert event_bus_for_region("ap-south-1").event_bus_arn.endswith("event-bus/ingress")
    kwargs = events.put_permission.call_args.kwargs
    assert kwargs["EventBusName"] == "ingress"
    assert kwargs["Principal"] == "123456789012"
    assert kwargs["Action"] == "events:PutEvents"
