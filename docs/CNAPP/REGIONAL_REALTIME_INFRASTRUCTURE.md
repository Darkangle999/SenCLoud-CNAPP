# Regional real-time infrastructure

Odineyes separates the one-time cross-account IAM foundation from regional
telemetry. This prevents a global IAM role from being recreated when a customer
enables monitoring in another AWS Region.

## Example platform account: 123456789012

Deploy `infrastructure/aws-regional-realtime.yaml` once in every supported
Region. Pass `WorkerRoleName` from the `InstanceRoleName` output of the
existing `OdineyesBootstrap` stack. The stack creates a regional EventBridge
ingress bus, worker SQS queue, EventBridge delivery DLQ, worker DLQ, and the
least privilege policy required to consume the queue and register customer
accounts on that Region's ingress bus.

Record the outputs in the application host environment:

```json
{
  "us-east-1": {
    "url": "https://sqs.us-east-1.amazonaws.com/123456789012/...",
    "arn": "arn:aws:sqs:us-east-1:123456789012:...",
    "event_bus_arn": "arn:aws:events:us-east-1:123456789012:event-bus/..."
  },
  "ap-south-1": {
    "url": "https://sqs.ap-south-1.amazonaws.com/123456789012/...",
    "arn": "arn:aws:sqs:ap-south-1:123456789012:...",
    "event_bus_arn": "arn:aws:events:ap-south-1:123456789012:event-bus/..."
  }
}
```

Set that JSON as `ODINEYES_REALTIME_QUEUES_JSON`, then run the updated Go
realtime worker in each Region with `AWS_REGION` (or
`ODINEYES_REALTIME_WORKER_REGION`) set to that Region. A deployed worker then
consumes only its local queue; it refuses to poll another Region's queue. The
legacy single-queue variables remain supported for US-East-only installs.

## Customer account: one foundation, many regional stacks

1. Deploy `cspm_g3_onboarding.yaml` once to create `OdineyesReadOnly`.
2. For each monitored Region, retrieve
   `GET /api/inventory/accounts/{account_id}/realtime-regions/template?region=<region>`.
3. Deploy the returned `cspm_g3_regional_telemetry.yaml` in that same customer
   Region using the supplied `RealtimeEventBusArn`.
4. If that Region already has a suitable active CloudTrail trail, leave
   `EnableRealtimeCloudTrail=false`. Otherwise set it to `true` to create a
   dedicated write-management-event trail and retained private log bucket.
5. Register the `RealtimeDeliveryRoleArn` stack output:

```http
PUT /api/inventory/accounts/{account_id}/realtime-regions
Authorization: Bearer <operator token>
Content-Type: application/json

{"region":"ap-south-1","delivery_role_arn":"arn:aws:iam::<customer-account>:role/<stack-generated-role>"}
```

Registration grants that customer account `events:PutEvents` only on the
matching regional ingress bus. The customer delivery role itself is scoped to
that bus and its exact customer EventBridge rule. The platform SQS queue stays
private: only the platform ingress-bus rule can send to it.

## Operational constraints

- A customer EventBridge rule targets the platform EventBridge ingress bus in
  the same Region. It does not target platform SQS directly.
- SQS messages are long-polled in batches of up to ten.
- CloudTrail data events are not enabled. The EventBridge rule matches only
  the security mutation allowlist.
- Reconciliation runs once per dirty account and Region, so an event in
  `ap-south-1` never triggers a resource scan against `us-east-1`.
- Begin with Regions actually containing customer workloads. Add a regional
  ingress bus and worker queue before onboarding customer telemetry in that
  Region.
