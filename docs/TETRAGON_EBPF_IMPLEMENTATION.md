# Tetragon eBPF Runtime Security for Odineyes

Status: proposed implementation plan  
Scope: Linux EC2 and EKS worker nodes  
Authoring date: 2026-07-22

## 1. Executive decision

Tetragon is a strong open-source fit for Odineyes because it provides Linux runtime visibility from eBPF and can enforce carefully reviewed policies when the product is ready. It is not a replacement for CSPM. It provides a runtime evidence layer that lets Odineyes answer a question CSPM alone cannot answer:

> A cloud asset has a risky configuration or vulnerable workload. Did a suspicious process actually execute, attempt privilege escalation, access a sensitive file, or make an unexpected network connection?

Odineyes should implement Tetragon in two stages:

1. Monitoring-first runtime detection for customer Linux EC2 and EKS worker nodes.
2. Optional, explicitly approved enforcement after policy observation, canary validation, and rollback controls exist.

The existing repository has an early Tetragon shipper and runtime-event API, so this is an evolution rather than a greenfield feature. The current implementation must not be presented as production-ready. It lacks authenticated enrollment, event ownership, persistent delivery state, robust rotation handling, and an agent inventory model.

## 2. The real problem this solves

CSPM detects cloud posture conditions such as:

- an internet-reachable security group;
- an EC2 instance with an overly powerful IAM instance profile;
- public or weakly protected data storage;
- a container image containing a critical CVE;
- an IAM policy that enables privilege escalation.

Those conditions identify potential exposure. They do not prove runtime behavior. Security teams still need to investigate:

- Did the vulnerable process run on the exposed workload?
- Did it spawn a shell, download a payload, or write into a sensitive path?
- Did the workload attempt to access cloud metadata, credentials, or a data store?
- Did a container process escape its expected execution profile?
- Which CSPM finding, resource, identity, and application owner should receive the incident?

Tetragon observes process execution, file activity, network activity, system calls, and policy matches at the Linux kernel boundary. That lets Odineyes join static cloud posture with runtime evidence.

The intended decision becomes:

    CSPM says: this internet-reachable production instance has an exploitable path.
    Tetragon says: the instance executed curl from a web process, then spawned a shell,
    then accessed credentials.
    Odineyes says: this is an active, high-confidence attack path. Isolate or remediate
    these two controls first.

## 3. What Tetragon covers, and what it does not

### 3.1 Covered in the first release

For Linux EC2 hosts and EKS nodes, Odineyes can collect:

- process execution and parent-child process trees;
- executable, effective user, process identifiers, container and pod context;
- selected file access or sensitive-path activity;
- selected outbound network connections;
- signals for shell spawning, reverse-shell-like behavior, suspicious download tools, and credential access;
- policy enforcement decisions later, including monitor-only decisions;
- health information: Tetragon version, node identity, kernel/BTF readiness, policy bundle version, delivery lag, buffered events, and drops.

### 3.2 Not covered by Tetragon

Tetragon cannot observe every workload type:

| Runtime target | First release support | Reason |
| --- | --- | --- |
| Linux EC2 | Yes | Tetragon runs on the host and sees host processes. |
| EKS using EC2 worker nodes | Yes | Install as a DaemonSet on each Linux worker node. |
| EKS Fargate | No | Fargate does not support DaemonSets, privileged containers, or host-level eBPF access. |
| ECS on EC2 | Later | Feasible with host-level installation, but needs ECS container identity mapping. |
| ECS Fargate | No | No host-level eBPF capability. |
| Lambda | No | The execution environment is not customer-host managed. |
| Windows | No | Tetragon is a Linux eBPF project. |
| Managed databases and SaaS services | No | Use CloudTrail, service audit logs, and database-native telemetry instead. |

This is a deliberate coverage boundary, not a product failure. The Sensors page must show unsupported resources clearly instead of showing them as silently unprotected.

Official references:

- Tetragon event concepts: https://tetragon.io/docs/concepts/events/
- Standalone container installation: https://tetragon.io/docs/installation/container/
- Kubernetes installation: https://tetragon.io/docs/installation/kubernetes/
- Tetragon kernel and BTF FAQ: https://tetragon.io/docs/installation/faq/
- EKS on Fargate limitations: https://docs.aws.amazon.com/eks/latest/userguide/fargate.html

## 4. Architecture

### 4.1 Target architecture

~~~mermaid
flowchart LR
    subgraph Customer["Customer AWS account"]
      Host["Linux EC2 host"]
      Node["EKS Linux worker node"]
      T1["Tetragon"]
      S1["Odineyes Runtime Sensor"]
      T2["Tetragon"]
      S2["Odineyes Runtime Sensor"]
      Host --> T1 --> S1
      Node --> T2 --> S2
    end

    subgraph Odineyes["Odineyes control plane"]
      Gate["Authenticated runtime ingestion API"]
      Queue["Durable event buffer"]
      Normalizer["Schema validation and normalization"]
      Store["Runtime event store"]
      Graph["CSPM correlation and security graph"]
      Cases["Findings, attack paths, timelines"]
      Gate --> Queue --> Normalizer --> Store --> Graph --> Cases
    end

    S1 -->|"Outbound TLS only"| Gate
    S2 -->|"Outbound TLS only"| Gate

    CSPM["AWS inventory, IAM, network, data, vulnerabilities"] --> Graph
~~~

The sensor initiates an outbound HTTPS connection to Odineyes. The customer does not expose a host port, SSH service, Tetragon gRPC endpoint, or Kubernetes API endpoint to Odineyes.

### 4.2 Separation of cloud roles

The current OdineyesReadOnly customer role remains a read-only inventory role. It should retain permissions that discover AWS configuration and should not gain SSM command execution, EC2 mutation, Kubernetes administration, or arbitrary deployment permissions.

There are two acceptable installation modes:

| Mode | Who installs the sensor | Role design | Recommended use |
| --- | --- | --- | --- |
| Customer-managed | Customer runs a CloudFormation stack, SSM Association, Helm command, or GitOps deployment | No new central write permission | Default and safest onboarding path |
| Managed deployment | Customer explicitly delegates a separate, tightly scoped deployment role | Separate deployment role, separate approval, separate audit trail | Enterprise opt-in only |

The central CSPM scanner role must never become a remote administration credential merely because runtime visibility is added.

### 4.3 Event sources

Tetragon can export JSON events or stream events through its local gRPC interface. The recommended progression is:

| Stage | Sensor input | Why |
| --- | --- | --- |
| Pilot | Local Tetragon JSON export file | Simplest migration from the existing shipper and easy to inspect. |
| Production | Local Tetragon Unix-domain gRPC adapter | Stronger schema handling, lower tailing complexity, less dependence on log rotation. |
| Optional fallback | JSON export with an explicit file checkpoint and spool | Useful if gRPC is unavailable or during migration. |

Tetragon gRPC must stay local to the host or node. Do not expose it through a public TCP listener. If TCP is unavoidable within a controlled network, use TLS and mutual TLS as documented by Tetragon.

## 5. Current repository assessment

### 5.1 Existing foundation

Odineyes already includes:

- src/odineyes/sensor/tetragon_shipper.py, which tails a Tetragon JSON log;
- runtime event endpoints in src/odineyes/api/server.py;
- RuntimeEvent persistence in src/odineyes/db/models.py;
- runtime event correlation in src/odineyes/inventory/exploitation.py;
- a Sensors presentation path in frontend/src/pages/Ebpf.tsx;
- a Compose profile named runtime.

That proves the product direction and supports an early local demonstration.

### 5.2 Production gaps to close

| Gap | Current behavior | Required correction |
| --- | --- | --- |
| Sensor identity | The shipper sends only a tenant header and fixed node name. | Use a registered sensor identity with mTLS or a scoped, rotating enrollment credential. |
| Event ownership | RuntimeEvent account_id may be null. | Resolve every enrolled event to one customer account and one sensor. |
| API security | Internal runtime endpoints accept unverified generic payloads. | Put a dedicated authenticated ingestion endpoint behind authorization, validation, rate limits, and audit logging. |
| Delivery reliability | No persistent offset, no bounded disk spool, and batch IDs are time-derived. | Use event UUIDs, sequence numbers, persistent checkpoints, retry with backoff, and a capped encrypted local spool. |
| Log rotation | File tailing has no inode or rotation recovery. | Track inode plus offset, reopen rotated files, and suppress duplicates. |
| Sensitive data | Raw command arguments and environment context can be sensitive. | Redact at sensor and server, minimize storage, encrypt evidence, and apply retention policies. |
| Agent inventory | The UI infers sensors from assets and events. | Persist sensor registration, compatibility, policy state, heartbeat, health, and coverage. |
| Correlation quality | Event matching is resource-centric only. | Join process, image, pod, identity, vulnerability, network exposure, and sensitive-data context. |
| Installation IaC | The Terraform prototype contains obsolete and placeholder installation behavior. | Replace it with version-pinned, verified customer deployment artifacts. |

## 6. Data model

SQLite remains acceptable for a local pilot and a single low-volume deployment. It is not the long-term queue or evidence store for many hosts. Build the schema so a later migration to PostgreSQL, SQS, and encrypted S3 does not change the logical event contract.

### 6.1 New table: runtime_sensors

Each installed sensor must have a durable record.

| Field | Purpose |
| --- | --- |
| id | UUID sensor ID, generated at enrollment |
| tenant_id | Odineyes tenant scope |
| account_id | Customer cloud account that owns this host or node |
| provider and region | Cloud placement |
| target_kind | ec2_host, eks_node, ecs_host, or other declared target |
| instance_id, cluster_arn, node_name | Cloud and orchestration identity |
| host_id | Stable machine identity, not a display name |
| platform, kernel_release, btf_available | Compatibility and support evidence |
| tetragon_version | Running Tetragon version |
| sensor_version | Odineyes runtime sensor version |
| policy_bundle and policy_bundle_version | Exact policy deployment state |
| mode | monitoring, monitor_only, or enforcement |
| enrollment_state | pending, active, revoked, unsupported, or error |
| enrolled_at, last_heartbeat_at, last_event_at | Operational health |
| last_sequence, dropped_event_count, buffered_event_count | Delivery health |
| revoked_at, revocation_reason | Lifecycle and incident response |

Recommended indexes:

- account_id plus enrollment_state;
- account_id plus last_heartbeat_at;
- cluster_arn plus node_name;
- host_id;
- sensor version and policy bundle version for fleet health.

### 6.2 Extend runtime_events

The existing RuntimeEvent record should become a normalized security event, not only a display item.

| Field | Purpose |
| --- | --- |
| id | UUID assigned by sensor or ingestion service |
| sensor_id | Required foreign key after enrollment |
| account_id | Required for enrolled customer events |
| schema_version | Enables safe evolution of the event contract |
| observed_at and received_at | Distinguishes source time from ingest delay |
| event_type and action | Tetragon event family and observation or enforcement outcome |
| severity and confidence | Detection classification with evidence confidence |
| policy_name and policy_version | Exact policy that produced the event |
| instance_id, cluster_arn, node_name | Runtime target |
| namespace, pod_name, container_id, container_image | Kubernetes or container context |
| process_exec_id, parent_exec_id, pid, ppid | Process-tree correlation |
| binary, arguments_redacted, uid, cwd_redacted | Process evidence without unrestricted secrets |
| file_path_redacted | Sensitive file activity |
| destination_ip, destination_port, protocol | Network evidence |
| resource_id and workload | Existing CSPM joins |
| event_hash and source_sequence | Idempotency and replay protection |
| raw_redacted or raw_evidence_ref | Sanitized event payload or encrypted external evidence pointer |
| retention_until | Explicit lifecycle control |

### 6.3 Detection and correlation tables

Add separate, queryable records rather than deriving all incidents from raw events at render time:

| Table | Purpose |
| --- | --- |
| runtime_detections | A deduplicated detection with state, score, owner, and suppression lifecycle |
| runtime_detection_events | Many-to-many evidence linking a detection to raw events |
| runtime_policy_bundles | Versioned policy manifest, checksum, mode, reviewer, rollout state |
| runtime_sensor_heartbeats | Optional time-series health if detailed fleet history is needed |
| runtime_enrollment_tokens | Hashed, one-time, short-lived enrollment artifacts; never store raw token material |

### 6.4 Canonical event envelope

All input sources should normalize into this shape before persistence:

~~~json
{
  "schema_version": 1,
  "event_id": "uuid",
  "sensor_id": "uuid",
  "sequence": 1842,
  "observed_at": "2026-07-22T12:00:00Z",
  "source": {
    "provider": "aws",
    "account_id": "123456789012",
    "region": "us-east-1",
    "target_kind": "ec2_host",
    "instance_id": "i-0123456789abcdef0"
  },
  "runtime": {
    "event_type": "process_exec",
    "action": "observed",
    "policy_name": "odineyes-sensitive-paths",
    "process": {
      "exec_id": "kernel-or-tetragon-id",
      "parent_exec_id": "parent-id",
      "binary": "/usr/bin/curl",
      "arguments_redacted": ["curl", "https://example.invalid/payload"],
      "uid": 0
    }
  }
}
~~~

The raw Tetragon source event is useful forensic evidence, but it must be sanitized before storage. Queryable first-class fields must never depend on a JSON blob alone.

## 7. API and delivery design

### 7.1 New endpoint

Replace unprotected internal ingestion with a versioned runtime endpoint:

    POST /api/v1/runtime/batches

Request requirements:

- authenticated sensor identity;
- sensor ID in the client identity and request envelope;
- tenant and account resolved server-side from the sensor registration, not trusted from a client-supplied header;
- batch UUID, monotonically increasing sequence range, and per-event UUID;
- strict schema validation and payload-size limits;
- idempotent acceptance;
- rate limits per sensor and tenant;
- audit log of enrollment, policy change, ingestion failure, revocation, and dropped event reports.

The API must reject events when:

- the sensor is revoked or not active;
- source account identity does not match the registered account;
- a sequence is implausibly far behind or ahead without an explicit recovery flow;
- the event cannot pass schema validation;
- the payload contains restricted fields that the privacy policy prohibits.

### 7.2 Sensor delivery contract

The runtime sensor should follow this lifecycle:

1. Read Tetragon events through local gRPC or the local export file.
2. Normalize to the canonical envelope.
3. Redact configured arguments, environment values, and sensitive paths before local persistence.
4. Append to a bounded local encrypted spool.
5. Send a batch over outbound TLS.
6. Delete acknowledged records only after the control plane confirms accepted event IDs.
7. Retry with exponential backoff and jitter after transient failure.
8. Emit heartbeat metrics even if no security event occurs.
9. Report local queue pressure and dropped-event counts as operational findings.

For a file-based adapter, persist:

- file path;
- inode or Windows-equivalent identity where applicable;
- byte offset;
- last accepted source timestamp;
- event hashes in a rolling dedup window.

Tetragon supports JSON export rotation and compression settings. The Odineyes adapter must be tested against rotation, restart, duplicate delivery, partial lines, disk-full behavior, and a temporary API outage.

### 7.3 Authentication

Preferred production authentication:

- one-time enrollment URL or short-lived enrollment artifact;
- generated key pair on the host;
- client certificate issued by Odineyes after device registration;
- mTLS for sensor-to-control-plane ingestion;
- certificate rotation and immediate revocation;
- no long-lived static API key in user data, Docker environment variables, or an AMI.

For an early pilot, a per-sensor signed token can be accepted if it is:

- short-lived;
- scoped to a single sensor and account;
- stored only in a customer-controlled encrypted secret mechanism;
- hashed server-side;
- rotatable and revocable;
- never logged.

The sensor enrollment artifact is an authentication credential, not an AWS access key and not the AWS ExternalId. It grants only the ability to submit telemetry for a single registered sensor.

## 8. Tetragon policy strategy

### 8.1 Default policy posture

Start every policy in monitoring mode. A policy should first accumulate observations, be triaged for false positives, have owner review, and pass canary validation. Do not enable blocking by default.

Tetragon supports monitoring, enforcement, and monitor_only policy modes. Enforcement can prevent an action or terminate a process. That makes policy deployment a production change with real availability risk, not merely a detection-rule update.

### 8.2 Phase-one detections

Build a small, explainable default bundle:

| Detection | Runtime evidence | CSPM enrichment | Initial outcome |
| --- | --- | --- | --- |
| Web process launches shell | nginx, apache, node, java, or python parent launches sh, bash, dash, or zsh | Internet exposure, critical CVE, workload identity | High detection and attack-path boost |
| Suspicious downloader from service process | curl, wget, python, or shell invoked by web or application process | Public endpoint, security-group exposure | High when followed by shell or privileged access |
| Cloud credential path access | Process reads configured credential or metadata-related paths | Attached IAM role, privilege and data access | High detection and identity-path boost |
| Sensitive file access | Unexpected process accesses ssh keys, shadow-like files, application secrets, or configuration | Asset tags and data classification | Medium or high depending on actor and file |
| Unexpected outbound connection | New process connects to unapproved destination or port | Public exposure, subnet, workload baseline | Medium initially; elevate on known attack chain |
| Privilege boundary attempt | Process opens sensitive kernel, namespace, or capability-related paths | Host criticality and container context | High |
| Container boundary anomaly | Process behavior conflicts with expected pod/container boundary | Kubernetes workload, image vulnerability | High, analyst review required |

Avoid a broad rule that reports every process execution. It generates cost, noise, and potentially sensitive command data without producing a security decision.

### 8.3 Policy bundle management

Treat Tetragon policies as versioned artifacts:

1. Store source YAML in the repository with a policy ID and owner.
2. Generate a manifest containing policy name, checksum, supported platforms, mode, and test evidence.
3. Validate syntax in CI against the pinned Tetragon release.
4. Deploy to a development account.
5. Observe for at least 30 days or a meaningful workload cycle.
6. Canary to an explicitly selected production subset.
7. Roll out only with customer approval and an immediate rollback command.
8. Record deployed policy bundle version in runtime_sensors and every detection.

Tetragon tracing policies and Kubernetes filtering references:

- https://tetragon.io/docs/concepts/tracing-policy/
- https://tetragon.io/docs/reference/tracing-policy/
- https://tetragon.io/docs/concepts/tracing-policy/k8s-filtering/
- https://tetragon.io/docs/concepts/tracing-policy/mode/
- https://tetragon.io/docs/getting-started/enforcement/

## 9. Cloud deployment plans

### 9.1 Linux EC2 pilot

Use a customer-owned CloudFormation stack or an SSM Association that the customer applies. The stack should:

1. Create a restricted instance profile or use an existing customer execution mechanism.
2. Install a version-pinned Tetragon release and Odineyes runtime sensor.
3. Verify kernel compatibility and BTF before activation.
4. Install only the monitoring policy bundle.
5. Retrieve the enrollment artifact from a customer-controlled secure runtime source.
6. Start system services with restart-on-failure and least privilege compatible with eBPF requirements.
7. Send a heartbeat and installation result.

Do not use a generic remote shell command, placeholder download URL, or unverified latest binary in production infrastructure. Pin versions and verify signatures, image digests, or published checksums. Tetragon publishes image/SBOM verification guidance:

https://tetragon.io/docs/installation/verify/

Minimal resource expectations:

- modern Linux kernel with BTF support;
- a pilot node larger than the existing t3.micro control-plane host;
- disk quota for a bounded spool;
- outbound access to the Odineyes ingestion endpoint;
- no inbound network exposure added by the sensor.

### 9.2 EKS using EC2 nodes

Deploy Tetragon through its Helm chart as a DaemonSet so each compatible Linux worker node receives a sensor. Deploy the Odineyes runtime adapter either:

- as a tightly coupled sidecar only if Tetragon export access is safely shared; or
- as a separate privileged DaemonSet that reads only the local Tetragon Unix socket or export directory.

The second option is clearer operationally but adds another privileged workload. The runtime adapter must be independently versioned, secured, and visible in the Sensor inventory.

Use Kubernetes filtering to target selected namespaces, pod labels, containers, or nodes during the pilot. Begin with non-production or a defined production canary, not every node in every cluster.

Relevant guardrails:

- dedicated namespace for runtime security;
- Pod Security Admission exceptions only for the required privileged DaemonSets;
- EKS worker-node security groups and IMDS configuration reviewed before deployment;
- network policy allowing only needed outbound delivery;
- Cluster Autoscaler and node churn tested;
- policy removal and DaemonSet rollback tested.

### 9.3 EKS Fargate and other unsupported compute

Mark these targets unsupported in the Odineyes UI and explain the reason. Continue CSPM findings, cloud audit logs, and vulnerability context for these workloads. Do not claim runtime eBPF coverage where the platform does not permit it.

## 10. CSPM and attack-path correlation

Runtime evidence should change confidence and priority, not create a separate alert silo.

### 10.1 Correlation graph additions

Add the following security-graph node and edge types:

~~~mermaid
flowchart LR
    Internet["Internet"]
    SG["Public security group"]
    Workload["EC2 or Kubernetes workload"]
    CVE["Critical deployed vulnerability"]
    Proc["Suspicious runtime process"]
    Role["Attached IAM role"]
    Data["Sensitive data store"]
    Finding["Runtime-backed attack path"]

    Internet --> SG --> Workload
    CVE --> Workload
    Workload --> Proc
    Workload --> Role
    Role --> Data
    Proc --> Finding
    Workload --> Finding
    Role --> Finding
    Data --> Finding
~~~

Required relationship examples:

- WORKLOAD_HAS_RUNTIME_SENSOR
- SENSOR_OBSERVED_EVENT
- PROCESS_SPAWNED_PROCESS
- PROCESS_RAN_IN_CONTAINER
- WORKLOAD_HAS_VULNERABILITY
- WORKLOAD_IS_EXPOSED_TO
- WORKLOAD_USES_ROLE
- ROLE_CAN_ACCESS
- DATA_STORE_HAS_SENSITIVITY
- RUNTIME_EVENT_CONFIRMS_PATH

### 10.2 Scoring policy

Use evidence tiers:

| Evidence tier | Example | Score effect |
| --- | --- | --- |
| Potential | Public security group plus critical image CVE | Existing CSPM severity |
| Corroborated | Workload executed suspicious downloader | Raise confidence and priority |
| Confirmed chain | Downloader, shell, credential access, and high-privilege role access | Critical attack path and incident workflow |
| Blocked | Tetragon enforcement prevented the configured action | High detection, reduced ongoing exploitability, mandatory review |

A practical rule is:

    final risk = posture risk x runtime confidence x exposure x privilege x data sensitivity

The system should explain the score in plain language and show which event supplied the runtime confidence.

### 10.3 User experience

The current eBPF/Sensors view should become a coverage and evidence page:

- coverage by account, region, cluster, node, and target type;
- active, stale, unsupported, and unhealthy sensor counts;
- kernel/BTF incompatibility and agent-version drift;
- policy bundle version and mode;
- event-delivery lag, local buffering, and drops;
- runtime detections with process tree and sanitized evidence;
- direct link from an attack path to the exact runtime observations;
- suppression, ownership, case status, and remediation verification.

The Attack Path page should only show a runtime-backed path when the event identity maps unambiguously to the relevant workload. A generic role trust relationship alone is not runtime evidence.

## 11. Privacy, security, and operations

### 11.1 Data minimization

Runtime telemetry can contain sensitive command arguments, file paths, hostnames, and occasionally secrets passed incorrectly through process arguments. The default must minimize collection:

- collect allowlisted event types only;
- redact command-line values by pattern and position;
- do not collect process environment variables by default;
- hash or tokenize sensitive paths where exact value is not necessary;
- retain normalized detections longer than raw events;
- store raw evidence only when needed, encrypted, with explicit retention and access audit;
- provide customer-configurable exclusion rules for regulated paths and namespaces.

Tetragon documentation notes that exported events can include sensitive fields and that daemon configuration controls event handling and rate limits:

- https://tetragon.io/docs/concepts/events/
- https://tetragon.io/docs/reference/daemon-configuration/

### 11.2 Availability controls

- Cap local spool storage and report drops as a finding.
- Apply Tetragon export aggregation and rate limits where appropriate.
- Give the adapter CPU, memory, and disk budgets.
- Make telemetry failure fail open during monitoring mode; it must not stop customer workloads.
- In enforcement mode, use policy-specific fail-safe expectations and an immediate policy rollback.
- Monitor sensor heartbeat, event backlog, API rejection rate, and policy rollout health.

### 11.3 Threat model

| Threat | Control |
| --- | --- |
| Forged runtime events | mTLS or scoped short-lived sensor credential, registration-bound account scope, event signature or authenticated transport |
| Replayed batches | Event UUID, sequence range, batch UUID, idempotency record |
| Compromised sensor host | Treat host as untrusted data source, restrict sensor scope, protect credentials, compare account/instance identity, record attestation signals where available |
| Telemetry secrets leakage | Local and server redaction, strict RBAC, encryption, retention controls |
| Attack through Tetragon endpoint | Local Unix socket only; no public gRPC listener |
| Destructive policy rollout | Monitoring first, approval, canary, policy versioning, rollback |
| Excess cloud permissions | Keep scanner and deployment roles separate; default to customer-managed installation |

## 12. Delivery roadmap

### Phase 0: foundation and design

Deliverables:

- document and approve runtime threat model;
- define canonical event schema and data retention policy;
- create runtime_sensors, runtime_detections, policy-bundle, and event schema migrations;
- replace generic internal endpoints with authenticated versioned ingestion;
- mark current shipper and Terraform installer as prototype-only.

Exit criteria:

- a sensor cannot submit an event for another customer account;
- all accepted events have a sensor ID and account ID;
- invalid and replayed batches are rejected predictably;
- sensor health is represented in the database and UI.

### Phase 1: EC2 monitoring pilot

Deliverables:

- version-pinned customer-owned CloudFormation deployment artifact;
- local Tetragon JSON adapter with persistent checkpoint, rotation support, spool, retries, and redaction;
- five to seven high-signal monitoring policies;
- sensor enrollment and heartbeat;
- process-tree and CSPM issue correlation for EC2.

Exit criteria:

- installation works without opening inbound host ports;
- API outage does not lose events within configured spool capacity;
- events deduplicate after restart and rotation;
- one intentionally generated safe test event appears in an attack-path timeline with a clear explanation.

### Phase 2: EKS EC2-node pilot

Deliverables:

- Helm-based Tetragon deployment;
- Odineyes adapter DaemonSet design and security review;
- namespace and workload-label scoped policy canary;
- pod/container/image joins;
- cluster coverage and unsupported Fargate messaging.

Exit criteria:

- node churn and a rolling upgrade do not produce identity confusion;
- a pod event maps to the correct cluster, namespace, pod, container image, and cloud account;
- performance and event volume stay within the pilot budget.

### Phase 3: production hardening

Deliverables:

- local Unix gRPC adapter;
- mTLS enrollment and certificate rotation;
- durable ingestion queue and PostgreSQL migration plan;
- encrypted evidence storage and retention jobs;
- SIEM/webhook integrations;
- fleet policy rollout, canary, and rollback controls.

Exit criteria:

- a revoked sensor cannot submit data;
- certificates rotate without operator action;
- tenant isolation and replay tests pass;
- SLO dashboard shows coverage, event lag, and loss rate.

### Phase 4: enforcement, opt-in only

Deliverables:

- policy approval workflow;
- monitor_only reports and false-positive review;
- per-policy risk classification;
- canary rollout and instant rollback;
- audit history of who approved and deployed enforcement.

Exit criteria:

- customer explicitly enables a named enforcement policy;
- policy has a tested rollback;
- prevention results appear alongside detection evidence;
- the product can prove which action was blocked and why.

## 13. Recommended implementation backlog

### Backend first

1. Add runtime sensor and policy-bundle migrations.
2. Make account_id and sensor_id mandatory for enrolled runtime events.
3. Introduce authenticated sensor enrollment, revocation, and heartbeat endpoints.
4. Replace generic runtime ingestion with the versioned batch endpoint.
5. Add idempotency, sequence validation, throttling, and audit records.
6. Implement redaction before persistence.
7. Update graph correlation with process, container, policy, and runtime-confirmation edges.
8. Add tests for tenant isolation, account spoofing, duplicate batches, rotation, offline spool, and sensitive-data redaction.

### Runtime adapter

1. Convert tetragon_shipper.py into a supported adapter with a persistent state directory.
2. Remove fixed host and node identifiers.
3. Read stable cloud identity from IMDSv2 or Kubernetes Downward API, then verify it at enrollment.
4. Add a bounded local queue and acknowledgement-driven deletion.
5. Add a heartbeat and health-report loop.
6. Implement a local gRPC adapter after the JSON adapter passes pilot validation.

### Frontend

1. Make Sensors a fleet-coverage page based on runtime_sensors, not inferred assets.
2. Add per-sensor detail: compatibility, heartbeat, policy, delivery health, and recent detections.
3. Add a runtime evidence panel to Findings and Attack Paths.
4. Clearly label potential, corroborated, confirmed, and blocked attack paths.
5. Show unsupported platforms and the correct alternative evidence sources.

### Infrastructure

1. Replace placeholder Tetragon install logic with a version-pinned CloudFormation template and checksum or signature verification.
2. Publish the customer-owned template behind the one-click onboarding flow.
3. Keep the scanner trust role read-only.
4. Add a distinct managed-deployment role only after an explicit customer approval flow exists.
5. Do not deploy the runtime sensor on the small Odineyes control-plane host as a default production configuration.

## 14. Acceptance tests

Before calling Tetragon support production-ready, validate:

| Test | Expected outcome |
| --- | --- |
| Sensor sends event from its own account | Accepted and attributed to correct sensor, host, and account |
| Sensor claims another account | Rejected and audited |
| Same batch sent twice | Exactly-once logical processing |
| API unavailable for 15 minutes | Events buffer then deliver in order within configured capacity |
| Log rotation during event stream | No missed or duplicate logical detections |
| Sensor process restart | Checkpoint resumes safely |
| Sensitive argument in process command | Redacted before control-plane persistence |
| EKS pod restart and node replacement | New sensor identity, correct pod and node attribution |
| Unsupported Fargate target | Explicit unsupported status, not false coverage |
| Test web-shell simulation in isolated lab | Corroborated/confirmed path links runtime evidence to CSPM exposure |
| Policy rollback | Monitoring returns safely and audit record is visible |

## 15. Final recommendation

Implement Tetragon as Odineyes Runtime Security, not as an isolated eBPF dashboard.

The near-term product value is not collecting every kernel event. It is proving when a cloud posture risk turns into suspicious behavior, then connecting that behavior to the exposed workload, cloud identity, reachable data, and smallest remediation action.

Start with customer-managed EC2 monitoring, a minimal high-signal policy bundle, authenticated sensors, durable event delivery, and runtime-backed attack-path scoring. Add EKS EC2-node coverage next. Keep EKS Fargate, ECS Fargate, Lambda, Windows, enforcement, and full forensic evidence storage explicitly out of the initial release until the required platform support and operational controls exist.
