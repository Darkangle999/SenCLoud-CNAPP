# CSPM scan pipeline refinement

## End-to-end workflow

```text
operator trigger / scheduled cycle
  -> per-account concurrency guard
  -> provider credential/session creation
  -> parallel read-only collection
  -> collection completeness report (type + region)
  -> normalization with per-resource error isolation
  -> transactional asset upsert and drift events
  -> scope-safe stale-asset retirement
  -> findings reconciliation
  -> attack-path issue reconciliation
  -> compliance snapshot
```

The central correctness rule is: **an API failure means unknown, not empty**.
An asset is retired only when the listing operation for its resource type and
region completed successfully. Account-wide operations use a wildcard region.
Denied, truncated, client-initialization, and normalization failures are stored
as scan errors and protect the affected scope from deletion.

## Implemented guarantees

- AWS collection remains parallel and uses adaptive SDK retry, but worker count
  is clamped to 1-64 and every operation now reports success/failure coverage.
- AWS results hitting the 5,000-item operation guard are explicitly partial and
  cannot retire assets. Azure and GCP collectors expose the same completeness
  contract for their account/project-wide storage listings.
- Duplicate resources inside one scan are collapsed before persistence.
- Asset identity is tenant-scoped by `(account_id, cloud_provider, resource_id)`.
  Existing SQLite and PostgreSQL schemas are upgraded in place at initialization.
- Scan jobs are committed before asset persistence. A failed persistence
  transaction leaves a durable `failed` job and `scan_error` instead of vanishing.
- Concurrent scans for the same provider/account are rejected inside one API
  process, preventing two snapshots from interleaving their delete decisions.
- The database layer caches engines/session factories per URL. SQLite uses WAL,
  foreign-key enforcement, a 30-second busy timeout, and query-oriented indexes.
- Asset tag filters execute in SQLite/PostgreSQL JSON queries before pagination;
  finding context loads only assets referenced by the selected findings.
- Scan/mutation endpoints share the operator bearer-token gate when
  `ODINEYES_ADMIN_TOKEN` is configured, and request sizes/regions are bounded.

## Production implementation plan

### P1 - durable scan execution

Move long-running HTTP scans to a durable queue (for example SQS, Redis Streams,
or a PostgreSQL job queue). Return `202` with a job ID, have workers update scan
stages and heartbeats, and let the UI poll or subscribe to progress. Add a lease
timeout so abandoned `running` jobs become failed/retryable.

Use a PostgreSQL advisory lock or lease row keyed by provider/account in the
worker. The in-process guard is correct for the current single-process topology,
but it cannot coordinate multiple API/worker replicas.

### P2 - large-tenant query path

Run production on PostgreSQL, add cursor pagination to findings/issues/
vulnerabilities, persist the computed finding priority used for ordering, and
add GIN indexes only for JSON tag/property filters proven hot by query metrics.
Add retention/partitioning for raw payloads, asset events, scan errors, and
compliance history before those tables become unbounded.

### P3 - collector scale and Go boundary

Profile collection, normalization, and DB commit time separately first. AWS API
latency and throttling usually dominate; the current Python thread pool already
handles that I/O concurrency. Introduce Go only as a stateless collector worker
when profiling shows Python process overhead, memory pressure, or very large
fleet fan-out is material.

The clean Go boundary is:

```text
Go collector worker -> versioned raw-resource batches + coverage report
                    -> existing Python normalization/rules/persistence API
```

Keep rule evaluation, finding lifecycle, compliance semantics, and database
ownership in one service until a versioned event contract and idempotency keys
exist. This avoids duplicating CSPM business logic across languages while still
allowing Go to optimize connection reuse, bounded goroutines, streaming, and
memory use during very large cloud enumerations.

## Operational signals to add next

- scan duration by stage, provider, account, service, and region;
- API calls, throttles, retries, denied scopes, truncated scopes, and resources;
- queue age, worker heartbeat, retry count, and lock contention;
- DB transaction duration, rows upserted/retired, query latency, and table growth;
- a visible partial-scan state in the UI, including protected scopes and errors.
