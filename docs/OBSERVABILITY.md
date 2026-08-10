# Observability and compliance logging

Loom is a security enforcement point, so operators need to answer four questions for every governed action:

1. Who made the request, and how was that identity verified?
2. Which operation version, boundary, resource, and adapter were involved?
3. Which control stopped or permitted the request?
4. What happened after the handler ran, including uncertain or reconciled outcomes?

Loom provides structured audit events and a small dependency-free metrics collector. Applications may bridge the same records to OpenTelemetry, Prometheus, SIEM, or an existing compliance platform.

## Official OpenTelemetry bridge

The maintained `observability/otel` package implements `runtime.Observer`. It
records execution counters and duration histograms and annotates the current
OpenTelemetry span when the request context already carries one:

```go
bridge, err := loomotel.New(loomotel.Config{
    Meter:  meterProvider.Meter("loom-app"),
    Tracer: tracerProvider.Tracer("loom-app"),
})
if err != nil {
    return err
}
deps.Observer = bridge
```

The bridge labels only operation, exact operation version, adapter, decision,
outcome, stable reason, and enforcement stage. It never emits execution IDs,
principals, boundaries, credentials, SQL, request bodies, or customer IDs as
metric labels or span attributes. Applications remain responsible for
configuring exporters, sampling, access controls, and retention.

## Audit events

The runtime emits one final `execution.decision` event for each execution attempt. The event records the final decision and the enforcement stage and reason. It is not a verbose trace of every internal function call; this keeps the security record stable and prevents implementation details from becoming a compatibility contract.

Execution status changes also emit lifecycle events when the application calls the reconciliation APIs:

- `execution.reconciliation` records confirmation of an `executed_unconfirmed` attempt.
- `execution.recovery_queued` records that durable idempotency or audit recording recovery was queued.

Events contain bounded, queryable fields including:

- `schema_version`, `event_type`, `protocol_version`;
- `id`, `execution_id`, `trace_id`, and `prior_audit_id`;
- principal, delegator, authentication method, boundary, tenant, and adapter;
- operation and exact operation version, resource type and resource ID;
- declared effects and evaluated risk;
- decision, outcome, enforcement stage, stable reason code, and a scrubbed message;
- approval, quota, and idempotency states;
- execution state, recovery status, reconciliation note, and reliability warning;
- duration, requested output-field count, and returned output-field count;
- SHA-256 digests of redacted input and filtered output.

The audit event does not contain credentials, approval tokens, idempotency keys, raw SQL, or unrestricted request bodies. Input and metadata are redacted at the audit logger boundary. Opaque values that are useful for correlation are represented by digests. A custom sink must treat the `audit.Event` as sensitive and must not add the original request to it.

## Sinks and durability

Use the sink appropriate to the deployment:

- `audit.MemorySink` is for tests and local development only.
- `audit.WriterSink` writes JSON Lines to an `io.Writer`; use an fsync-backed file or managed log exporter when durability matters.
- `audit.NewDurableWriterSink` records that the application has established durable delivery.
- `audit.MultiSink` fans out to several sinks and reports the first write error after attempting all sinks.
- `store/postgres.NewAuditSink` stores structured events in PostgreSQL and is suitable for shared deployments when the database, backup, access control, and retention plan are managed correctly.

In production, configure a durable audit sink and export it to an access-controlled, append-only or WORM-capable destination when required by policy. The database table or JSONL file alone is not automatically an immutable compliance archive.

## Tamper-evident audit streams

Wrap the selected sink with `audit.NewHashChainSink` when the deployment needs
to detect modification or deletion inside the audit store:

```go
sink := audit.NewHashChainSink(durableSink, previousCheckpointHash)
logger := audit.NewLogger(sink)
```

Each event contains `prev_event_hash` and `event_hash`. The chain advances only
after the underlying sink accepts the event. On restart, load the last hash
from a trusted checkpoint or start a deliberately separate chain; never infer
it from untrusted log input.

Verify exported events before using them as compliance evidence:

```go
if err := audit.VerifyChain(events, trustedPreviousHash); err != nil {
    return fmt.Errorf("audit integrity check failed: %w", err)
}
if err := audit.VerifyCheckpoint(events, checkpoint, signer); err != nil {
    return fmt.Errorf("audit checkpoint check failed: %w", err)
}
```

`audit.CreateCheckpoint` produces a signed terminal hash when supplied with a
caller-managed signer. The included HMAC helper requires a 32-byte key and is
appropriate only when the key is managed separately. Regulated deployments
should use a KMS/HSM-backed `audit.CheckpointSigner`, store checkpoints in an
access-controlled immutable location, restrict direct database writes, and
retain WORM/object-storage exports according to policy. Hash chaining detects
tampering; it does not make a mutable database immutable by itself.

`audit.HashChainSink` coordinates its chain head with a mutex inside one
process. It is suitable for one writer per stream only; multiple replicas can
otherwise create branches if they start from the same previous hash. For
multi-node deployments, use `store/postgres.NewAuditSinkForStream` with a
stable stream ID. PostgreSQL then owns `loom_audit_chain_heads`, assigns
sequence numbers under `SELECT ... FOR UPDATE`, verifies the previous hash,
enforces unique `(audit_stream, sequence_no)`, and records the active
checkpoint ID. Use `AuditSink.RotateStream` for a checkpoint/rotation and
`AuditSink.ChainHead` when exporting the trusted head. `AuditSink.ExportStream`
exports and verifies a bounded contiguous sequence range against a trusted
prior hash; never take that prior hash from the same untrusted export. Do not
wrap a coordinated PostgreSQL sink in a separate process-local hash chain.

## Correlation workflow

Use `execution_id` for one governed attempt and `trace_id` for the request or distributed trace. The response includes both the execution ID and audit ID when available. For a replay, `prior_audit_id` links the replay event to the original audit event.

For an uncertain side effect:

1. Stop automatic retries.
2. Search audit storage by `execution_id` and `trace_id`.
3. Check the external provider or database using its own reference.
4. Call the authenticated reconciliation endpoint with the confirmed outcome.
5. Resume only after the execution status is no longer uncertain.

`retry_recording` queues durable recording work only. It never runs the business handler again.

## Metrics

`runtime.Metrics` exposes counters for:

- total, allowed, and denied execution attempts;
- cumulative execution duration;
- idempotent replays and conflicts;
- approval-required and quota-rejected decisions;
- `executed_unconfirmed` outcomes;
- denials grouped by enforcement stage and stable reason code.

The HTTP adapter exposes Prometheus text at `GET /metrics`. The built-in collector exports fixed execution-latency buckets, an in-flight execution gauge, durable-store aggregate latency/error counters, recovery queue depth/age/attempt/renewal/dead-letter signals, and webhook outbox depth/age/attempt/delivery/failure/dead-letter signals. Protect the endpoint with the same network and identity controls used for other operational endpoints. Applications should add deployment-specific labels and backend metrics without exposing credentials, request bodies, SQL, or customer identifiers.

`loom_execute_duration_seconds` is a complete histogram family (`_bucket`, `_sum`, `_count`), so both `histogram_quantile` and `rate(_sum)/rate(_count)` work. `loom_execute_duration_seconds_total` carries the same cumulative value as `_sum` and is retained only for existing scrapers.

The recovery signals are populated by the recovery worker, which reports queue depth and oldest-record age from an indexed count. `loom recovery-worker` wires this automatically. An application that embeds `recovery.Worker` directly must set `recovery.Config.Observer` (`runtime.Metrics` satisfies it), or the recovery series will stay at zero and any alert built on them will never fire.

Webhook outbox signals are populated by `loom webhook-worker` (or an in-process worker when `LOOM_WEBHOOK_RUN_WORKER=true`) via `runtime.Metrics` as `webhook.WorkerObserver`. Snapshot keys include `webhook_depth`, `webhook_oldest_age_seconds`, `webhook_attempts`, `webhook_deliveries`, `webhook_failures`, and `webhook_dead_letters`. They never include event IDs, URLs with credentials, or payload contents.

## Recommended alerts and dashboards

Track at least:

- denial rate by operation, adapter, stage, reason, and policy version;
- audit-write failures and time since the last successful audit event;
- `executed_unconfirmed` count and oldest record age;
- recovery queue depth, lease conflicts, and retry failures;
- webhook outbox depth, oldest age, delivery failures, and dead letters;
- approval consumption conflicts and quota rejection rate;
- idempotency conflicts and replay rate;
- operation latency, in-flight executions, and durable-store latency;
- policy reload/version status and readiness failures (including OIDC JWKS);
- adapter request count and latency.

Do not use credentials, tokens, SQL, request bodies, tenant secrets, or high-cardinality customer identifiers as metric labels or span attributes. Prefer operation version, adapter, decision, stage, and stable reason code.

## Retention and access control

Define retention by operation class and applicable financial, privacy, security, and regulatory requirements. Retention is an application and deployment responsibility; Loom does not choose a universal period. Restrict audit reads, separate operational readers from writers, encrypt storage and backups, and monitor deletion or export jobs. Preserve the original event schema version when exporting so future readers can interpret historical records.

Audit logging supports compliance evidence; it does not replace database audit logging, payment-provider records, PostgreSQL RLS, identity-provider logs, or an immutable archival system where those controls are required.
