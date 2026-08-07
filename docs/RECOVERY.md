# Execution recovery worker

Loom never reruns a business handler to resolve an uncertain side effect. If a
handler may have succeeded but durable completion recording failed, Loom stores
an `executed_unconfirmed` execution with an immutable execution ID and queues
it for recovery. The `recovery` package claims a lease, asks the application to
verify the external effect, retries durable recording, reconciles execution
status, and releases the lease.

## Required components

Use a shared `store/postgres.ExecutionStore` when more than one worker may run.
File and memory execution stores are useful for development and tests but do
not provide distributed recovery coordination.

A worker requires:

- an `execution.RecoveryQueue`;
- an `execution.Store` for reconciliation;
- a verifier that checks the provider or database without invoking Loom's
  business handler;
- a unique owner name per worker process;
- an explicit lease duration and polling interval; and
- an escalation handler for operator-review work.

An optional recorder retries idempotency or other durable completion. Recorder
implementations must be safe to call more than once.

## Worker example

```go
worker, err := recovery.NewWorker(recovery.Config{
	Queue:       executionStore,
	Store:       executionStore,
	Owner:       os.Getenv("LOOM_RECOVERY_OWNER"),
	Lease:       2 * time.Minute,
	Poll:        5 * time.Second,
	BackoffBase: 10 * time.Second,
	BackoffMax:  10 * time.Minute,
	MaxAttempts: 8,
	Verifier: recovery.VerifierFunc(func(ctx context.Context, record execution.Record) (recovery.Verification, error) {
		status, err := payments.Lookup(ctx, record.ExecutionID)
		if err != nil {
			return recovery.Verification{}, err
		}
		return recovery.Verification{
			Confirmed: status.Found,
			Outcome:   status.Outcome,
			Note:      status.Reference,
		}, nil
	}),
	Recorder: recovery.IdempotencyRecorder{
		Store: idempotencyStore,
		TTL:   24 * time.Hour,
	},
	Escalator: recovery.EscalatorFunc(func(ctx context.Context, record execution.Record, cause error) error {
		return complianceAlerts.Publish(ctx, record.ExecutionID, cause)
	}),
})
if err != nil {
	return err
}
return worker.Run(ctx)
```

The payment lookup above is application code. Loom does not know how to query
every payment provider, telecom system, database transaction, or job queue.
The integration must use an authoritative provider reference and must not trust
a caller-supplied “success” flag.

## Official CLI worker

The release image includes `loom recovery-worker`. It requires a durable
PostgreSQL-backed platform and an application-owned HTTPS verifier endpoint:

```sh
LOOM_ENV=production \
LOOM_REQUIRE_DURABLE=true \
LOOM_DISABLE_DEMO_PRINCIPALS=true \
LOOM_DATABASE_URL="$LOOM_DATABASE_URL" \
LOOM_REDIS_URL="$LOOM_REDIS_URL" \
LOOM_JWT_SECRET="$LOOM_JWT_SECRET" \
LOOM_JWT_ISSUER="$LOOM_JWT_ISSUER" \
LOOM_JWT_AUDIENCE="$LOOM_JWT_AUDIENCE" \
LOOM_RECOVERY_VERIFIER_URL="https://provider.example/recovery/verify" \
loom recovery-worker
```

The verifier receives JSON containing `execution_id`, `operation`, and
`operation_version`, and returns `confirmed`, `outcome` (`allowed` or `denied`),
and an optional bounded note. It must perform an authoritative provider lookup;
it must not trust a caller-provided success flag. The worker logs only the
execution ID when escalating to operator review.

## Processing and retry rules

1. Claim one queued record with a short-lived lease.
2. Renew the lease while verification, recording, and reconciliation are in
   progress. Renewal is guarded by both execution ID and lease ID.
3. Verify the external effect using a provider or database read.
4. If the result is unknown or a recoverable step fails, persist a safe failure
   category and summary, compute bounded exponential backoff with deterministic
   jitter, and schedule the next attempt.
5. Retry durable idempotency or audit completion when configured.
6. Reconcile to `allowed` or `denied` only after authoritative confirmation.
7. Release the lease after successful reconciliation.
8. After the configured maximum automatic attempts, transition to
   `operator_review` and emit one deduplicated escalation. A worker cannot
   requeue operator-review work; an approved administrative operation must do
   that explicitly.

Recovery code never calls the original handler. A successful provider effect
with a failed recording step remains safe to retry because recording is
idempotent. A successful reconciliation with a failed lease release is also
safe: the next worker observes the terminal state and clears the stale lease.

## Scheduling state

PostgreSQL persists the following operational fields with the execution record:

- `recovery_attempt` — incremented atomically when a lease is claimed;
- `next_attempt_at` — prevents workers from retrying before backoff expires;
- `last_failure_category` and `last_failure_summary` — bounded, non-sensitive
  operator context;
- `recovery_escalated` — prevents duplicate escalation; and
- `state=operator_review` — a dead-letter state requiring approved requeue.

Failure summaries are static categories such as `external verification failed`
or `durable recording failed`; raw provider errors, credentials, request input,
and customer identifiers do not enter execution status or audit output.

## Operational safeguards

- Give every worker a stable, unique owner name.
- Set the lease longer than the worst-case verification, durable-recording, and
  reconciliation duration with a safety margin, and keep heartbeat renewal
  enabled for long-running work.
- Require idempotency for side-effecting operations.
- Do not retry the original handler from a worker.
- Stop automated client retries while an execution is uncertain.
- Keep provider references in a controlled integration store, not raw audit
  input.
- Retain reconciled and operator-review records for the period required by the
  operation and applicable compliance policy.
- Alert on queue depth, oldest queued age, lease conflicts, renewal failures,
  verification failures, retry attempts, dead letters, and reconciliation age.

See [`API.md`](API.md) for execution status and reconciliation endpoints and
[`OPERATIONS.md`](OPERATIONS.md) for incident handling.
