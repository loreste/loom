# Execution recovery worker

Loom never reruns a business handler to resolve an uncertain side effect. If
the handler may have succeeded but durable completion recording failed, Loom
stores an `executed_unconfirmed` execution with an execution ID and queues it
for recovery.

The `recovery` package provides the worker loop for that queue. It claims a
lease, asks the application to verify the external effect, retries durable
recording, reconciles the execution state, and releases the lease. Two workers
cannot own the same live lease, and a record that cannot be confirmed remains
queued and can be escalated.

## Required components

Use a shared `store/postgres.ExecutionStore` for more than one worker. The
file and memory execution stores are useful for development and tests but do
not implement distributed recovery leasing.

The worker requires:

- an `execution.RecoveryQueue`;
- an `execution.Store` for reconciliation;
- a verifier that checks the provider or database without invoking Loom's
  business handler;
- an owner name unique to the worker process;
- an explicit lease duration and polling interval; and
- an escalation handler for unresolved or failed work.

An optional recorder retries idempotency or other durable completion. Recorder
implementations must be safe to call more than once.

## Worker example

```go
worker, err := recovery.NewWorker(recovery.Config{
    Queue:     executionStore, // shared PostgreSQL store
    Store:     executionStore,
    Owner:     os.Getenv("LOOM_RECOVERY_OWNER"),
    Lease:     2 * time.Minute,
    Poll:      5 * time.Second,
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
That integration must use an authoritative provider reference and must not
trust a caller-supplied “success” flag.

## Processing rules

1. Claim one queued record with a short lease.
2. Verify the external effect using a provider or database read.
3. If the result is unknown, alert and release the lease without clearing the
   queue marker.
4. Retry idempotency/audit completion if configured.
5. Reconcile to `allowed` or `denied` only after confirmation.
6. Release the lease as completed.

Recovery errors are observable and retryable. Do not configure an escalator
that silently drops records. Monitor queue depth, oldest queued age, lease
conflicts, verification failures, and reconciliations by operation.

## Operational safeguards

- Give every worker a stable, unique owner name.
- Keep leases shorter than the maximum time a provider lookup can take, or
  renew leases in the deployment layer.
- Require idempotency for side-effecting operations.
- Do not retry the original handler from the worker.
- Stop automated client retries while an execution is uncertain.
- Keep provider references in a controlled integration store, not in raw audit
  input.
- Retain reconciled execution records for the period required by the operation
  and applicable compliance policy.

See [`API.md`](API.md) for status and reconciliation endpoints and
[`OPERATIONS.md`](OPERATIONS.md) for incident handling.
