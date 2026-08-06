# Failure-injection results

Loom's failure handling is tested by making individual enforcement and storage
dependencies fail. The tests assert that the runtime does not grant access,
leak output, reuse approval, or rerun a side-effecting handler.

## Reproduce the checks

```bash
go test ./runtime -run 'Test.*(Panic|Audit|Failure|Unconfirmed|Idempotency|Quota|Approval)'
go test ./execution ./recovery
go test -race ./runtime ./execution ./recovery
go test -fuzz=FuzzExecute -fuzztime=15s ./runtime/
```

The full release gate is documented in [`BUILD.md`](BUILD.md).

## Recorded scenarios

| Injected failure | Expected behavior | Coverage |
| --- | --- | --- |
| Guardrail panic | Deny and return a safe reason | runtime hardening tests |
| Audit failure after a side effect | Return `executed_unconfirmed` with an execution ID | runtime hardening tests |
| Idempotency completion failure | Keep the reservation, queue recording recovery, never rerun the handler | runtime hardening tests |
| File-store reconciliation write failure | Restore the prior in-memory state and preserve the durable file | execution file-store tests |
| Concurrent reconciliation | One terminal state wins; repeated same-outcome reconciliation is safe | execution file-store tests |
| Recovery verification timeout | Keep the item queued and invoke escalation | recovery worker tests |
| Recovery lease collision | Only one worker processes a live lease | PostgreSQL integration tests |
| Tampered audit event | Hash-chain/checkpoint verification fails | audit integrity tests |

These checks cover library failure paths. Run provider, database failover,
network-partition, multi-node, and upgrade/downgrade tests against the actual
deployment topology before enabling high-risk effects.
