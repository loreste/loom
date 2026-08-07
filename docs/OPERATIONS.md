# Production operations runbook

Loom sits on the path to sensitive application operations. Treat it as a
security and reliability dependency, not only as middleware.

## Before deployment

1. Register every sensitive action as a versioned operation.
2. Declare effects, input/output schemas, sensitive fields, approval rules,
   idempotency requirements, and quota policy.
3. Inject a production identity verifier and document issuer, audience,
   algorithm, key-rotation, certificate-rotation, and revocation behavior.
4. Disable demo principals and generated development secrets.
5. Choose durable stores from the operation effects:
   - file-backed state for a single node;
   - PostgreSQL for shared approval, audit, idempotency, policy, and execution
     state; and
   - Redis for shared quotas.
6. Configure database roles, RLS, tenant-bound transactions, timeouts, and
   connection limits independently of Loom's SQL guard.
7. Protect `/metrics`, `/readyz`, execution status, reconciliation, and any
   admin operation with deployment-appropriate controls.
8. Run the adversarial and cross-adapter test suites against the release.

## Storage selection

| Deployment | Recommended state |
| --- | --- |
| Local development | Memory defaults or a temporary data directory. |
| Single-node service | `DataDir` or `LOOM_DATA_DIR` for file-backed state. |
| Multiple replicas | PostgreSQL bundle for durable shared state and Redis for shared quotas. |
| High-risk side effects | Durable execution, idempotency, approval, quota, and audit components before startup. |

Do not use a file store as a multi-node lock or coordination mechanism. Do not
assume a process-local quota, idempotency key, approval, or execution record
survives failover.

Start at least one configured [`recovery` worker](RECOVERY.md) for each shared
execution store. Alert when the queue is not draining, when the oldest item
exceeds its recovery objective, or when verification repeatedly escalates.

## Startup and readiness

Use `/healthz` for process health and `/readyz` for dependency readiness. A
healthy process can still be unready if PostgreSQL, Redis, policy loading, or a
required audit sink is unavailable.

Treat readiness failures as deployment events. Do not route production traffic
to an instance whose durable security dependencies are not ready.

`/readyz` probes PostgreSQL and Redis automatically. It cannot probe a
dependency the application constructed itself, including an identity verifier.
Register those through `bootstrap.Config.ReadyChecks`; an OIDC deployment
should pass `verifier.ReadyCheck()`, which fails until issuer discovery and the
JWKS fetch have both succeeded. Without it, a process that never reached its
identity provider reports ready and then denies every authenticated request.

## Side-effect failure handling

Every side-effecting operation should use idempotency. If Loom returns
`executed_unconfirmed`:

1. retain the execution ID;
2. query execution status;
3. inspect the external system using its provider reference or audit trail;
4. reconcile the confirmed outcome; and
5. retry the business operation only when the external result is known not to
   have occurred.

`retry_recording` is safe for durable recording recovery but never reruns the
handler. Recovery workers claim leases so two workers do not complete the same
record concurrently. Configure the official worker with an authoritative
provider verifier and an escalation destination. A worker must never call the
original handler.

## Observability

Alert on:

- readiness failures;
- audit-write failures;
- growth or age of the recovery queue;
- `executed_unconfirmed` records;
- reconciliation conflicts;
- idempotency conflicts and replay spikes;
- approval and quota rejection changes;
- policy reload failures; and
- latency or denial changes by adapter and operation.

Do not log raw credentials, approval tokens, SQL, request bodies, or secret
fields. Use execution IDs, trace IDs, stable reason codes, and redacted audit
fields for incident correlation.

## Database and tenant operations

Loom's SQL classifier is defense in depth. Keep application database roles
restricted and verify that tenant roles do not own shared tables or have
`BYPASSRLS`. Test both application-layer boundary denial and database-layer RLS
denial.

Break-glass access must be a separate, short-lived, approved operation with an
explicit target tenant and a complete audit record.

## Upgrades and retention

Before upgrading:

1. read the changelog and compatibility contract;
2. apply forward-compatible database migrations;
3. run SDK and adapter conformance tests;
4. test rollback or fail-forward behavior against a copy of production data;
5. verify policy versions and operation-version compatibility; and
6. keep the previous release available until health and reconciliation queues
   are stable.

Archive terminal execution records before purging them. Retention periods must
match audit, financial, tenant, and regulatory requirements. A purge is not a
substitute for an archive or backup.

## Audit operations

For each production deployment, document the audit sink, backup/export path, retention period, reader and writer identities, encryption controls, and alert owner. Verify that an audit event can be found by `execution_id` and `trace_id` from both the application response and the durable sink.

At minimum, alert on audit-write failures, no successful audit events within the expected interval, growing `executed_unconfirmed` age, recovery queue failures, and reconciliation conflicts. Treat an audit delivery failure after a handler side effect as an uncertain outcome and reconcile before allowing automated retries.

For JSONL deployments, ship the file as structured JSON without rewriting fields, rotate it without truncating unexported records, and preserve `schema_version`. For PostgreSQL deployments, restrict direct writes, grant readers only the columns and rows they need, back up `loom_audit`, and export terminal history before retention cleanup.

When tamper evidence is required, wrap the audit sink with
`audit.NewHashChainSink`, periodically create signed checkpoints, and export
both events and checkpoints to an immutable destination. Verify the chain
before investigations, retention exports, and compliance reports. Keep the
checkpoint signing key outside Loom and rotate it under the organization's key
management policy.

## Operator CLI

The CLI provides operator-safe diagnostics without a private state bypass:

```sh
loom execution get <execution-id> --url=https://loom.example --token="$LOOM_TOKEN"
loom policy lint --input=policy.json
loom policy test --input=policy-with-tests.json
loom policy explain --input=policy.json --principal=user:alice --boundary=dev --operation=document.read
loom policy simulate --input=policy.json --principal=user:alice --boundary=dev --operation=document.read
loom policy diff --from=old-policy.json --to=new-policy.json
loom audit head --input=/var/log/loom/audit.jsonl --initial-hash="$TRUSTED_HEAD"
loom audit verify --input=/var/log/loom/audit.jsonl --initial-hash="$TRUSTED_HEAD"
loom audit export --input=/var/log/loom/audit.jsonl --from=100 --to=200 --initial-hash="$TRUSTED_HEAD"
LOOM_AUDIT_CHECKPOINT_KEY="$CHECKPOINT_KEY" loom audit checkpoint --input=/var/log/loom/audit.jsonl
LOOM_AUDIT_CHECKPOINT_KEY="$ROTATED_KEY" loom audit rotate --input=/var/log/loom/audit.jsonl
loom recovery-worker --verifier-url=https://provider.example/recovery/verify
loom recovery list --url=https://loom.example --token="$LOOM_TOKEN" --boundary=ops
loom recovery requeue --execution-id="$EXECUTION_ID" --url=https://loom.example --token="$LOOM_TOKEN" --boundary=ops --idempotency-key="$IDEMPOTENCY_KEY" --approval-token="$APPROVAL_TOKEN"
loom recovery dead-letter --execution-id="$EXECUTION_ID" --url=https://loom.example --token="$LOOM_TOKEN" --boundary=ops --idempotency-key="$IDEMPOTENCY_KEY" --approval-token="$APPROVAL_TOKEN"
```

`execution get` uses the authenticated execution-status endpoint and follows
the same capability checks as other adapters. `audit verify` is offline and
checks a JSONL hash chain against a trusted prior head; it does not trust a
head read from the same untrusted file. `audit export` verifies a bounded
segment before writing JSONL to stdout. `audit checkpoint` reads its signing
key only from `LOOM_AUDIT_CHECKPOINT_KEY`; do not pass checkpoint keys as
command-line arguments. `policy test` accepts the normal versioned policy
document plus a bounded `tests` array. Each fixture supplies `principal`,
`boundary`, `operation`, optional `version` and `capabilities`, and an
`expected` value of `allow` or `deny`. `audit rotate` creates a newly signed
checkpoint with the currently configured signer; archive the prior checkpoint
before rotating and use a KMS/HSM-backed secret in production. The recovery worker is documented in
[`RECOVERY.md`](RECOVERY.md) and never invokes a business handler.

## Incident response

When Loom denies unexpectedly, capture the trace ID, execution ID, operation
version, denial reason, stage, policy version, and dependency readiness state.
When an external side effect is uncertain, stop automated retries, reconcile the
execution, and inspect the external provider before resuming traffic.

Report security vulnerabilities privately rather than including secrets or
customer data in public issues. See [`SECURITY.md`](SECURITY.md).
