# HTTP API

The HTTP adapter is an optional network edge. It translates HTTP requests into
the same `runtime.Runtime.Execute` path used by embedded calls, workers, MCP,
GraphQL, gRPC, CLI, and Weft.

## Start a development server

```bash
export LOOM_TOKEN="loom-dev-$(openssl rand -hex 24)"
export LOOM_DEMO_TOKEN_ALICE="$LOOM_TOKEN"
go run ./cmd/loom serve --addr=:8080
```

Use a real identity verifier and TLS deployment outside development. The
development token is a seeded demo credential, not a general API key.

## Execute an operation

`POST /v1/execute` accepts:

```json
{
  "operation": "document.read",
  "operation_version": "1",
  "boundary": "dev",
  "resource": {"type": "document", "id": "doc-1"},
  "input": {"id": "doc-1"},
  "fields": ["id", "title"],
  "idempotency_key": "read-doc-1",
  "approval_token": "...",
  "metadata": {"client": "example"}
}
```

Authentication is taken from `Authorization: Bearer ...` or a verified mTLS
peer certificate. Authorization headers take precedence over request-body
metadata. The adapter also accepts:

- `Idempotency-Key` when the body does not provide `idempotency_key`;
- `X-Approval-Token` when the body does not provide `approval_token`; and
- `X-Trace-Id` for correlation.

Example:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $LOOM_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'X-Loom-Protocol-Version: 1' \
  -d '{
    "operation":"document.read",
    "operation_version":"1",
    "boundary":"dev",
    "resource":{"type":"document","id":"doc-1"},
    "input":{"id":"doc-1"}
  }' \
  http://127.0.0.1:8080/v1/execute
```

The response is a `core.Response` JSON object. Important fields are
`Allowed`, `Decision`, `Outcome`, `ExecutionID`, `OperationVersion`, `Denial`,
`Output`, `TraceID`, `AuditID`, `IdempotentReplay`, and
`ReliabilityWarning`.

Output is present only after the runtime validates and filters it. A denial
does not include handler output.

## HTTP status behavior

The response body contains the structured Loom decision. The HTTP status also
communicates the broad result:

| Status | Meaning |
| ---: | --- |
| `200` | Allowed execution or successful status/reconciliation request. |
| `400` | Invalid JSON, unknown operation/schema, or malformed request. |
| `401` | Missing or invalid credentials. |
| `403` | Authenticated request denied by policy or another gate. |
| `409` | Idempotency conflict. |
| `424` | Approval is required. |
| `422` | Guardrail rejected the request. |
| `429` | Quota exceeded. |
| `503` | Readiness or dependency failure. |

The exact machine-readable denial reason is more useful than the HTTP status.
Clients should branch on the response reason and outcome, not only the status
code.

## Execution status and reconciliation

Side-effecting operations can return `Outcome: "executed_unconfirmed"` with an
execution ID. Do not blindly retry. Query the status first:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $LOOM_TOKEN" \
  http://127.0.0.1:8080/v1/executions/$EXECUTION_ID
```

After confirming the external result, reconcile it:

```bash
curl --fail-with-body -X POST \
  -H "Authorization: Bearer $LOOM_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"outcome":"allowed","note":"confirmed by provider"}' \
  http://127.0.0.1:8080/v1/executions/$EXECUTION_ID/reconcile
```

`POST /v1/executions/{execution_id}/retry_recording` retries durable recording
only. It never reruns the business handler. Status, reconcile, and recording
retry require authenticated access and are subject to execution ownership and
policy checks.

## Operational endpoints

| Method and path | Authentication | Purpose |
| --- | --- | --- |
| `GET /healthz` | None | Process health. |
| `GET /readyz` | None | Dependency readiness; may return `503`. |
| `GET /.well-known/loom.json` | None | Static service discovery without operation data. |
| `GET /v1/openapi.json` | Caller | Capability-filtered OpenAPI when configured. |
| `GET /metrics` | Configurable | Prometheus text metrics when configured. |
| `POST /mcp` | Caller | MCP JSON-RPC adapter when configured. |
| `POST /graphql` | Caller | GraphQL adapter when configured. |

Protect operational endpoints according to the deployment's network and
identity controls. Discovery is intentionally static and does not grant access.

## Compliance correlation

Successful, denied, replayed, and uncertain executions return an `execution_id`, `trace_id`, and, when audit delivery succeeds, an `audit_id`. The exact selected `operation_version` is returned as well. Pass `X-Trace-Id` at the edge when a caller already has a distributed trace; Loom preserves it in the response and audit event.

An `executed_unconfirmed` outcome means the handler may have performed a side effect but Loom could not complete durable post-execution recording. Treat it as an operationally uncertain result: query status, inspect the external system, then reconcile. Do not blindly retry.

Audit events never expose credentials, approval tokens, idempotency keys, raw SQL, or unrestricted request bodies. Request and metadata values are redacted and correlation digests are used where useful.

## Convenience routes

`POST /v1/approvals` and `POST /v1/catalog` are convenience aliases. They still
enter the full runtime as `approval.issue` and `catalog.list`; they are not
privilege shortcuts.

## Protocol version

Send `X-Loom-Protocol-Version: 1` and preserve the same header on responses.
Operation versions are separate from this protocol version. See
[`COMPATIBILITY.md`](COMPATIBILITY.md).
