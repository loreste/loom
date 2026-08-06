# How-to guide

These recipes assume a development checkout. They show the explicit grants and
the single execution path that Loom requires.

## Register an operation

```go
op := &core.Operation{
    Name:        "invoice.read",
    Version:     "1",
    Permissions: []string{"invoice.read"},
    Resources:   []string{"invoice"},
    Effects:     []core.Effect{core.EffectRead},
    InputSchema: json.RawMessage(`{"type":"object","required":["id"]}`),
    OutputSchema: json.RawMessage(`{
        "type":"object",
        "required":["id"],
        "properties":{"id":{"type":"string"}}
    }`),
}

err := a.Register(op, func(ec *core.ExecutionContext) (*core.Result, error) {
    return &core.Result{
        Output: map[string]any{"id": ec.Input["id"]},
    }, nil
})
```

An operation version is part of the execution contract. Keep it stable for the
life of the contract and register a new version when the input, output, or
authorization meaning changes.

## Grant access explicitly

```go
_ = a.AddUser(principal, token, boundary, []string{"invoice.read"})
_ = a.AllowPolicy(policy.Rule{
    Principal: principal,
    Boundary:  boundary,
    Operation: "invoice.read",
})
_ = a.AllowResource(resource.Rule{
    Principal:  principal,
    Boundary:   boundary,
    Type:       "invoice",
    ID:         "*",
    Operations: []string{"invoice.read"},
})
_ = a.AllowFields(principal, boundary, "invoice.read", []string{"id"})
_ = a.AllowInputFields(principal, boundary, "invoice.read", []string{"id"})
```

Input-field grants and output-field grants are separate. A caller may be
allowed to see a field without being allowed to change it.

## Call through the runtime

```go
resp := a.Call(ctx, core.Request{
    Operation:        "invoice.read",
    OperationVersion: "1",
    Credentials:      core.Credentials{Scheme: "bearer", Token: token},
    Boundary:         boundary,
    Resource:         &core.ResourceRef{Type: "invoice", ID: invoiceID},
    Input:            map[string]any{"id": invoiceID},
})
if !resp.Allowed {
    return fmt.Errorf("invoice read denied: %s", resp.Denial.Reason)
}
```

For a side-effecting call, `OutcomeExecutedUnconfirmed` means the handler may
have run even though durable completion was not confirmed. Query and reconcile
the execution record before retrying:

```go
if resp.Outcome == core.OutcomeExecutedUnconfirmed {
    record, err := a.Runtime.ExecutionStatus(ctx, resp.ExecutionID)
    if err != nil {
        return err
    }
    _ = record
    // Confirm the external result, then reconcile with the confirmed outcome.
}
```

Remote callers can use the corresponding endpoints:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $LOOM_TOKEN" \
  "http://127.0.0.1:8080/v1/executions/$EXECUTION_ID"

curl --fail-with-body -X POST \
  -H "Authorization: Bearer $LOOM_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"outcome":"allowed","note":"confirmed by payment provider"}' \
  "http://127.0.0.1:8080/v1/executions/$EXECUTION_ID/reconcile"
```

Reconciliation records what happened; it never reruns the business handler.

## Govern database access

Prefer domain handlers with fixed, parameterized SQL. If an administrative
operation genuinely needs governed SQL, register an allowlisted pool and grant
the caller the `db.query` or `db.exec` capability:

```go
_ = a.OpenDB("primary", "pgx", os.Getenv("DATABASE_URL"), db.Options{
    AllowedTables:    []string{"public.invoices"},
    MaxRows:          500,
    StatementTimeout: 5 * time.Second,
})
_ = a.EnableDBOps()
```

Loom rejects multi-statement input, comments, DDL/admin statements, dangerous
functions, and tables outside the configured allowlist. Use restricted roles,
PostgreSQL RLS, statement timeouts, connection limits, and tenant-bound
transactions as additional database controls. Loom does not provide row-level
tenant isolation by itself.

## Use exact financial values

Money effects use `core.Money`, not `float64`:

```go
amount, err := core.ParseMoney(input["amount"], "USD")
if err != nil {
    return err
}
_ = amount

op.AllowedCurrencies = []string{"USD", "EUR"}
```

The three-letter currency code is syntactically validated. Operations should
set `AllowedCurrencies` when only specific currencies are acceptable. Use
`core.MoneyDelta` for signed ledger adjustments rather than weakening the
non-negative payment amount type.

## Require approval and idempotency

```go
op.Approval = core.ApprovalPolicy{MinRisk: core.RiskHigh}
op.Idempotency = core.IdempotencyPolicy{
    Required:   true,
    TTLSeconds: 3600,
}
```

The runtime validates approval, reserves idempotency, charges quota, and claims
the single-use approval before the handler runs. A failed handler does not
restore a consumed approval token. Clients should reuse the same idempotency
key when retrying an operation.

## Configure durable execution status

Side-effecting production operations need an `execution.Store` that survives a
process restart. PostgreSQL is the shared option for multiple replicas:

```go
bundle, err := postgres.NewBundle(ctx, os.Getenv("LOOM_DATABASE_URL"))
if err != nil {
    return err
}
defer bundle.Close()

a, err := app.New(app.Config{
    Environment:       "production",
    ApprovalEngine:     bundle.Approvals,
    IdempotencyStore:   bundle.Idempotency,
    ExecutionStore:     bundle.ExecutionStatus,
    AuditSink:          bundle.Audit,
})
```

For a single node, bootstrap with `DataDir` to use file-backed execution,
approval, idempotency, and audit state. The file store is not a multi-node
coordination system. PostgreSQL recovery workers claim short-lived leases to
complete durable recording; they must not rerun a business handler.

## Run background jobs safely

Use `job.Runner` with an `app.App` or runtime caller. Queue delivery is not a
privilege path: every job becomes a request and passes the full pipeline.

```go
runner := &job.Runner{
    Queue:  queue,
    Caller: a,
    Token:  serviceToken,
}
```

## Expose the same runtime over HTTP

```bash
go run ./cmd/loom serve --addr=:8080
```

The primary endpoint is `POST /v1/execute`. Discovery is available at
`/.well-known/loom.json`; capability-filtered OpenAPI is available at
`/v1/openapi.json`. MCP, GraphQL, gRPC, CLI, and Weft remain adapters over the
same runtime.

## Add metrics and tracing

`app.App` and `bootstrap.Platform` expose a `runtime.Metrics` collector. Pass
it to the HTTP adapter to expose Prometheus text metrics:

```go
srv, _ := loomhttp.NewServer(a.Runtime, loomhttp.ServerConfig{
    Metrics: a.Metrics,
})
```

For OpenTelemetry or an existing metrics system, attach a
`runtime.Observer` through `runtime.Dependencies.Observer`. Do not put tokens,
SQL, request bodies, or tenant secrets in labels or span attributes. See
[`OBSERVABILITY.md`](OBSERVABILITY.md).

## Test an adversarial path

For every new control, add a test that tries to bypass it: wrong tenant,
missing policy, forged adapter metadata, replayed approval, duplicate
idempotency key, unsafe SQL, unexpected output, canceled context, or a
panicking guardrail.

```bash
go vet ./...
go test -race ./...
go test -fuzz=FuzzExecute -fuzztime=15s ./runtime/
```
