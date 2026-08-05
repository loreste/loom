# How-to guide

These recipes assume a development checkout and keep Loom's deny-by-default
behavior visible.

## Register a governed operation

```go
op := &core.Operation{
    Name:        "invoice.read",
    Version:     "1",
    Permissions: []string{"invoice.read"},
    Resources:   []string{"invoice"},
    Effects:     []core.Effect{core.EffectRead},
    InputSchema: json.RawMessage(`{"type":"object","required":["id"]}`),
}

err := a.Register(op, func(ec *core.ExecutionContext) (*core.Result, error) {
    return &core.Result{Output: map[string]any{"id": ec.Input["id"]}}, nil
})
```

Grant every layer explicitly:

```go
_ = a.AddUser(principal, token, boundary, []string{"invoice.read"})
_ = a.AllowPolicy(policy.Rule{
    Principal: principal, Boundary: boundary, Operation: "invoice.read",
})
_ = a.AllowResource(resource.Rule{
    Principal: principal, Boundary: boundary, Type: "invoice", ID: "*",
    Operations: []string{"invoice.read"},
})
_ = a.AllowFields(principal, boundary, "invoice.read", []string{"id"})
_ = a.AllowInputFields(principal, boundary, "invoice.read", []string{"id"})
```

Call it through the single entrypoint:

```go
resp := a.Call(ctx, core.Request{
    Operation: "invoice.read",
    OperationVersion: "1",
    Credentials: core.Credentials{Scheme: "bearer", Token: token},
    Boundary: boundary,
    Resource: &core.ResourceRef{Type: "invoice", ID: invoiceID},
    Input: map[string]any{"id": invoiceID},
})
if !resp.Allowed {
    return fmt.Errorf("invoice read denied: %s", resp.Denial.Reason)
}

// For a side-effecting operation, an executed_unconfirmed outcome means the
// handler may have run. Check status/reconciliation using resp.ExecutionID
// before retrying; do not treat it as an ordinary safe denial.
if resp.Outcome == core.OutcomeExecutedUnconfirmed {
    log.Printf("reconcile execution %s before retry", resp.ExecutionID)
}
```

## Govern database access

## Schema and financial inputs

Loom validates a declared `OutputSchema` after the handler returns. The
supported Loom Schema subset is documented in the guardrails package and
rejects unsupported keywords rather than silently ignoring them. Use nested
`items`, `properties`, `required`, `additionalProperties`, enums/constants,
length and range constraints, and declare only the keywords Loom supports.

Money operations must use `core.Money` limits and include a three-letter
currency. Do not compare payment amounts as `float64`; handlers should call
`core.ParseMoney` and compare exact values.

Input field grants are separate from output projection grants:

```go
_ = a.AllowFields(principal, boundary, "customer.update", []string{"id", "name"})
_ = a.AllowInputFields(principal, boundary, "customer.update", []string{"name"})
```

This allows a caller to read a field without implicitly allowing it to change
that field.

Prefer domain operations with fixed SQL. If a controlled administrative tool
needs SQL, register a pool with an allowlist, enable `db.query` or `db.exec`,
and grant access to the specific principal and boundary.

```go
_ = a.OpenDB("primary", "pgx", os.Getenv("DATABASE_URL"), db.Options{
    AllowedTables: []string{"public.invoices"},
    MaxRows: 500,
    StatementTimeout: 5 * time.Second,
})
_ = a.EnableDBOps()
```

Loom rejects multi-statement input, comments, DDL, dangerous functions, and
tables outside the configured allowlist. Use restricted database roles,
PostgreSQL RLS, timeouts, and tenant-bound transactions as defense in depth.

## Expose the same runtime over HTTP

```bash
go run ./cmd/loom serve --addr=:8080
```

The primary endpoint is `POST /v1/execute`. Discovery is at
`/.well-known/loom.json`; capability-filtered OpenAPI is at
`/v1/openapi.json`. MCP, GraphQL, gRPC, and Weft are adapters over the same
pipeline, not alternate authorization paths.

## Add approvals and idempotency

Mark sensitive operations with approval and idempotency requirements:

```go
op.Approval = core.ApprovalPolicy{MinRisk: core.RiskHigh}
op.Idempotency = core.IdempotencyPolicy{Required: true, TTLSeconds: 3600}
```

The runtime evaluates approval, reserves the idempotency key, consumes the
single-use approval immediately before the handler, and audits the result. A
failed handler burns the approval token by design. Clients must reuse the same
idempotency key for a safe retry.

## Run background jobs safely

Use `job.Runner` with an `app.App` or runtime caller. Every queued job becomes
a request and passes the full pipeline.

```go
runner := &job.Runner{Queue: queue, Caller: a, Token: serviceToken}
```

The queue is delivery infrastructure, not a privilege path.

## Add metrics and tracing

`app.App` and `bootstrap.Platform` expose a `runtime.Metrics` collector. Pass it
to the HTTP adapter for Prometheus text metrics:

```go
srv, _ := loomhttp.NewServer(a.Runtime, loomhttp.ServerConfig{
    Metrics: a.Metrics,
})
```

For OpenTelemetry, implement `runtime.Observer` and attach it through
`runtime.Dependencies.Observer`. Keep credentials, SQL, request bodies, and
tenant secrets out of labels and span attributes. See
[OBSERVABILITY.md](OBSERVABILITY.md).

## Test an adversarial path

For every new control, add a test attempting to bypass it: wrong tenant,
missing policy, forged adapter metadata, replayed approval, duplicate
idempotency key, unsafe SQL, unexpected output field, canceled context, or a
panicking guardrail.

```bash
go vet ./...
go test -race ./...
go test -fuzz=FuzzExecute -fuzztime=10s ./runtime/
```
