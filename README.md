# Loom

Loom is an embed-first governance runtime for Go applications. It puts one
controlled execution path in front of operations that call handlers, access a
database, run jobs, change payments or credit, provision services, or perform
administrative work.

Loom has been used internally for the past two months. We are now making it
available as open source so the implementation, examples, and trade-offs can
be reviewed and used by other teams.

## Why it exists

Sensitive operations usually acquire several entry points as an application
grows: an HTTP endpoint, a worker, an internal service, an administrative CLI,
an MCP tool, or code running in the same process. When each entry point carries
its own checks, the rules can diverge.

That divergence creates practical problems:

- one transport checks a permission that another transport misses;
- a worker can perform an operation that the user-facing path rejects;
- application code reaches the database without the same policy checks;
- retries repeat an operation with side effects;
- tenant context is lost before a database query runs; and
- an operator cannot easily see which check caused a denial.

Loom addresses this by making the operation, rather than the transport, the
unit of authorization. HTTP, MCP, GraphQL, gRPC, Weft, workers, and in-process
callers can all reach the same runtime.

## How it works

Application code registers named operations and invokes them through
`app.Call` or `runtime.Runtime.Execute`:

```text
caller or adapter
        → identity and boundary checks
        → operation and resource policy
        → contextual policy and guardrails
        → risk, approval, idempotency, and quota checks
        → handler or governed database executor
        → output filtering and audit
```

The default decision is deny. Unknown operations, missing rules, failed
verification, invalid boundaries, and enforcement errors fail closed. Approval
tokens are consumed before side effects, and idempotency can protect retries.

Database access is registered through Loom's database layer rather than passed
to application callers as a raw `*sql.DB`. The SQL guard rejects classes of
input such as multi-statement queries, comments, DDL, and dangerous functions.
It is an additional check, not a replacement for restricted database roles,
PostgreSQL RLS, timeouts, and tenant-aware transactions.

## What Loom is and is not

Loom provides:

- an embedded authorization and execution pipeline;
- a registry for governed operations;
- resource and field-level access checks;
- approvals, risk classification, quotas, and idempotency controls;
- governed database access;
- output filtering, redaction, and audit events; and
- optional protocol adapters using the same runtime.

Loom is not an identity provider, an OIDC service, an ORM, or a guarantee of
tenant isolation by itself. Production applications still need a real identity
verifier, durable security state, restricted database credentials, database
isolation, and operational monitoring. Loom also does not define an
application's domain model or decide which operations an application should
allow.

## Status

The current public release is `v0.1.4`. It is an early open-source release.
The runtime has been exercised internally and includes tests across its main
packages. Production integrations, packaging, and documentation will continue
to evolve with use.

## Quick start

Start with the [installation guide](docs/INSTALL.md) and then follow the
[how-to guide](docs/HOWTO.md):

```bash
git clone https://github.com/loreste/loom.git
cd loom
make build
LOOM_EXAMPLE_TOKEN="$(openssl rand -hex 24)" go run ./examples/orders-app/
```

Other local examples:

```bash
LOOM_EXAMPLE_TOKEN="$(openssl rand -hex 24)" \\
LOOM_EXAMPLE_APPROVAL_TOKEN="$(openssl rand -hex 24)" \\
go run ./examples/embed/         # governed SQLite access in-process
LOOM_WORKER_TOKEN="$(openssl rand -hex 24)" go run ./examples/worker/ # jobs that use the same Call path
go test -race ./...
```

To add Loom to a Go application, use the tagged module release:

```bash
go get github.com/loreste/loom@v0.1.4
```

Then register operations and call them through the application API:

```go
a, err := app.New(app.Config{})
if err != nil {
	return err
}

response := a.Call(ctx, core.Request{
	Operation: "order.create",
	Credentials: core.Credentials{
		Scheme: "bearer",
		Token:  token,
	},
	Boundary: "development",
	Input: map[string]any{
		"sku": "example-sku",
	},
})
if !response.Allowed {
	return fmt.Errorf("operation denied: %s", response.Denial.Reason)
}
```

See [EMBED.md](docs/EMBED.md) for database registration, bootstrapping, and
background jobs. Language-specific Go, Python, TypeScript/Node, and Rust
examples are in [SDK.md](docs/SDK.md).

## Optional network adapters

When callers need a network interface, run the HTTP and gRPC adapters or use
the other adapters in the repository. They all translate requests into the
same execution path:

```bash
go run ./cmd/loom serve --addr=:8080 --grpc-addr=:9090
```

| Interface | Entry point |
| --- | --- |
| HTTP | `POST /v1/execute` |
| Execution status | `GET /v1/executions/{execution_id}` |
| Execution reconcile | `POST /v1/executions/{execution_id}/reconcile` |
| Discovery | `GET /.well-known/loom.json` |
| OpenAPI | `GET /v1/openapi.json` |
| MCP | `POST /mcp` |
| GraphQL | `POST /graphql` |
| gRPC | `loom.v1.Runtime/Execute` |

The Go, Python, TypeScript, and Rust SDKs call the HTTP adapter. They do not
grant themselves additional permissions.

## Production considerations

Do not expose the development configuration on a public network. Before using
Loom in production, configure a real identity verifier, disable demo
principals, and use durable stores for approvals, idempotency, quotas, and
audit as appropriate for the deployment.

Read:

- [SECURITY.md](docs/SECURITY.md) for the security model and limits;
- [IDENTITY.md](docs/IDENTITY.md) for OIDC/JWKS and mTLS integration;
- [TENANCY.md](docs/TENANCY.md) and the [tenant example](examples/tenancy/README.md)
  for application and database isolation;
- [OBSERVABILITY.md](docs/OBSERVABILITY.md) for metrics and tracing; and
- [COMPATIBILITY.md](docs/COMPATIBILITY.md) for protocol and SDK contracts;
- [SCHEMA.md](docs/SCHEMA.md) for the bounded input and output schema contract; and
- [SDK.md](docs/SDK.md) for installation and examples for Go, Weft, Python, Node.js, TypeScript, and Rust.

## Repository layout

| Area | Purpose |
| --- | --- |
| `app`, `runtime` | Embed API and execution pipeline |
| `db` | Database pools, SQL checks, migrations, and governed queries |
| `policy`, `identity`, `boundary`, `resource` | Policy building blocks |
| `approval`, `risk`, `quotas`, `idempotency`, `audit` | Execution controls and records |
| `adapters/*` | Optional HTTP, CLI, MCP, GraphQL, gRPC, and Weft adapters |
| `store/postgres` | Durable PostgreSQL backends |
| `sdk/*` | Go, Python, TypeScript, and Rust clients |
| `examples/*` | Runnable examples; not production applications |

## Tests

The main CI workflow runs Go vet, race-enabled tests, runtime fuzzing, builds,
PostgreSQL integration tests, SDK checks, and cross-SDK contract tests. Local
Go checks are:

```bash
go vet ./...
go test -race ./...
go test -fuzz=FuzzExecute -fuzztime=15s ./runtime/
go build ./...
```

Language-specific SDK checks are documented in the SDK READMEs and run in CI.

## License

Apache-2.0.
