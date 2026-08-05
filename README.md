# Loom

Loom is an embed-first governance runtime for Go applications. It puts one
controlled execution boundary in front of handlers, database operations,
background jobs, payments, provisioning, and administrative actions.

Loom has been used internally for the past two months. We are now open-sourcing
it so teams can inspect the design, use the runtime in their own applications,
and contribute improvements to a problem we have been solving in practice.

Applications need this because sensitive work rarely has only one entry point.
The same operation may be reachable through an HTTP request, a worker, an
internal service, an MCP tool, or in-process code. If each path implements its
own authentication, authorization, tenant checks, approvals, and auditing,
the rules drift and one path eventually becomes a bypass.

Loom routes those paths through `app.Call` / `Runtime.Execute`. It is
deny-by-default, fail-closed, and designed to keep the enforcement logic shared
when a new adapter or worker is added. Read the full explanation in
[`docs/OVERVIEW.md`](docs/OVERVIEW.md), then use [`docs/INSTALL.md`](docs/INSTALL.md)
to get started.

Loom is a small Go library that sits in front of the parts of your app that
actually do things—call a handler, touch a database, run a job—and decides
whether that call is allowed.

You embed it in your process. There is no separate authz service to deploy
unless you want one later. HTTP, MCP, GraphQL, and gRPC are optional adapters
on top of the same runtime; they do not get a shortcut around it.

**Status:** v0.1.1. Useful if you are building in Go and want a single place
for identity, policy, and safe DB access. Not a full identity platform, not
an ORM, and not a replacement for careful application design.

## Why it exists

A lot of internal tools end up with the same mess:

- Product code that talks straight to the database
- Authz rules scattered across middleware, SQL, and ad-hoc checks
- A growing pile of endpoints that each reimplement “who can do what”
- Workers or other callers that need the same rules without a second stack

Loom is aimed at that middle ground: **named operations go through one
pipeline**, and the pipeline is deny-by-default. If you need network access
later, you expose the same pipeline—not a second, weaker path.

It will not invent your product model for you. You still register users (or
wire a real verifier), write allow rules, and design tenancy carefully.
What it does give you is a consistent enforcement point and some hard
defaults around SQL and side effects.

## How it works

```
your code  →  app.Call / Runtime.Execute  →  handler or db.Executor
                     ↑
        identity, boundary, policy, guardrails,
        risk, approval, quotas, idempotency, audit
```

Anything that should be governed is an **operation** (`order.create`,
`db.query`, …). Callers never get a raw `*sql.DB`. Database access goes
through a pool registry and a SQL classifier that rejects multi-statement
queries, comments, DDL, and a set of dangerous functions. Table allowlists
and boundary pins are optional but recommended.

Default decision is **deny**. Missing rules, eval errors, and most
misconfiguration fail closed rather than open.

## Quick start

New users: start with [`docs/INSTALL.md`](docs/INSTALL.md), then follow
[`docs/HOWTO.md`](docs/HOWTO.md). The shortest local path is:

```bash
git clone https://github.com/loreste/loom.git
cd loom
make build
go run ./examples/orders-app/
```

```bash
go test -race ./...

go run ./examples/embed/         # governed SQL against SQLite in-process
go run ./examples/orders-app/    # product ops; callers never send SQL
go run ./examples/worker/        # jobs that only run via Call
```

Embedding without a server:

```go
a, err := app.New(app.Config{})
// register DB pool, ops, users, grants…
resp := a.Call(ctx, core.Request{
    Operation:   "order.create",
    Credentials: core.Credentials{Token: token},
    Boundary:    "dev",
    // …
})
if !resp.Allowed {
    // Denial has a stable reason (and optional hint / retryable)
}
```

There is also `app.Bootstrap` if you want migrate → open pool → seed users
in one step. Details: [`docs/EMBED.md`](docs/EMBED.md).

## Optional network edge

Same runtime, different transports:

```bash
go run ./cmd/loom serve --addr=:8080 --grpc-addr=:9090
```

| Path | Role |
|------|------|
| `POST /v1/execute` | Call an operation |
| `GET /.well-known/loom.json` | Static discovery (no op list) |
| `GET /v1/openapi.json` | Capability-filtered OpenAPI |
| `POST /mcp` | MCP tools/list + tools/call |
| `POST /graphql` | `mutation { execute(...) }` |
| gRPC `loom.v1.Runtime/Execute` | Same as execute |

Remote SDKs (Go / Python / TypeScript / Rust) only talk to that edge. They
cannot grant themselves power.

For anything beyond local demos, set production flags (durable store, no
demo principals, real JWT secret). See [`docs/SECURITY.md`](docs/SECURITY.md).

## CLI

```bash
go build -o loom ./cmd/loom
./loom version
./loom serve --addr=:8080
```

Version string defaults to the value in `VERSION` (0.1.1) unless you inject
ldflags yourself.

## What is in the tree

| Area | Purpose |
|------|---------|
| `app`, `runtime` | Embed API and enforcement pipeline |
| `db` | Pools, SQL guard, migrator, governed query/exec |
| `policy`, `identity`, `boundary`, `resource`, … | Building blocks |
| `adapters/*` | Optional HTTP / CLI / MCP / GraphQL / gRPC / Weft |
| `store/postgres`, Redis quotas | Durable backends when you need them |
| `examples/*` | Small runnable demos, not production apps |

## Honest limits

- **Tenancy:** Loom enforces boundaries and ACLs at the app layer. Sharing
  one table across tenants still needs RLS, separate pools, or SQL that
  always filters by tenant. See [`docs/TENANCY.md`](docs/TENANCY.md).
- **Identity:** Static tokens and demo JWTs are for development. Wire a
  real verifier for production.
- **Demo users:** The CLI platform ships known tokens when demos are
  enabled. Do not expose that configuration on a public network.

Production construction, identity integration, compatibility guarantees,
observability, and the tenant/RLS reference are documented in
[`docs/BUILD.md`](docs/BUILD.md), [`docs/IDENTITY.md`](docs/IDENTITY.md),
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md),
[`docs/OBSERVABILITY.md`](docs/OBSERVABILITY.md), and
[`examples/tenancy/README.md`](examples/tenancy/README.md).

## License

Apache-2.0.
