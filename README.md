# Loom

Loom is an embed-first governance runtime for Go applications. It gives
operations one controlled execution path, whether they arrive from a web
request, a worker, an MCP tool, an administrative command, or code in the same
process.

Loom has been used internally for the past two months. We are publishing it
as open source so the implementation, examples, and trade-offs can be reviewed
and used by other teams.

## Why Loom exists

As an application grows, sensitive work tends to acquire several entry points:

- an HTTP endpoint;
- a background worker;
- an internal service or CLI;
- an MCP, GraphQL, or gRPC operation; and
- an in-process call from another package.

When each entry point implements its own checks, the rules eventually diverge.
That creates practical security and reliability problems:

- one transport checks a permission while another misses it;
- a worker can perform an operation rejected by the user-facing path;
- product code reaches a database without the same policy checks;
- retries repeat a payment or another side effect; and
- tenant context is lost before a database query runs.

Loom makes the governed operation, rather than the transport, the unit of
authorization. Adapters translate requests into the same runtime contract;
they do not create alternate authorization paths.

## What Loom does

The default decision is deny. `app.App.Call` and
`runtime.Runtime.Execute` run the request through a common pipeline:

```text
identity and delegation
  → tenant/boundary resolution
  → operation and resource policy
  → input-field authorization
  → contextual policy and guardrails
  → risk, approval, idempotency, and quota checks
  → handler or governed database executor
  → output schema validation, filtering, and redaction
  → execution status and audit
```

Unknown operations, missing rules, verification failures, invalid boundaries,
and enforcement errors fail closed. Approval tokens are claimed before a
handler runs. Idempotency protects operations that require safe retries.
Side-effecting calls that run but cannot confirm durable completion return an
`executed_unconfirmed` outcome and an execution ID; callers must reconcile the
status before retrying.

Loom's SQL guard rejects multi-statement input, comments, DDL/admin statements,
and dangerous functions. It is defense in depth, not a replacement for
restricted database roles, PostgreSQL RLS, statement timeouts, or tenant-aware
transactions.

## Compliance visibility

Every governed attempt produces a structured audit decision with an execution ID, trace ID, selected operation version, adapter, boundary, enforcement stage, stable reason code, outcome, and redacted correlation digests. Reconciliation and recovery actions are recorded as lifecycle events. `runtime.Metrics` exposes bounded counters for denials, replays, quota and approval outcomes, idempotency conflicts, and uncertain executions, plus an execution-latency histogram, an in-flight gauge, durable-store latency and error aggregates, and recovery queue depth, age, attempts, renewals, and dead letters. The maintained `observability/otel` bridge exports bounded metrics and annotates an existing OpenTelemetry span without emitting credentials or high-cardinality customer identifiers.

Audit streams are hash-chained. `loom audit head`, `verify`, and `export` check a
segment against a trusted prior hash rather than one read from the same source,
`export --stream` reads a verified segment from the durable PostgreSQL stream,
and `checkpoint`, `verify-checkpoint`, and `rotate` sign, confirm, and re-key a
signed terminal hash. Rotation verifies the prior checkpoint under the retired
key before signing with the new one.

Loom keeps credentials, approval tokens, idempotency keys, raw SQL, and unrestricted request bodies out of audit events. Configure a durable PostgreSQL or JSONL sink for production and export it to the immutable archive, SIEM, or compliance system required by your organization. See [`docs/OBSERVABILITY.md`](docs/OBSERVABILITY.md).

## What Loom is not

Loom is not an identity provider, managed tenant directory, ORM, payment
processor, or complete tenant-isolation solution. It includes an embeddable
OIDC/JWKS verifier, but the application still supplies issuer, audience, claim
mapping, revocation, and tenant configuration before Loom applies policy to the
verified identity.
Production deployments still need an identity integration, durable state,
database isolation, secrets management, and operational monitoring.

Loom also does not define an application's domain model or decide which
operations that application should expose.

## Status

The current repository release is `v0.2.1`; [`VERSION`](VERSION) is the
release source of truth. See the [release page](https://github.com/loreste/loom/releases)
for published binaries, checksums, signatures, SBOM, provenance, and the signed
container image. The release includes a production-oriented OIDC/JWKS verifier,
while database isolation, provider lifecycle, secret management, and
operational monitoring remain responsibilities of the integrating application.
The Python, TypeScript, and Rust SDK manifests are version-aligned; install
those SDKs from the checkout until registry publication is confirmed in
[`docs/RELEASES.md`](docs/RELEASES.md).

## Quick start

For a local embedded example:

```bash
git clone https://github.com/loreste/loom.git
cd loom
make build
LOOM_EXAMPLE_TOKEN="$(openssl rand -hex 24)" \
  go run ./examples/orders-app/
```

To run the HTTP adapter with a development principal, use the same token for
the server and the client:

```bash
export LOOM_TOKEN="loom-dev-$(openssl rand -hex 24)"
export LOOM_DEMO_TOKEN_ALICE="$LOOM_TOKEN"
go run ./cmd/loom serve --addr=:8080
```

Then follow the [documentation index](docs/README.md), which links to the
[installation guide](docs/INSTALL.md), [how-to guide](docs/HOWTO.md),
[HTTP API guide](docs/API.md), and [SDK quick starts](docs/SDK.md).

To add Loom to another Go module, use an exact release tag:

```bash
go get github.com/loreste/loom@vX.Y.Z
```

The Go module and SDK manifests are aligned to the release version. The Go
module is available by tag. The Python, TypeScript/Node, and Rust publication
workflow is configured but requires registry-side trusted-publisher setup;
until that setup is complete, install those SDKs from this checkout. See
[SDK.md](docs/SDK.md) for both paths. Published binaries, the signed GHCR
image, and SDK publication requirements are documented in
[RELEASES.md](docs/RELEASES.md).

## Optional protocol adapters

The adapters below all reach the same execution runtime:

| Interface | Entry point |
| --- | --- |
| HTTP | `POST /v1/execute` |
| Execution status | `GET /v1/executions/{execution_id}` |
| Execution reconcile | `POST /v1/executions/{execution_id}/reconcile` |
| Execution recording retry | `POST /v1/executions/{execution_id}/retry_recording` |
| Discovery | `GET /.well-known/loom.json` |
| OpenAPI | `GET /v1/openapi.json` |
| MCP | `POST /mcp` |
| GraphQL | `POST /graphql` |
| gRPC | `loom.v1.Runtime/Execute` |
| Weft | in-process adapter and Go SDK |

Start the network adapters with:

```bash
go run ./cmd/loom serve --addr=:8080 --grpc-addr=:9090
```

The Go SDK supports both in-process calls and the HTTP adapter. Python,
TypeScript/Node, and Rust SDKs call the HTTP adapter. None of the SDKs grant
themselves additional permissions.

## Production considerations

Before using Loom for production side effects:

- inject a real identity verifier and configure issuer, audience, key rotation,
  certificate rotation, and revocation behavior;
- disable demo principals;
- use PostgreSQL-backed execution, approval, idempotency, and audit state for
  multi-node deployments;
- use Redis when quotas must be shared across replicas;
- use restricted database roles, PostgreSQL RLS, tenant-bound transactions,
  timeouts, and connection limits;
- register application-owned dependencies through `bootstrap.Config.ReadyChecks`
  so `/readyz` reflects them — an OIDC deployment should pass
  `verifier.ReadyCheck()`, since Loom cannot probe a verifier it did not build;
  and
- protect readiness, metrics, status, and reconciliation endpoints.

Read:

- [INSTALL.md](docs/INSTALL.md) for source, binary, Docker, and production setup;
- [CONFIGURATION.md](docs/CONFIGURATION.md) for environment variables and CLI flags;
- [API.md](docs/API.md) for HTTP requests, responses, and execution recovery;
- [OPERATIONS.md](docs/OPERATIONS.md) for deployment, monitoring, and incident handling;
- [SECURITY.md](docs/SECURITY.md) for guarantees and deployment boundaries;
- [IDENTITY.md](docs/IDENTITY.md) for production verifier integration;
- [TENANCY.md](docs/TENANCY.md) and the [tenant example](examples/tenancy/README.md);
- [OBSERVABILITY.md](docs/OBSERVABILITY.md) for metrics and tracing;
- [COMPATIBILITY.md](docs/COMPATIBILITY.md) for protocol and SDK contracts;
- [SCHEMA.md](docs/SCHEMA.md) for the bounded Loom Schema; and
- [SDK.md](docs/SDK.md) for Go, Weft, Python, Node.js/TypeScript, and Rust usage.

Additional operational guides:

- [RECOVERY.md](docs/RECOVERY.md) recovery worker and reconciliation;
- [PERFORMANCE.md](docs/PERFORMANCE.md) benchmark result and measurement guidance;
- [FAILURE-INJECTION.md](docs/FAILURE-INJECTION.md) failure scenarios and release evidence.

## Repository layout

| Area | Purpose |
| --- | --- |
| `app`, `runtime` | Embedded execution pipeline |
| `db` | Database pools, SQL checks, migrations, and governed queries |
| `policy`, `identity`, `boundary`, `resource` | Policy and identity building blocks |
| `approval`, `risk`, `quotas`, `idempotency`, `execution`, `audit` | Execution controls and records |
| `adapters/*` | Optional HTTP, CLI, MCP, GraphQL, gRPC, and Weft edges |
| `store/postgres` | Durable PostgreSQL backends |
| `sdk/*` | Go, Python, TypeScript, and Rust clients |
| `examples/*` | Runnable examples; they are not production applications |

## Verification

The main CI workflow runs Go vet, race-enabled tests, fuzz smoke tests,
PostgreSQL integration tests, SDK builds/tests, and cross-SDK contract tests.
Security workflows run Go vulnerability and static checks, CodeQL, secret
scanning, dependency review, and SBOM generation. Container scanning runs on
pull requests, relevant source changes, release tags, and a weekly schedule.
The Helm chart is linted in CI.

Useful local checks:

```bash
go vet ./...
go test -race ./...
go test -fuzz=FuzzExecute -fuzztime=15s ./runtime/
go build ./...
```

## License

Apache-2.0.
