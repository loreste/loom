# Performance results

These numbers describe one local in-process benchmark, not a production SLA.
Network adapters, identity providers, PostgreSQL, Redis, external APIs, host
contention, operation complexity, and audit sinks change the result.

## Reproduce

From the repository root:

```bash
GOCACHE=/tmp/loom-gocache go test -run '^$' \
  -bench BenchmarkExecuteGranted -benchtime=2s ./runtime
```

The benchmark uses a fully wired in-memory test stack and a low-risk read
operation. It excludes network, database, Redis, external identity, and
provider latency.

## Recorded result

Run date: 2026-08-05  
Host: Apple M4, darwin/arm64  
Go: 1.26.5  
Command: `go test -run '^$' -bench BenchmarkExecuteGranted -benchtime=2s ./runtime`

```text
BenchmarkExecuteGranted-10    382894    7789 ns/op
```

The benchmark is checked into `runtime/benchmark_test.go` so future changes
can compare the same path. Treat the result as a regression signal, not a
capacity promise. Publish deployment-specific p50, p95, p99, throughput,
in-flight count, and durable-store latency before setting an operational
budget.

## What to measure in a deployment

- latency by adapter and operation version;
- authorization-stage latency and denial rate;
- PostgreSQL and Redis latency/error rate;
- audit-write latency and failures;
- recovery queue depth and oldest age;
- active executions and `executed_unconfirmed` age; and
- external identity and provider lookup latency.

Never put credentials, tokens, raw SQL, or customer identifiers in metric
labels. See [`OBSERVABILITY.md`](OBSERVABILITY.md).
