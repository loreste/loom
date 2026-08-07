# Performance and resilience evidence

Loom does not publish in-memory microbenchmarks as production throughput or an
SLO. Database, Redis, identity-provider, external API, audit-sink, host, and
replica contention materially change performance.

## Adapter benchmark runner

From the repository root:

```bash
LOOM_PERF_OUTPUT=/tmp/loom-performance \
LOOM_PERF_COUNT=5 \
LOOM_PERF_TIME=2s \
sh scripts/performance.sh
```

The runner records Go and host metadata and executes reproducible benchmarks
for in-process, HTTP, MCP, GraphQL, gRPC, and Weft adapters. These benchmarks
use in-memory dependencies and report Go benchmark means and allocations. They
exclude PostgreSQL, Redis, external identity, external APIs, replica scale,
failure injection, and soak behavior.

## Production-resilience harness contract

Before publishing deployment results, run the same versioned Loom build against
the supported PostgreSQL and Redis versions with:

- one, ten, and fifty API replicas plus separate recovery workers;
- PostgreSQL restart/failover and injected slowdown;
- Redis loss/reconnect and quota fail-closed checks;
- concurrent approvals, idempotency retries, reconciliation, and audit-sink
  slowdown/failure;
- large policy sets and schema documents;
- network latency/partition injection; and
- a minimum 24-hour soak with a recovery backlog drain phase.

The harness must retain its configuration, workload generator, failure-injection
parameters, and raw output. It must never report a successful side effect when
the durable result is `executed_unconfirmed`.

## Required report

Every production report must include:

- throughput and error/denial rates;
- p50, p95, p99, and maximum latency for requests and durable-store calls;
- allocations and memory high-water mark;
- PostgreSQL/Redis latency, errors, and availability;
- recovery queue depth, oldest age, and backlog recovery time objective;
- hardware, operating system, Go version, Loom commit, database/Redis versions;
- replica and worker counts, operation mix, policy/schema sizes, and all
  configuration values; and
- exact commands and links to raw artifacts.

The checked-in adapter benchmarks are useful regression signals, not evidence
for these deployment claims. Publish deployment-specific results only after
the external services and failure scenarios above have actually been run.

The checked-in integration runner requires real services and records raw
results; it does not create replicas or simulate failover:

```bash
LOOM_DATABASE_URL='postgres://...' \
LOOM_REDIS_URL='redis://...' \
LOOM_PERF_OUTPUT=/tmp/loom-resilience \
sh scripts/performance-resilience.sh
```

Run the same command inside the deployment harness for each replica count and
failure scenario, then attach its metadata and raw outputs to the report.
