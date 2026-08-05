# Observability

Loom is a central enforcement choke point. Instrument it as a security
control, not only as application latency.

`runtime.Metrics` records execution totals, allow/deny totals, cumulative
duration, denial stages, and denial reasons. Pass it through the HTTP adapter
to expose `GET /metrics` in the Prometheus text format. Protect that endpoint
with the same network controls used for operational endpoints.

For richer telemetry, provide a `runtime.Observer` implementation. The
observer receives one bounded observation per execution and can create an
OpenTelemetry span or increment an existing Prometheus registry. Do not put
tokens, raw credentials, SQL, request bodies, or secret-bearing metadata in
metric labels or span attributes.

Recommended dashboards and alerts include:

- operation latency and error rate;
- denials grouped by pipeline stage and stable reason code;
- approval-required, quota-rejected, idempotency-replay, and idempotency-
  conflict counts;
- audit-write failures and readiness failures;
- policy version/reload status; and
- request counts and latency by adapter.

Tracing must propagate the Loom trace ID, while audit records remain the
authoritative security record. A telemetry backend outage must not turn a
denial into an allow; observer failures are isolated from the execution result.
