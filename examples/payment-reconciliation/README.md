# Payment reconciliation reference

This example registers the versioned, idempotent, approval-gated
`payment.capture` operation. A provider reference is treated as external
state. If durable recording is uncertain, the result is
`executed_unconfirmed`; reconciliation queries the provider and never invokes
the capture handler again.

```sh
go run ./examples/payment-reconciliation
```

Production deployments must replace the process-local app with PostgreSQL
execution/approval/idempotency/audit stores, Redis quotas, an OIDC verifier,
and a provider implementation with an idempotent request key. Provider
credentials and raw processor responses must remain outside logs, metrics, and
caller-visible denials.
