# AI/MCP governed reference

This example exposes AI operations through the MCP adapter. Tool discovery is
metadata only; each call still authenticates, resolves the tenant boundary,
checks the operation version and capability, validates bounded input, enforces
approval/risk/quota/idempotency, and filters output.

```sh
go run ./examples/ai-mcp
```

The example uses process-local stores for portability. Production deployments
must use the OIDC verifier, PostgreSQL execution/approval/idempotency/audit
stores, Redis quotas, and an external model/tool provider. Python, TypeScript,
Rust, and Go clients can call the same governed HTTP endpoint; none receives a
privileged MCP path.
