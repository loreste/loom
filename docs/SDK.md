# SDK quick starts

The SDKs are thin clients for Loom's HTTP adapter. They submit an operation,
version, boundary, input, and credentials; the server remains responsible for
authentication, policy, guardrails, approvals, quotas, idempotency, execution,
filtering, and audit. SDKs do not add permissions.

Start a development server from the repository:

```bash
export LOOM_TOKEN="$(openssl rand -hex 24)"
go run ./cmd/loom serve --addr=:8080
```

Use a real token issued by your identity system outside development. The
examples below assume `LOOM_TOKEN` and a running server.

## Go

```bash
go get github.com/loreste/loom@v0.1.5
```

```go
import (
    "context"
    "os"

    "github.com/loreste/loom/core"
    loom "github.com/loreste/loom/sdk/go/loom"
)

ctx := context.Background()
client := loom.NewHTTPClient("http://127.0.0.1:8080", os.Getenv("LOOM_TOKEN"))
response, err := client.Call(ctx, core.Request{
    Operation: "document.read", OperationVersion: "1", Boundary: "dev",
    Credentials: core.Credentials{Scheme: "bearer", Token: os.Getenv("LOOM_TOKEN")},
    Input: map[string]any{"id": "1"},
})
```

Use `loom.NewClient(app.Runtime)` for in-process Go calls so the same pipeline
is used without opening a network listener.

For Weft workflow steps, use the Weft SDK package. It is an in-process client
over the same adapter and does not bypass Loom:

```go
import loomweft "github.com/loreste/loom/sdk/go/weft"

client := loomweft.New(app.Runtime)
response, err := client.Invoke(ctx, loomweft.StepCall{
    WorkflowID: "workflow-id", StepID: "step-id",
    Operation: "document.read", OperationVersion: "1", Boundary: "dev",
    BearerToken: os.Getenv("LOOM_TOKEN"), Input: map[string]any{"id": "1"},
})
```

## Python

```bash
python -m pip install loom-sdk==0.1.5
```

```python
import os

from loom import Client

client = Client("http://127.0.0.1:8080", token=os.environ["LOOM_TOKEN"])
response = client.call(
    "document.read", operation_version="1", boundary="dev", input={"id": "1"}
)
if not response.allowed:
    raise RuntimeError(response.denial.hint if response.denial else "denied")
```

## TypeScript and Node

The package requires Node 18 or newer. Browser-compatible callers import
`Client`; Node applications should import the explicit `NodeClient` entry
point.

```bash
npm install @loreste/loom-sdk@0.1.5
```

```ts
import { NodeClient } from "@loreste/loom-sdk/node";

const client = new NodeClient("http://127.0.0.1:8080", process.env.LOOM_TOKEN);
const response = await client.call({
  operation: "document.read", operationVersion: "1", boundary: "dev",
  input: { id: "1" },
});
```

`NodeClient` uses Node's built-in `fetch`. A compatible `fetchImpl` can be
provided for tests or older runtimes.

## Rust

```toml
[dependencies]
loom-sdk = "0.1.5"
```

```rust
let token = std::env::var("LOOM_TOKEN")?;
let client = loom_sdk::Client::new("http://127.0.0.1:8080", token)?;
let response = client.call(loom_sdk::Call {
    operation: "document.read".into(),
    operation_version: Some("1".into()),
    boundary: "dev".into(),
    input: serde_json::json!({"id": "1"}),
    resource: None, fields: None, idempotency_key: None,
    approval_token: None, token: None, metadata: Default::default(),
    trace_id: None,
}).await?;
```

Every SDK exposes `Outcome`, `ExecutionID`, `OperationVersion`, and
`ReliabilityWarning` when the server returns them. For
`executed_unconfirmed`, query `GET /v1/executions/{execution_id}` or use the
runtime status API, then reconcile with an explicit outcome before retrying a
side-effecting call. `retry_recording` only retries durable recording; it
never reruns the handler.
