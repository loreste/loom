# SDK quick starts

Loom SDKs are thin clients. They submit an operation, version, boundary, input,
and credential to Loom; the server remains responsible for authentication,
policy, guardrails, approvals, quotas, idempotency, execution, filtering, and
audit. An SDK cannot add permissions.

The Go SDK supports both local in-process calls and remote HTTP calls. The
Weft SDK is an in-process Go adapter. Python, TypeScript/Node, and Rust call
the HTTP adapter.

Package manifests are kept equal to the Loom release tag and checked before
publication. The publication workflow still requires trusted-publisher setup
in each registry; version alignment alone does not mean a package is available.
Cross-language request/response semantics are versioned in
[`../conformance/fixtures/execute-semantics.v1.json`](../conformance/fixtures/execute-semantics.v1.json).

## Install released SDKs

Use these commands only after the release documentation confirms that the
corresponding registry publication succeeded. For v0.2.0, install from the
checkout using the local-development sections below while registry setup is
pending.

```sh
python -m pip install loom-sdk
npm install @loreste/loom-sdk
cargo add loom-sdk
go get github.com/loreste/loom@vX.Y.Z
```

Replace `vX.Y.Z` with the reviewed release. Node applications use the
TypeScript package directly through its package exports.

## Start a development server

From a Loom checkout:

```bash
export LOOM_TOKEN="loom-dev-$(openssl rand -hex 24)"
export LOOM_DEMO_TOKEN_ALICE="$LOOM_TOKEN"
go run ./cmd/loom serve --addr=:8080
```

The development server seeds demo principals only for local use. Use a token
issued by your identity system outside development.

## Go

Use an exact release tag in a Go module:

```bash
go get github.com/loreste/loom@vX.Y.Z
```

Remote HTTP client:

```go
import (
    "context"
    "os"

    "github.com/loreste/loom/core"
    loom "github.com/loreste/loom/sdk/go/loom"
)

client := loom.NewHTTPClient("http://127.0.0.1:8080", os.Getenv("LOOM_TOKEN"))
response, err := client.Call(context.Background(), core.Request{
    Operation:        "document.read",
    OperationVersion: "1",
    Boundary:         "dev",
    Credentials:      core.Credentials{Scheme: "bearer", Token: os.Getenv("LOOM_TOKEN")},
    Input:            map[string]any{"id": "1"},
})
if err != nil {
    panic(err)
}
if !response.Allowed {
    panic(response.Denial.Reason)
}
```

For in-process use, construct Loom with `app.New` and wrap its runtime:

```go
client := loom.NewClient(app.Runtime)
response := client.Call(ctx, request)
```

## Weft Go SDK

The Weft SDK adapts workflow steps to the same runtime. It does not bypass
authorization or create a separate policy path:

```go
import loomweft "github.com/loreste/loom/sdk/go/weft"

client := loomweft.New(app.Runtime)
response, err := client.Invoke(ctx, loomweft.StepCall{
    WorkflowID:       "workflow-id",
    StepID:           "step-id",
    Operation:        "document.read",
    OperationVersion: "1",
    Boundary:         "dev",
    BearerToken:      os.Getenv("LOOM_TOKEN"),
    Input:            map[string]any{"id": "1"},
})
```

## Python

For local checkout development, install the Python package directly from the
repository:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ./sdk/python
```

```python
import os

from loom import Client, ResourceRef

client = Client(
    base_url="http://127.0.0.1:8080",
    token=os.environ["LOOM_TOKEN"],
)
response = client.call(
    "document.read",
    operation_version="1",
    boundary="dev",
    resource=ResourceRef(type="document", id="1"),
    input={"id": "1"},
)
if not response.allowed:
    raise RuntimeError(response.denial.hint if response.denial else "denied")
print(response.output)
```

The client also exposes `manifest()`, `openapi()`, and `mcp()` for server
discovery and protocol requests. Discovery does not grant access.

## TypeScript and Node.js

For local checkout development, build the TypeScript package from the
repository. It
requires Node.js 18 or newer. Browser-compatible callers use `Client`; Node
applications should import the explicit `NodeClient` entry point.

```bash
cd sdk/typescript
npm install
npm run build
npm test
```

For an application outside the checkout, build the package in the checkout and
then include its compiled `dist/` output through the application's workspace
or package process. `npm install` alone does not create `dist/`.

```ts
import { NodeClient } from "@loreste/loom-sdk/node";

const token = process.env.LOOM_TOKEN;
if (!token) throw new Error("LOOM_TOKEN is required");

const client = new NodeClient("http://127.0.0.1:8080", token);
const response = await client.call({
  operation: "document.read",
  operationVersion: "1",
  boundary: "dev",
  resource: { type: "document", id: "1" },
  input: { id: "1" },
});
if (!response.Allowed) {
  throw new Error(response.Denial?.Hint ?? "denied");
}
console.log(response.Output);
```

## Rust

The Rust crate is currently used as a path dependency from a Loom checkout:

```toml
[dependencies]
loom-sdk = { path = "../loom/sdk/rust" }
```

```rust
use loom_sdk::{Call, Client};

let token = std::env::var("LOOM_TOKEN")?;
let client = Client::new("http://127.0.0.1:8080", token)?;
let response = client.call(Call {
    operation: "document.read".into(),
    operation_version: Some("1".into()),
    boundary: "dev".into(),
    input: serde_json::json!({"id": "1"}),
    resource: None,
    fields: None,
    idempotency_key: None,
    approval_token: None,
    token: None,
    metadata: Default::default(),
    trace_id: None,
}).await?;
```

## Reliability outcomes

SDK responses expose the selected operation version, execution ID, outcome, and
reliability warning when the server returns them. If the outcome is
`executed_unconfirmed`, query `GET /v1/executions/{execution_id}` and reconcile
the confirmed external result before retrying a side-effecting call.

`retry_recording` retries durable recording only; it never reruns the business
handler.
