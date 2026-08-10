# Loom Rust SDK

This crate is a thin HTTP client. Governance remains server-side and the SDK
cannot grant permissions.

The crate version matches the Loom release (`VERSION` in the repository root).
crates.io publication is pending trusted-publisher configuration—see
[`docs/RELEASES.md`](../../docs/RELEASES.md). Use a path dependency from this
checkout for now:

```toml
[dependencies]
loom-sdk = { path = "../loom/sdk/rust" }
```

Example:

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

See [`../../docs/INSTALL.md`](../../docs/INSTALL.md) and
[`../../docs/SDK.md`](../../docs/SDK.md) for server setup and reliability
outcomes.
