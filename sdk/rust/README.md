# Loom Rust SDK

```rust
use loom_sdk::{Call, Client, ResourceRef};
use serde_json::json;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let c = Client::new("http://127.0.0.1:8080", "alice-secret-token")?;
    let resp = c
        .call(Call {
            operation: "document.read".into(),
            boundary: "dev".into(),
            input: json!({"id": "1"}),
            resource: Some(ResourceRef {
                type_: "document".into(),
                id: "1".into(),
            }),
            fields: None,
            idempotency_key: None,
            approval_token: None,
            token: None,
            metadata: HashMap::new(),
            trace_id: None,
        })
        .await?;
    assert!(resp.allowed);

    // Agent discovery
    let _manifest = c.manifest().await?;
    let _openapi = c.openapi().await?;
    Ok(())
}
```
