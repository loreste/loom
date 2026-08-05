//! Loom Rust SDK — thin HTTP client. All governance is server-side.

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("sdk: {0}")]
    Sdk(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Denial {
    #[serde(rename = "Reason")]
    pub reason: Option<String>,
    #[serde(rename = "Message")]
    pub message: Option<String>,
    #[serde(rename = "Step")]
    pub step: Option<String>,
    #[serde(rename = "Retryable", default)]
    pub retryable: Option<bool>,
    #[serde(rename = "Hint", default)]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    #[serde(rename = "Allowed")]
    pub allowed: bool,
    #[serde(rename = "Decision")]
    pub decision: Option<String>,
    #[serde(rename = "Denial")]
    pub denial: Option<Denial>,
    #[serde(rename = "Output")]
    pub output: Option<Value>,
    #[serde(rename = "TraceID")]
    pub trace_id: Option<String>,
    #[serde(rename = "AuditID")]
    pub audit_id: Option<String>,
    #[serde(rename = "IdempotentReplay")]
    pub idempotent_replay: Option<bool>,
    #[serde(rename = "Risk")]
    pub risk: Option<String>,
    #[serde(rename = "Outcome")]
    pub outcome: Option<String>,
    #[serde(rename = "ExecutionID")]
    pub execution_id: Option<String>,
    #[serde(rename = "OperationVersion")]
    pub operation_version: Option<String>,
    #[serde(rename = "ReliabilityWarning")]
    pub reliability_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceRef {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize)]
struct ExecuteBody {
    operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_version: Option<String>,
    boundary: String,
    input: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<ResourceRef>,
    metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Call {
    pub operation: String,
    pub operation_version: Option<String>,
    pub boundary: String,
    pub input: Value,
    pub resource: Option<ResourceRef>,
    pub fields: Option<Vec<String>>,
    pub idempotency_key: Option<String>,
    pub approval_token: Option<String>,
    pub token: Option<String>,
    pub metadata: HashMap<String, String>,
    pub trace_id: Option<String>,
}

pub struct Client {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl Client {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            http,
        })
    }

    pub async fn call(&self, call: Call) -> Result<Response, Error> {
        let mut metadata = call.metadata;
        metadata
            .entry("adapter".into())
            .or_insert_with(|| "sdk-rust".into());
        let body = ExecuteBody {
            operation: call.operation,
            operation_version: call.operation_version,
            boundary: call.boundary,
            input: call.input,
            fields: call.fields,
            idempotency_key: call.idempotency_key,
            approval_token: call.approval_token,
            resource: call.resource,
            metadata,
        };
        let bearer = call.token.as_deref().unwrap_or(&self.token);
        let mut req = self
            .http
            .post(format!("{}/v1/execute", self.base_url))
            .header(CONTENT_TYPE, "application/json")
            .header("X-Loom-Protocol-Version", "1")
            .header(USER_AGENT, "loom-rust-sdk/0.1.4")
            .json(&body);
        if !bearer.is_empty() {
            req = req.header(AUTHORIZATION, format!("Bearer {bearer}"));
        }
        if let Some(tid) = call.trace_id {
            req = req.header("X-Trace-Id", tid);
        }
        let res = req.send().await?;
        let parsed = res.json::<Response>().await?;
        Ok(parsed)
    }

    /// GET /.well-known/loom.json — unauthenticated discovery.
    pub async fn manifest(&self) -> Result<Value, Error> {
        let res = self
            .http
            .get(format!("{}/.well-known/loom.json", self.base_url))
            .header(USER_AGENT, "loom-rust-sdk/0.1.4")
            .header("X-Loom-Protocol-Version", "1")
            .send()
            .await?;
        Ok(res.json().await?)
    }

    /// GET /v1/openapi.json — capability-filtered OpenAPI document.
    pub async fn openapi(&self) -> Result<Value, Error> {
        let mut req = self
            .http
            .get(format!("{}/v1/openapi.json", self.base_url))
            .header(USER_AGENT, "loom-rust-sdk/0.1.4")
            .header("X-Loom-Protocol-Version", "1");
        if !self.token.is_empty() {
            req = req.header(AUTHORIZATION, format!("Bearer {}", self.token));
        }
        let res = req.send().await?;
        Ok(res.json().await?)
    }

    /// POST /mcp — one JSON-RPC MCP message.
    pub async fn mcp(&self, rpc: Value) -> Result<Value, Error> {
        let mut req = self
            .http
            .post(format!("{}/mcp", self.base_url))
            .header(CONTENT_TYPE, "application/json")
            .header("X-Loom-Protocol-Version", "1")
            .header(USER_AGENT, "loom-rust-sdk/0.1.4")
            .json(&rpc);
        if !self.token.is_empty() {
            req = req.header(AUTHORIZATION, format!("Bearer {}", self.token));
        }
        let res = req.send().await?;
        if res.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(Value::Object(Default::default()));
        }
        Ok(res.json().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::{Call, Client};
    use serde_json::json;
    use std::collections::HashMap;

    #[tokio::test]
    async fn execute_contract_when_configured() {
        let Ok(base_url) = std::env::var("LOOM_CONTRACT_URL") else {
            return;
        };
        let client = Client::new(
            base_url,
            std::env::var("LOOM_CONTRACT_TOKEN").expect("contract token"),
        )
        .expect("client");
        let response = client
            .call(Call {
                operation: std::env::var("LOOM_CONTRACT_OPERATION").expect("contract operation"),
                operation_version: None,
                boundary: std::env::var("LOOM_CONTRACT_BOUNDARY").expect("contract boundary"),
                input: json!({}),
                resource: None,
                fields: None,
                idempotency_key: None,
                approval_token: None,
                token: None,
                metadata: HashMap::new(),
                trace_id: None,
            })
            .await
            .expect("contract response");
        assert!(response.allowed, "{response:?}");
        assert_eq!(response.output.expect("output")["status"], "ok");
    }
}
