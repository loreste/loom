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
            .header(USER_AGENT, "loom-rust-sdk/0.3")
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
}
