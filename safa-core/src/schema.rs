use crate::errors::AmaError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ActionRequest {
    pub adapter: String,
    pub action: String,
    pub target: String,
    pub magnitude: u64,
    #[serde(default)]
    pub dry_run: bool,
    pub method: Option<String>,
    pub payload: Option<String>,
    pub args: Option<Vec<String>>,
}

pub fn validate_adapter(adapter: &str) -> Result<(), AmaError> {
    if adapter.is_empty() || adapter.len() > 64 {
        return Err(AmaError::Validation {
            error_class: "invalid_adapter".into(),
            message: "adapter must be 1-64 chars of [A-Za-z0-9_-]".into(),
        });
    }

    if !adapter
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(AmaError::Validation {
            error_class: "invalid_adapter".into(),
            message: "adapter must be 1-64 chars of [A-Za-z0-9_-]".into(),
        });
    }

    Ok(())
}

pub fn validate_magnitude(magnitude: u64) -> Result<(), AmaError> {
    if !(1..=1000).contains(&magnitude) {
        return Err(AmaError::Validation {
            error_class: "invalid_magnitude".into(),
            message: format!("magnitude must be 1-1000, got {}", magnitude),
        });
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct ActionResponse {
    pub status: String,
    pub action_id: String,
    pub dry_run: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub status: String,
    pub error_class: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct VersionResponse {
    pub name: String,
    pub version: String,
    pub schema_version: String,
}
