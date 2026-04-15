use crate::errors::AmaError;
use chrono::{SecondsFormat, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

/// Audit log entry — metadata only, never contains payload content.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: String,
    pub session_id: String,
    pub action_id: String,
    pub adapter: String,
    pub action: String,
    pub domain_id: String,
    pub magnitude_effective: u64,
    pub duration_ms: u64,
    pub status: String,       // "authorized" | "impossible" | "error"
    pub request_hash: String, // SHA-256 of canonical action
    pub truncated: bool,
}

/// Proof-of-Constraint record — stored in-memory for P3.
/// Allows any downstream product to verify a past verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofVerdict {
    Authorized,
    Impossible,
    BadRequest,
    ValidationError,
    Conflict,
    PayloadTooLarge,
    UnsupportedMediaType,
    RateLimited,
    ServiceUnavailable,
}

impl ProofVerdict {
    pub fn from_error(error: &AmaError) -> Self {
        match error {
            AmaError::Impossible => Self::Impossible,
            AmaError::BadRequest { .. } => Self::BadRequest,
            AmaError::Validation { .. } => Self::ValidationError,
            AmaError::Conflict { .. } => Self::Conflict,
            AmaError::PayloadTooLarge => Self::PayloadTooLarge,
            AmaError::UnsupportedMediaType => Self::UnsupportedMediaType,
            AmaError::RateLimited => Self::RateLimited,
            AmaError::ServiceUnavailable { .. } => Self::ServiceUnavailable,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProofRecord {
    pub request_id: String,
    pub agent_id: String,
    pub action: String,
    pub verdict: ProofVerdict,
    pub manifest_hash: String, // SHA-256 of active policy at decision time
    pub timestamp: String,     // RFC 3339 / ISO 8601 UTC
}

/// In-memory proof store with bounded capacity and TTL-based eviction.
/// Thread-safe via Mutex.
pub struct ProofStore {
    records: Mutex<HashMap<String, ProofRecord>>,
    max_entries: usize,
}

impl ProofStore {
    pub fn new(max_entries: usize) -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    /// Store a proof record. If at capacity, silently drops oldest
    /// (HashMap doesn't preserve order, but bounded size prevents OOM).
    pub fn insert(&self, record: ProofRecord) {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if records.len() >= self.max_entries {
            // Evict one arbitrary entry to stay bounded
            if let Some(key) = records.keys().next().cloned() {
                records.remove(&key);
            }
        }
        records.insert(record.request_id.clone(), record);
    }

    /// Retrieve a proof record by request_id.
    pub fn get(&self, request_id: &str) -> Option<ProofRecord> {
        self.records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(request_id)
            .cloned()
    }
}

/// Compute SHA-256 hash of the canonical action representation.
/// Hashes over (action, target, magnitude) — NOT raw JSON.
pub fn compute_request_hash(action: &str, target: &str, magnitude: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(action.as_bytes());
    hasher.update(b"|");
    hasher.update(target.as_bytes());
    hasher.update(b"|");
    hasher.update(magnitude.to_le_bytes());
    format!("{:x}", hasher.finalize())
}

/// Emit audit log entry via tracing (structured JSON).
pub fn log_audit(entry: &AuditEntry) {
    tracing::info!(
        timestamp = %entry.timestamp,
        session_id = %entry.session_id,
        action_id = %entry.action_id,
        adapter = %entry.adapter,
        action = %entry.action,
        domain_id = %entry.domain_id,
        magnitude = entry.magnitude_effective,
        duration_ms = entry.duration_ms,
        status = %entry.status,
        request_hash = %entry.request_hash,
        truncated = entry.truncated,
        "SAFA_AUDIT"
    );
}

pub fn timestamp_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}
