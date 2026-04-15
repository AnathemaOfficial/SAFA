// SAFA P3 — Identity Binding via HMAC-SHA256
//
// Each agent with a configured `secret` requires all requests to include:
//   - X-Agent-Id: <agent_id>
//   - X-Agent-Timestamp: <unix_epoch_secs>
//   - X-Agent-Signature: <hex(HMAC-SHA256(secret, agent_id + "." + timestamp + "." + body_sha256))>
//
// The timestamp must be within +-TIMESTAMP_TOLERANCE_SECS of server time.
// This prevents replay attacks while allowing reasonable clock skew.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Maximum allowed clock skew between agent and SAFA daemon (seconds).
pub const TIMESTAMP_TOLERANCE_SECS: u64 = 300;

/// Errors from identity verification.
#[derive(Debug, PartialEq)]
pub enum IdentityError {
    /// X-Agent-Timestamp header missing or not valid ASCII.
    MissingTimestamp,
    /// X-Agent-Timestamp is not a valid u64.
    InvalidTimestamp,
    /// Timestamp is outside the acceptable +-300s window.
    ExpiredTimestamp,
    /// X-Agent-Signature header missing or not valid ASCII.
    MissingSignature,
    /// X-Agent-Signature is not valid hex.
    InvalidSignatureFormat,
    /// HMAC verification failed (wrong secret or tampered request).
    SignatureMismatch,
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingTimestamp => write!(f, "missing X-Agent-Timestamp header"),
            Self::InvalidTimestamp => write!(f, "X-Agent-Timestamp is not a valid unix timestamp"),
            Self::ExpiredTimestamp => write!(
                f,
                "X-Agent-Timestamp outside acceptable window (+-{}s)",
                TIMESTAMP_TOLERANCE_SECS
            ),
            Self::MissingSignature => write!(f, "missing X-Agent-Signature header"),
            Self::InvalidSignatureFormat => write!(f, "X-Agent-Signature is not valid hex"),
            Self::SignatureMismatch => write!(f, "HMAC signature verification failed"),
        }
    }
}

/// Compute SHA-256 of request body, returned as hex string.
pub fn body_hash(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    format!("{:x}", hasher.finalize())
}

/// Build the canonical message that gets signed:
/// `agent_id + "." + timestamp + "." + body_sha256`
fn build_signing_message(agent_id: &str, timestamp: &str, body_sha256: &str) -> String {
    format!("{}.{}.{}", agent_id, timestamp, body_sha256)
}

/// Compute the expected HMAC-SHA256 signature for a request.
/// Returns hex-encoded signature string.
pub fn compute_signature(secret: &str, agent_id: &str, timestamp: &str, body: &[u8]) -> String {
    let body_sha = body_hash(body);
    let message = build_signing_message(agent_id, timestamp, &body_sha);

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verify an agent's HMAC identity binding.
///
/// # Arguments
/// - `secret`: The agent's shared secret from config
/// - `agent_id`: The claimed agent ID from X-Agent-Id header
/// - `timestamp_str`: The X-Agent-Timestamp header value
/// - `signature_hex`: The X-Agent-Signature header value
/// - `body`: The raw request body bytes
/// - `now_secs`: Current server time as unix epoch seconds
///
/// # Returns
/// - `Ok(())` if identity is verified
/// - `Err(IdentityError)` with specific failure reason
pub fn verify_identity(
    secret: &str,
    agent_id: &str,
    timestamp_str: Option<&str>,
    signature_hex: Option<&str>,
    body: &[u8],
    now_secs: u64,
) -> Result<(), IdentityError> {
    // 1. Validate timestamp header exists and is parseable
    let timestamp_str = timestamp_str.ok_or(IdentityError::MissingTimestamp)?;
    let timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| IdentityError::InvalidTimestamp)?;

    // 2. Check timestamp is within tolerance window
    let diff = now_secs.abs_diff(timestamp);
    if diff > TIMESTAMP_TOLERANCE_SECS {
        return Err(IdentityError::ExpiredTimestamp);
    }

    // 3. Validate signature header exists
    let signature_hex = signature_hex.ok_or(IdentityError::MissingSignature)?;

    // 4. Decode hex signature
    let provided_sig =
        hex::decode(signature_hex).map_err(|_| IdentityError::InvalidSignatureFormat)?;

    // 5. Compute expected HMAC
    let body_sha = body_hash(body);
    let message = build_signing_message(agent_id, timestamp_str, &body_sha);

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());

    // 6. Constant-time comparison (via hmac crate's verify_slice)
    mac.verify_slice(&provided_sig)
        .map_err(|_| IdentityError::SignatureMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "a]3kf9$mZp!wL2xR7vN8qB4cY6hT0jDs";
    const TEST_AGENT: &str = "test-agent";
    const TEST_BODY: &[u8] = b"{\"action\":\"file_write\",\"target\":\"test.txt\",\"magnitude\":1}";

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn test_valid_signature() {
        let ts = now().to_string();
        let sig = compute_signature(TEST_SECRET, TEST_AGENT, &ts, TEST_BODY);
        let result = verify_identity(
            TEST_SECRET,
            TEST_AGENT,
            Some(&ts),
            Some(&sig),
            TEST_BODY,
            now(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_wrong_secret() {
        let ts = now().to_string();
        let sig = compute_signature(
            "wrong-secret-that-is-long-enough!",
            TEST_AGENT,
            &ts,
            TEST_BODY,
        );
        let result = verify_identity(
            TEST_SECRET,
            TEST_AGENT,
            Some(&ts),
            Some(&sig),
            TEST_BODY,
            now(),
        );
        assert_eq!(result, Err(IdentityError::SignatureMismatch));
    }

    #[test]
    fn test_tampered_body() {
        let ts = now().to_string();
        let sig = compute_signature(TEST_SECRET, TEST_AGENT, &ts, TEST_BODY);
        let tampered = b"{\"action\":\"shell_exec\",\"target\":\"rm -rf /\",\"magnitude\":1}";
        let result = verify_identity(
            TEST_SECRET,
            TEST_AGENT,
            Some(&ts),
            Some(&sig),
            tampered,
            now(),
        );
        assert_eq!(result, Err(IdentityError::SignatureMismatch));
    }

    #[test]
    fn test_expired_timestamp() {
        let old_ts = (now() - TIMESTAMP_TOLERANCE_SECS - 10).to_string();
        let sig = compute_signature(TEST_SECRET, TEST_AGENT, &old_ts, TEST_BODY);
        let result = verify_identity(
            TEST_SECRET,
            TEST_AGENT,
            Some(&old_ts),
            Some(&sig),
            TEST_BODY,
            now(),
        );
        assert_eq!(result, Err(IdentityError::ExpiredTimestamp));
    }

    #[test]
    fn test_future_timestamp() {
        let future_ts = (now() + TIMESTAMP_TOLERANCE_SECS + 10).to_string();
        let sig = compute_signature(TEST_SECRET, TEST_AGENT, &future_ts, TEST_BODY);
        let result = verify_identity(
            TEST_SECRET,
            TEST_AGENT,
            Some(&future_ts),
            Some(&sig),
            TEST_BODY,
            now(),
        );
        assert_eq!(result, Err(IdentityError::ExpiredTimestamp));
    }

    #[test]
    fn test_missing_timestamp() {
        let result = verify_identity(
            TEST_SECRET,
            TEST_AGENT,
            None,
            Some("deadbeef"),
            TEST_BODY,
            now(),
        );
        assert_eq!(result, Err(IdentityError::MissingTimestamp));
    }

    #[test]
    fn test_missing_signature() {
        let ts = now().to_string();
        let result = verify_identity(TEST_SECRET, TEST_AGENT, Some(&ts), None, TEST_BODY, now());
        assert_eq!(result, Err(IdentityError::MissingSignature));
    }

    #[test]
    fn test_invalid_hex_signature() {
        let ts = now().to_string();
        let result = verify_identity(
            TEST_SECRET,
            TEST_AGENT,
            Some(&ts),
            Some("not-hex-zzzz"),
            TEST_BODY,
            now(),
        );
        assert_eq!(result, Err(IdentityError::InvalidSignatureFormat));
    }

    #[test]
    fn test_invalid_timestamp_format() {
        let result = verify_identity(
            TEST_SECRET,
            TEST_AGENT,
            Some("not-a-number"),
            Some("deadbeef"),
            TEST_BODY,
            now(),
        );
        assert_eq!(result, Err(IdentityError::InvalidTimestamp));
    }

    #[test]
    fn test_signature_deterministic() {
        let ts = "1711000000";
        let sig1 = compute_signature(TEST_SECRET, TEST_AGENT, ts, TEST_BODY);
        let sig2 = compute_signature(TEST_SECRET, TEST_AGENT, ts, TEST_BODY);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_different_agents_different_signatures() {
        let ts = "1711000000";
        let sig_a = compute_signature(TEST_SECRET, "agent-a", ts, TEST_BODY);
        let sig_b = compute_signature(TEST_SECRET, "agent-b", ts, TEST_BODY);
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn test_timestamp_at_boundary_accepted() {
        let boundary_ts = (now() - TIMESTAMP_TOLERANCE_SECS).to_string();
        let sig = compute_signature(TEST_SECRET, TEST_AGENT, &boundary_ts, TEST_BODY);
        let result = verify_identity(
            TEST_SECRET,
            TEST_AGENT,
            Some(&boundary_ts),
            Some(&sig),
            TEST_BODY,
            now(),
        );
        assert!(result.is_ok());
    }
}
