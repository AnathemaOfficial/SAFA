use axum::http::header::{HeaderName, HeaderValue};
use bytes::Bytes;
use safa_core::config::{AgentConfig, BootHashes, DomainPolicy};
use safa_core::identity::compute_signature;
use safa_core::manifest::PublicManifest;
use safa_daemon::server::{test_server, test_server_with_agent_specs, TestAgentSpec};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");
const X_AGENT_ID: HeaderName = HeaderName::from_static("x-agent-id");
const X_AGENT_TIMESTAMP: HeaderName = HeaderName::from_static("x-agent-timestamp");
const X_AGENT_SIGNATURE: HeaderName = HeaderName::from_static("x-agent-signature");

fn hval(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn default_domain_policies() -> HashMap<String, DomainPolicy> {
    let mut domain_policies = HashMap::new();
    domain_policies.insert(
        "fs.write.workspace".into(),
        DomainPolicy {
            enabled: true,
            max_magnitude_per_action: 1000,
        },
    );
    domain_policies
}

fn action_request(target: &str) -> Value {
    json!({
        "adapter": "test",
        "action": "file_write",
        "target": target,
        "magnitude": 1,
        "payload": "hello"
    })
}

fn body_bytes(target: &str) -> Vec<u8> {
    serde_json::to_vec(&action_request(target)).unwrap()
}

fn build_test_agent(
    agent_id: &str,
    secret: Option<&str>,
    rate_limit_per_window: u64,
    rate_limit_window_secs: u64,
) -> TestAgentSpec {
    TestAgentSpec {
        agent_id: agent_id.to_string(),
        max_capacity: 10_000,
        rate_limit_per_window,
        rate_limit_window_secs,
        secret: secret.map(|s| s.to_string()),
    }
}

fn manifest_hash_for(
    agent_id: &str,
    secret: Option<&str>,
    rate_limit_per_window: u64,
    rate_limit_window_secs: u64,
) -> String {
    let bundle_hash = BootHashes {
        config_hash: "test".into(),
        domains_hash: "test".into(),
        intents_hash: "test".into(),
        allowlist_hash: "test".into(),
        agents_hash: "test".into(),
    }
    .policy_bundle_hash();
    let agent = AgentConfig {
        agent_id: agent_id.to_string(),
        max_capacity: 10_000,
        rate_limit_per_window,
        rate_limit_window_secs,
        domain_policies: default_domain_policies(),
        secret: secret.map(|s| s.to_string()),
    };
    PublicManifest::from_agent_config(&agent, &bundle_hash)
        .hash()
        .to_string()
}

#[tokio::test]
async fn signed_request_succeeds_and_sets_policy_hash() {
    let secret = "0123456789abcdef0123456789abcdef";
    let agent_id = "signed-agent";
    let server =
        test_server_with_agent_specs(vec![build_test_agent(agent_id, Some(secret), 60, 60)]).await;

    let body = body_bytes("signed.txt");
    let timestamp = now_secs().to_string();
    let signature = compute_signature(secret, agent_id, &timestamp, &body);
    let expected_hash = manifest_hash_for(agent_id, Some(secret), 60, 60);

    let resp = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .add_header(X_AGENT_ID, hval(agent_id))
        .add_header(X_AGENT_TIMESTAMP, hval(&timestamp))
        .add_header(X_AGENT_SIGNATURE, hval(&signature))
        .content_type("application/json")
        .bytes(Bytes::from(body))
        .await;

    resp.assert_status_ok();
    resp.assert_header("x-safa-policy-hash", expected_hash);
}

#[tokio::test]
async fn exact_signed_replay_with_different_idempotency_key_returns_403() {
    let secret = "0123456789abcdef0123456789abcdef";
    let agent_id = "signed-agent";
    let server =
        test_server_with_agent_specs(vec![build_test_agent(agent_id, Some(secret), 60, 60)]).await;

    let body = body_bytes("replay-different-key.txt");
    let timestamp = now_secs().to_string();
    let signature = compute_signature(secret, agent_id, &timestamp, &body);

    let resp1 = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .add_header(X_AGENT_ID, hval(agent_id))
        .add_header(X_AGENT_TIMESTAMP, hval(&timestamp))
        .add_header(X_AGENT_SIGNATURE, hval(&signature))
        .content_type("application/json")
        .bytes(Bytes::from(body.clone()))
        .await;
    resp1.assert_status_ok();

    let resp2 = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .add_header(X_AGENT_ID, hval(agent_id))
        .add_header(X_AGENT_TIMESTAMP, hval(&timestamp))
        .add_header(X_AGENT_SIGNATURE, hval(&signature))
        .content_type("application/json")
        .bytes(Bytes::from(body))
        .await;

    resp2.assert_status(axum::http::StatusCode::FORBIDDEN);
    resp2.assert_json(&json!({
        "status": "error",
        "error_class": "replay_detected",
        "message": "signed request replay detected"
    }));
}

#[tokio::test]
async fn exact_signed_retry_with_same_idempotency_key_replays_cached_result() {
    let secret = "0123456789abcdef0123456789abcdef";
    let agent_id = "signed-agent";
    let server =
        test_server_with_agent_specs(vec![build_test_agent(agent_id, Some(secret), 60, 60)]).await;

    let body = body_bytes("replay-same-key.txt");
    let timestamp = now_secs().to_string();
    let signature = compute_signature(secret, agent_id, &timestamp, &body);
    let idem_key = Uuid::new_v4().to_string();

    let resp1 = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&idem_key))
        .add_header(X_AGENT_ID, hval(agent_id))
        .add_header(X_AGENT_TIMESTAMP, hval(&timestamp))
        .add_header(X_AGENT_SIGNATURE, hval(&signature))
        .content_type("application/json")
        .bytes(Bytes::from(body.clone()))
        .await;
    resp1.assert_status_ok();
    let body1 = resp1.json::<Value>();

    let resp2 = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&idem_key))
        .add_header(X_AGENT_ID, hval(agent_id))
        .add_header(X_AGENT_TIMESTAMP, hval(&timestamp))
        .add_header(X_AGENT_SIGNATURE, hval(&signature))
        .content_type("application/json")
        .bytes(Bytes::from(body))
        .await;
    resp2.assert_status_ok();
    let body2 = resp2.json::<Value>();

    assert_eq!(
        body2, body1,
        "same envelope + same key should replay cached result"
    );
}

#[tokio::test]
async fn missing_signature_header_returns_403() {
    let secret = "0123456789abcdef0123456789abcdef";
    let agent_id = "signed-agent";
    let server =
        test_server_with_agent_specs(vec![build_test_agent(agent_id, Some(secret), 60, 60)]).await;

    let body = body_bytes("missing-signature.txt");
    let timestamp = now_secs().to_string();

    let resp = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .add_header(X_AGENT_ID, hval(agent_id))
        .add_header(X_AGENT_TIMESTAMP, hval(&timestamp))
        .content_type("application/json")
        .bytes(Bytes::from(body))
        .await;

    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    resp.assert_json(&json!({
        "status": "error",
        "error_class": "identity_verification_failed",
        "message": "missing X-Agent-Signature header"
    }));
}

#[tokio::test]
async fn missing_timestamp_header_returns_403() {
    let secret = "0123456789abcdef0123456789abcdef";
    let agent_id = "signed-agent";
    let server =
        test_server_with_agent_specs(vec![build_test_agent(agent_id, Some(secret), 60, 60)]).await;

    let body = body_bytes("missing-timestamp.txt");
    let signature = compute_signature(secret, agent_id, &now_secs().to_string(), &body);

    let resp = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .add_header(X_AGENT_ID, hval(agent_id))
        .add_header(X_AGENT_SIGNATURE, hval(&signature))
        .content_type("application/json")
        .bytes(Bytes::from(body))
        .await;

    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    resp.assert_json(&json!({
        "status": "error",
        "error_class": "identity_verification_failed",
        "message": "missing X-Agent-Timestamp header"
    }));
}

#[tokio::test]
async fn invalid_signature_format_returns_403() {
    let secret = "0123456789abcdef0123456789abcdef";
    let agent_id = "signed-agent";
    let server =
        test_server_with_agent_specs(vec![build_test_agent(agent_id, Some(secret), 60, 60)]).await;

    let body = body_bytes("invalid-signature.txt");
    let timestamp = now_secs().to_string();

    let resp = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .add_header(X_AGENT_ID, hval(agent_id))
        .add_header(X_AGENT_TIMESTAMP, hval(&timestamp))
        .add_header(X_AGENT_SIGNATURE, hval("not-hex"))
        .content_type("application/json")
        .bytes(Bytes::from(body))
        .await;

    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    resp.assert_json(&json!({
        "status": "error",
        "error_class": "identity_verification_failed",
        "message": "X-Agent-Signature is not valid hex"
    }));
}

#[tokio::test]
async fn tampered_body_signature_returns_403() {
    let secret = "0123456789abcdef0123456789abcdef";
    let agent_id = "signed-agent";
    let server =
        test_server_with_agent_specs(vec![build_test_agent(agent_id, Some(secret), 60, 60)]).await;

    let signed_body = body_bytes("signed-body.txt");
    let tampered_body = body_bytes("tampered-body.txt");
    let timestamp = now_secs().to_string();
    let signature = compute_signature(secret, agent_id, &timestamp, &signed_body);

    let resp = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .add_header(X_AGENT_ID, hval(agent_id))
        .add_header(X_AGENT_TIMESTAMP, hval(&timestamp))
        .add_header(X_AGENT_SIGNATURE, hval(&signature))
        .content_type("application/json")
        .bytes(Bytes::from(tampered_body))
        .await;

    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    resp.assert_json(&json!({
        "status": "error",
        "error_class": "identity_verification_failed",
        "message": "HMAC signature verification failed"
    }));
}

#[tokio::test]
async fn unsigned_request_to_unbound_agent_still_succeeds() {
    let server =
        test_server_with_agent_specs(vec![build_test_agent("compat-agent", None, 60, 60)]).await;

    let resp = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .content_type("application/json")
        .bytes(Bytes::from(body_bytes("compat.txt")))
        .await;

    resp.assert_status_ok();
}

#[tokio::test]
async fn malformed_json_is_cached_as_terminal_result() {
    let server = test_server().await;
    let key = Uuid::new_v4().to_string();
    let raw = Bytes::from_static(br#"{"adapter":"test","action":"file_write""#);

    let resp1 = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&key))
        .content_type("application/json")
        .bytes(raw.clone())
        .await;
    resp1.assert_status(axum::http::StatusCode::BAD_REQUEST);
    let body1 = resp1.json::<Value>();
    assert_eq!(body1["status"], "error");
    assert_eq!(body1["error_class"], "bad_request");

    let resp2 = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&key))
        .content_type("application/json")
        .bytes(raw)
        .await;
    resp2.assert_status_ok();
    let body2 = resp2.json::<Value>();

    assert_eq!(
        body2, body1,
        "retry with same key should replay cached terminal error"
    );
}

#[tokio::test]
async fn wrong_content_type_returns_415() {
    let server = test_server().await;

    let resp = server
        .post("/ama/action")
        .content_type("text/plain")
        .bytes(Bytes::from_static(b"not-json"))
        .await;

    resp.assert_status(axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn rate_limit_window_resets_after_elapsed_window() {
    let server =
        test_server_with_agent_specs(vec![build_test_agent("window-agent", None, 2, 1)]).await;

    for idx in 0..2 {
        let resp = server
            .post("/ama/action")
            .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
            .content_type("application/json")
            .bytes(Bytes::from(body_bytes(&format!("within-window-{idx}.txt"))))
            .await;
        resp.assert_status_ok();
    }

    let limited = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .content_type("application/json")
        .bytes(Bytes::from(body_bytes("window-limited.txt")))
        .await;
    limited.assert_status(axum::http::StatusCode::TOO_MANY_REQUESTS);

    sleep(Duration::from_millis(1_100)).await;

    let after_reset = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .content_type("application/json")
        .bytes(Bytes::from(body_bytes("after-reset.txt")))
        .await;
    after_reset.assert_status_ok();
}
