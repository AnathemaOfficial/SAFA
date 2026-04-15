use axum::http::header::{HeaderName, HeaderValue};
use safa_daemon::server::test_server_with_capacity;
use serde_json::Value;
use uuid::Uuid;

const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");

fn hval(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap()
}

#[tokio::test]
async fn proof_endpoint_keeps_impossible_distinct_from_validation_error() {
    let server = test_server_with_capacity(1).await;

    let first = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .json(&serde_json::json!({
            "adapter": "test",
            "action": "file_write",
            "target": "a.txt",
            "magnitude": 1,
            "payload": "x"
        }))
        .await;
    first.assert_status_ok();

    let denied = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .json(&serde_json::json!({
            "adapter": "test",
            "action": "file_write",
            "target": "b.txt",
            "magnitude": 1,
            "payload": "y"
        }))
        .await;
    denied.assert_status(axum::http::StatusCode::FORBIDDEN);
    let denied_json = denied.json::<Value>();
    let denied_action_id = denied_json["action_id"]
        .as_str()
        .expect("impossible response should carry action_id");

    let denied_proof = server.get(&format!("/ama/proof/{denied_action_id}")).await;
    denied_proof.assert_status_ok();
    let denied_proof_json = denied_proof.json::<Value>();
    assert_eq!(denied_proof_json["verdict"], "IMPOSSIBLE");
    let ts = denied_proof_json["timestamp"].as_str().unwrap();
    assert!(ts.contains('T') && ts.ends_with('Z'));

    let bad = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .json(&serde_json::json!({
            "adapter": "test",
            "action": "file_write",
            "target": "bad.txt",
            "magnitude": 1
        }))
        .await;
    bad.assert_status(axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    let bad_json = bad.json::<Value>();
    let validation_action_id = bad_json["action_id"]
        .as_str()
        .expect("terminal validation error should carry action_id");

    let validation_proof = server
        .get(&format!("/ama/proof/{validation_action_id}"))
        .await;
    validation_proof.assert_status_ok();
    let validation_proof_json = validation_proof.json::<Value>();
    assert_eq!(validation_proof_json["verdict"], "VALIDATION_ERROR");
    let ts = validation_proof_json["timestamp"].as_str().unwrap();
    assert!(ts.contains('T') && ts.ends_with('Z'));
}

#[tokio::test]
async fn invalid_adapter_returns_validation_error() {
    let server = test_server_with_capacity(10).await;

    let resp = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .json(&serde_json::json!({
            "adapter": "bad\nadapter",
            "action": "file_write",
            "target": "bad.txt",
            "magnitude": 1,
            "payload": "hello"
        }))
        .await;

    resp.assert_status(axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    let body = resp.json::<Value>();
    assert_eq!(body["status"], "error");
    assert_eq!(body["error_class"], "invalid_adapter");
    assert_eq!(body["message"], "adapter must be 1-64 chars of [A-Za-z0-9_-]");
    assert!(body["action_id"].as_str().is_some());
}
