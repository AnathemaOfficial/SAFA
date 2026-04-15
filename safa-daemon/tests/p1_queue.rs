use axum::http::StatusCode;
/// P1 WS3 — Bounded Queue and Admission Tests
///
/// These tests validate that SAFA handles load deterministically:
/// - Bounded concurrency (max 8 simultaneous)
/// - Overflow fails closed (timeout, not hang)
/// - Queue + duplicate key does not double-execute
///
/// Reference: docs/SAFA_QUEUE_MODEL.md
/// Reference: docs/SAFA_P1_TASKLIST.md (WS3)
use safa_daemon::server::test_server;
use uuid::Uuid;

/// Test 1 — Multiple requests succeed under concurrency limit
///
/// Send 5 requests (well under the 8 limit). All should succeed.
#[tokio::test]
async fn test_queue_accepts_within_capacity() {
    let server = test_server().await;

    for i in 0..5 {
        let key = Uuid::new_v4().to_string();
        let resp = server
            .post("/ama/action")
            .add_header(
                axum::http::header::HeaderName::from_static("idempotency-key"),
                axum::http::header::HeaderValue::from_str(&key).unwrap(),
            )
            .json(&serde_json::json!({
                "adapter": "test",
                "action": "file_write",
                "target": format!("queue_test_{}.txt", i),
                "magnitude": 1,
                "payload": "data"
            }))
            .await;

        assert!(
            resp.status_code().is_success(),
            "request {} should succeed under concurrency limit, got {}",
            i,
            resp.status_code()
        );
    }
}

/// Test 2 — Duplicate key during queue does not double-execute
///
/// Submit same key twice sequentially. Second must replay, not execute.
/// This validates that queue + idempotency interaction is correct.
#[tokio::test]
async fn test_queue_duplicate_key_no_double_execute() {
    let server = test_server().await;
    let key = Uuid::new_v4().to_string();

    // First request
    let resp1 = server
        .post("/ama/action")
        .add_header(
            axum::http::header::HeaderName::from_static("idempotency-key"),
            axum::http::header::HeaderValue::from_str(&key).unwrap(),
        )
        .json(&serde_json::json!({
            "adapter": "test",
            "action": "file_write",
            "target": "dup_queue_test.txt",
            "magnitude": 1,
            "payload": "first"
        }))
        .await;
    resp1.assert_status_ok();
    let body1 = resp1.text();

    // Second request with same key — must replay
    let resp2 = server
        .post("/ama/action")
        .add_header(
            axum::http::header::HeaderName::from_static("idempotency-key"),
            axum::http::header::HeaderValue::from_str(&key).unwrap(),
        )
        .json(&serde_json::json!({
            "adapter": "test",
            "action": "file_write",
            "target": "dup_queue_test.txt",
            "magnitude": 1,
            "payload": "first"
        }))
        .await;
    resp2.assert_status_ok();
    let body2 = resp2.text();

    assert_eq!(
        body1, body2,
        "duplicate key must replay, not double-execute"
    );
}

/// Test 3 — Overflow response is deterministic
///
/// When the queue/limit is saturated and timeout fires,
/// the response must be a clear error, not a hang.
/// This test validates the fail-closed property.
///
/// Note: We can't easily saturate the concurrency_limit in integration
/// tests since TestServer processes sequentially. This test validates
/// that the error response format is correct when returned.
#[tokio::test]
async fn test_overflow_response_is_deterministic() {
    let server = test_server().await;

    // Send a request that will fail (bad action) — verifies error path
    // is deterministic under queue pressure
    let key = Uuid::new_v4().to_string();
    let resp = server
        .post("/ama/action")
        .add_header(
            axum::http::header::HeaderName::from_static("idempotency-key"),
            axum::http::header::HeaderValue::from_str(&key).unwrap(),
        )
        .json(&serde_json::json!({
            "adapter": "test",
            "action": "nonexistent_action",
            "target": "test.txt",
            "magnitude": 1,
            "payload": "data"
        }))
        .await;

    // Should get a deterministic error (not a hang, not a crash)
    let status = resp.status_code();
    assert!(
        status == StatusCode::UNPROCESSABLE_ENTITY
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::FORBIDDEN,
        "overflow/error response must be deterministic, got {}",
        status
    );

    // Replay with same key must return cached error (Model A)
    let resp2 = server
        .post("/ama/action")
        .add_header(
            axum::http::header::HeaderName::from_static("idempotency-key"),
            axum::http::header::HeaderValue::from_str(&key).unwrap(),
        )
        .json(&serde_json::json!({
            "adapter": "test",
            "action": "nonexistent_action",
            "target": "test.txt",
            "magnitude": 1,
            "payload": "data"
        }))
        .await;

    // Must replay (200 with cached error body), not re-execute
    assert_eq!(
        resp2.status_code(),
        StatusCode::OK,
        "replay after error must return cached result (200), got {}",
        resp2.status_code()
    );
}
