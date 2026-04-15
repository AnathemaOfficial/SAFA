use safa_daemon::server::{test_server, test_server_with_capacity};

#[tokio::test]
async fn health_returns_ok() {
    let server = test_server().await;
    let resp = server.get("/health").await;
    resp.assert_status_ok();
    resp.assert_json(&serde_json::json!({"status": "ok"}));
}

#[tokio::test]
async fn version_returns_info() {
    let server = test_server().await;
    let resp = server.get("/version").await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn action_without_idempotency_key_returns_400() {
    let server = test_server().await;
    let resp = server
        .post("/ama/action")
        .json(&serde_json::json!({
            "adapter": "test",
            "action": "file_write",
            "target": "test.txt",
            "magnitude": 1,
            "payload": "hello"
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn valid_file_write_returns_200() {
    let server = test_server().await;
    let resp = server
        .post("/ama/action")
        .add_header(
            axum::http::header::HeaderName::from_static("idempotency-key"),
            axum::http::header::HeaderValue::from_str(&uuid::Uuid::new_v4().to_string()).unwrap(),
        )
        .json(&serde_json::json!({
            "adapter": "test",
            "action": "file_write",
            "target": "test.txt",
            "magnitude": 1,
            "payload": "hello"
        }))
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn impossible_returns_403() {
    let server = test_server_with_capacity(1).await;
    // First call succeeds
    server
        .post("/ama/action")
        .add_header(
            axum::http::header::HeaderName::from_static("idempotency-key"),
            axum::http::header::HeaderValue::from_str(&uuid::Uuid::new_v4().to_string()).unwrap(),
        )
        .json(&serde_json::json!({
            "adapter": "test", "action": "file_write",
            "target": "a.txt", "magnitude": 1, "payload": "x"
        }))
        .await
        .assert_status_ok();
    // Second call: capacity exhausted
    let resp = server
        .post("/ama/action")
        .add_header(
            axum::http::header::HeaderName::from_static("idempotency-key"),
            axum::http::header::HeaderValue::from_str(&uuid::Uuid::new_v4().to_string()).unwrap(),
        )
        .json(&serde_json::json!({
            "adapter": "test", "action": "file_write",
            "target": "b.txt", "magnitude": 1, "payload": "y"
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    let body = resp.json::<serde_json::Value>();
    assert_eq!(body["status"], "impossible");
    assert!(body["action_id"].as_str().is_some());
}
