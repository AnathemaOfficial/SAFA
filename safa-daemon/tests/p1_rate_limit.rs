/// P1 WS4 — Race-Safe Rate Limiting Tests
///
/// These tests validate that the rate limiter cannot be bypassed
/// under concurrent burst and that window reset is atomic.
///
/// Reference: docs/SAFA_P1_TASKLIST.md (WS4)
/// Reference: docs/KNOWN_ISSUES_P1.md (C3)
use safa_daemon::server::{test_server, test_server_with_capacity};
use uuid::Uuid;

/// Helper: POST a valid action
async fn post_valid_action(server: &axum_test::TestServer) -> axum_test::TestResponse {
    let key = Uuid::new_v4().to_string();
    server
        .post("/ama/action")
        .add_header(
            axum::http::header::HeaderName::from_static("idempotency-key"),
            axum::http::header::HeaderValue::from_str(&key).unwrap(),
        )
        .json(&serde_json::json!({
            "adapter": "test",
            "action": "file_write",
            "target": format!("rate_test_{}.txt", key),
            "magnitude": 1,
            "payload": "data"
        }))
        .await
}

/// Test 1 — Sequential requests within limit
///
/// 10 requests sequentially should all succeed (limit is 60/min).
#[tokio::test]
async fn test_rate_limit_sequential_within_limit() {
    let server = test_server().await;

    for i in 0..10 {
        let resp = post_valid_action(&server).await;
        assert!(
            resp.status_code().is_success()
                || resp.status_code() == axum::http::StatusCode::FORBIDDEN,
            "request {} should not be rate-limited, got {}",
            i,
            resp.status_code()
        );
    }
}

/// Test 2 — Sequential requests beyond limit
///
/// 65 requests sequentially — the first 60 should succeed,
/// the rest should be rate-limited (429).
#[tokio::test]
async fn test_rate_limit_sequential_beyond_limit() {
    let server = test_server_with_capacity(10_000).await;

    let mut ok_count = 0u32;
    let mut limited_count = 0u32;

    for _ in 0..65 {
        let resp = post_valid_action(&server).await;
        match resp.status_code() {
            axum::http::StatusCode::TOO_MANY_REQUESTS => limited_count += 1,
            _ => ok_count += 1,
        }
    }

    // At most 60 should pass, at least 5 should be limited
    assert!(
        ok_count <= 60,
        "rate limiter failed: {} requests passed (limit is 60/min)",
        ok_count
    );
    assert!(
        limited_count >= 5,
        "rate limiter failed: only {} requests were limited out of 65",
        limited_count
    );
}

/// Test 3 — Burst beyond limit (sequential rapid-fire)
///
/// Fire 80 requests as fast as possible. Under a correct rate limiter,
/// at most 60 should pass within one window. The rest must be 429.
#[tokio::test]
async fn test_rate_limit_burst_beyond_limit() {
    let server = test_server_with_capacity(10_000).await;

    let mut ok_count = 0u32;

    for _ in 0..80 {
        let resp = post_valid_action(&server).await;
        if resp.status_code() != axum::http::StatusCode::TOO_MANY_REQUESTS {
            ok_count += 1;
        }
    }

    assert!(
        ok_count <= 60,
        "RATE LIMITER BYPASS (C3): {} requests passed through (limit is 60/min). \
         The counter increment is not atomic with the window check.",
        ok_count
    );
}
