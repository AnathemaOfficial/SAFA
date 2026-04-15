use axum::http::StatusCode;
/// P1 Section 9 — Cross-Cutting Adversarial Tests
///
/// These tests validate that SAFA's hardened subsystems interact correctly
/// under combined stress. Each test exercises multiple workstreams simultaneously.
///
/// Reference: docs/SAFA_P1_TASKLIST.md (Section 9)
use safa_daemon::server::{test_server, test_server_with_capacity};
use uuid::Uuid;

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

/// POST a valid file_write action with a fresh key
async fn post_action(server: &axum_test::TestServer, target: &str) -> axum_test::TestResponse {
    let key = Uuid::new_v4().to_string();
    post_action_with_key(server, &key, target).await
}

/// POST a valid file_write action with a specific key
async fn post_action_with_key(
    server: &axum_test::TestServer,
    key: &str,
    target: &str,
) -> axum_test::TestResponse {
    server
        .post("/ama/action")
        .add_header(
            axum::http::header::HeaderName::from_static("idempotency-key"),
            axum::http::header::HeaderValue::from_str(key).unwrap(),
        )
        .json(&serde_json::json!({
            "adapter": "test",
            "action": "file_write",
            "target": target,
            "magnitude": 1,
            "payload": "data"
        }))
        .await
}

/// POST an invalid action (will fail validation)
async fn post_bad_action_with_key(
    server: &axum_test::TestServer,
    key: &str,
) -> axum_test::TestResponse {
    server
        .post("/ama/action")
        .add_header(
            axum::http::header::HeaderName::from_static("idempotency-key"),
            axum::http::header::HeaderValue::from_str(key).unwrap(),
        )
        .json(&serde_json::json!({
            "adapter": "test",
            "action": "nonexistent_action",
            "target": "test.txt",
            "magnitude": 1,
            "payload": "data"
        }))
        .await
}

// ─────────────────────────────────────────────
// Test 1 — Same-key concurrent duplicate under queue pressure
//
// WS1 (idempotency) × WS3 (queue): Submit many requests to create
// queue pressure, then submit duplicate key. The duplicate must
// replay, never double-execute.
// ─────────────────────────────────────────────
#[tokio::test]
async fn test_duplicate_key_under_queue_pressure() {
    let server = test_server().await;

    // Fill the queue with 7 distinct requests first
    for i in 0..7 {
        let resp = post_action(&server, &format!("pressure_{}.txt", i)).await;
        assert!(
            resp.status_code().is_success(),
            "request {} should succeed, got {}",
            i,
            resp.status_code()
        );
    }

    // Now submit a request and then replay it under pressure
    let dup_key = Uuid::new_v4().to_string();
    let resp1 = post_action_with_key(&server, &dup_key, "dup_pressure.txt").await;
    assert!(
        resp1.status_code().is_success(),
        "first request should succeed, got {}",
        resp1.status_code()
    );
    let body1 = resp1.text();

    // Replay with same key — must return cached result
    let resp2 = post_action_with_key(&server, &dup_key, "dup_pressure.txt").await;
    resp2.assert_status_ok();
    let body2 = resp2.text();

    assert_eq!(
        body1, body2,
        "replay under queue pressure must return identical result"
    );
}

// ─────────────────────────────────────────────
// Test 2 — Mixed requests racing for last capacity units
//
// WS2 (capacity) × WS3 (queue): Set capacity to 5, send 8 requests.
// Exactly 5 should succeed, 3 should get Impossible (403).
// ─────────────────────────────────────────────
#[tokio::test]
async fn test_mixed_requests_racing_last_capacity() {
    let server = test_server_with_capacity(5).await;

    let mut success_count = 0u32;
    let mut denied_count = 0u32;

    for i in 0..8 {
        let resp = post_action(&server, &format!("race_{}.txt", i)).await;
        match resp.status_code() {
            StatusCode::OK => success_count += 1,
            StatusCode::FORBIDDEN => denied_count += 1,
            other => panic!("unexpected status {} on request {}", other, i),
        }
    }

    assert_eq!(
        success_count, 5,
        "exactly 5 requests should succeed (capacity=5), got {}",
        success_count
    );
    assert_eq!(
        denied_count, 3,
        "exactly 3 requests should be denied, got {}",
        denied_count
    );
}

// ─────────────────────────────────────────────
// Test 3 — Rate-limit flood plus duplicate keys
//
// WS4 (rate limit) × WS1 (idempotency): Exhaust rate limiter,
// then replay a previously successful key. Replay must succeed
// because idempotency replay does not count as a new action
// OR must be rate-limited (both are acceptable — depends on
// whether rate check is before or after idempotency).
// The key invariant: replay never re-executes regardless.
// ─────────────────────────────────────────────
#[tokio::test]
async fn test_rate_limit_flood_plus_duplicate_keys() {
    let server = test_server_with_capacity(10_000).await;

    // First: execute a request and save its key
    let saved_key = Uuid::new_v4().to_string();
    let resp = post_action_with_key(&server, &saved_key, "rate_dup.txt").await;
    assert!(
        resp.status_code().is_success(),
        "initial request should succeed, got {}",
        resp.status_code()
    );
    let original_body = resp.text();

    // Exhaust rate limiter (60/min limit — we already used 1)
    for i in 0..62 {
        let _resp = post_action(&server, &format!("flood_{}.txt", i)).await;
    }

    // Now replay saved key — it should either:
    // (a) return 200 with cached body (replay bypasses rate limit), OR
    // (b) return 429 (rate limit applied before idempotency check)
    let replay = post_action_with_key(&server, &saved_key, "rate_dup.txt").await;
    let status = replay.status_code();

    assert!(
        status == StatusCode::OK || status == StatusCode::TOO_MANY_REQUESTS,
        "replay under rate limit must be either cached (200) or rate-limited (429), got {}",
        status
    );

    // If it returned 200, body must match original (no re-execution)
    if status == StatusCode::OK {
        let replay_body = replay.text();
        assert_eq!(
            original_body, replay_body,
            "replay body must match original — no re-execution"
        );
    }
}

// ─────────────────────────────────────────────
// Test 4 — Replay after committed success
//
// WS1 × WS5: Execute successfully, replay. Validates Model A
// for the success path under normal conditions.
// ─────────────────────────────────────────────
#[tokio::test]
async fn test_replay_after_committed_success() {
    let server = test_server().await;
    let key = Uuid::new_v4().to_string();

    let resp1 = post_action_with_key(&server, &key, "success_replay.txt").await;
    resp1.assert_status_ok();
    let body1 = resp1.text();

    // Second call — must be identical replay
    let resp2 = post_action_with_key(&server, &key, "success_replay.txt").await;
    resp2.assert_status_ok();
    let body2 = resp2.text();

    assert_eq!(body1, body2, "replay after success must be identical");

    // Third call — still identical
    let resp3 = post_action_with_key(&server, &key, "success_replay.txt").await;
    resp3.assert_status_ok();
    let body3 = resp3.text();

    assert_eq!(body1, body3, "third replay must still be identical");
}

// ─────────────────────────────────────────────
// Test 5 — Replay after deterministic denial
//
// WS1 × WS2: Cause a denial (bad action), replay with same key.
// Model A: denial is committed, replay returns cached denial (200).
// ─────────────────────────────────────────────
#[tokio::test]
async fn test_replay_after_deterministic_denial() {
    let server = test_server().await;
    let key = Uuid::new_v4().to_string();

    // First call — will fail (bad action)
    let resp1 = post_bad_action_with_key(&server, &key).await;
    let status1 = resp1.status_code();
    assert!(
        status1 == StatusCode::UNPROCESSABLE_ENTITY
            || status1 == StatusCode::BAD_REQUEST
            || status1 == StatusCode::FORBIDDEN,
        "bad action should return error, got {}",
        status1
    );

    // Replay — Model A: committed error replays as 200 with cached body
    let resp2 = post_bad_action_with_key(&server, &key).await;
    assert_eq!(
        resp2.status_code(),
        StatusCode::OK,
        "replay after denial must return cached result (200), got {}",
        resp2.status_code()
    );
}

// ─────────────────────────────────────────────
// Test 6 — Capacity exhaustion plus idempotency replay
//
// WS2 × WS1: Exhaust capacity, get denied, then replay a
// previously successful key. Success replay must still work
// even when capacity is exhausted (it's a replay, not new).
// ─────────────────────────────────────────────
#[tokio::test]
async fn test_capacity_exhaustion_plus_replay() {
    let server = test_server_with_capacity(3).await;

    // Execute 2 successful requests, save a key
    let saved_key = Uuid::new_v4().to_string();
    let resp = post_action_with_key(&server, &saved_key, "cap_replay.txt").await;
    assert!(resp.status_code().is_success());
    let saved_body = resp.text();

    let _resp2 = post_action(&server, "cap_fill_1.txt").await;

    // Exhaust remaining capacity
    let _resp3 = post_action(&server, "cap_fill_2.txt").await;

    // New request should be denied (capacity exhausted)
    let resp_denied = post_action(&server, "cap_denied.txt").await;
    assert_eq!(
        resp_denied.status_code(),
        StatusCode::FORBIDDEN,
        "new request with exhausted capacity should be 403, got {}",
        resp_denied.status_code()
    );

    // Replay saved key — should still succeed (it's a replay, not new execution)
    let replay = post_action_with_key(&server, &saved_key, "cap_replay.txt").await;
    assert_eq!(
        replay.status_code(),
        StatusCode::OK,
        "replay of successful key must work even with exhausted capacity, got {}",
        replay.status_code()
    );
    let replay_body = replay.text();
    assert_eq!(saved_body, replay_body, "replay body must match original");
}

// ─────────────────────────────────────────────
// Test 7 — Many unique keys rapid-fire (mixed workload stress)
//
// All workstreams: Fire 50 unique requests rapidly against a
// server with moderate capacity. Verify invariants:
// - no crashes
// - every response is deterministic (200 or 403)
// - total successes <= capacity
// ─────────────────────────────────────────────
#[tokio::test]
async fn test_many_unique_keys_rapid_fire() {
    let server = test_server_with_capacity(20).await;

    let mut success_count = 0u32;
    let mut denied_count = 0u32;
    let mut rate_limited_count = 0u32;

    for i in 0..50 {
        let resp = post_action(&server, &format!("stress_{}.txt", i)).await;
        match resp.status_code() {
            StatusCode::OK => success_count += 1,
            StatusCode::FORBIDDEN => denied_count += 1,
            StatusCode::TOO_MANY_REQUESTS => rate_limited_count += 1,
            other => panic!("unexpected status {} on request {}", other, i),
        }
    }

    assert!(
        success_count <= 20,
        "successes ({}) must not exceed capacity (20)",
        success_count
    );
    assert_eq!(
        success_count + denied_count + rate_limited_count,
        50,
        "all 50 requests must have deterministic outcomes"
    );
}

// ─────────────────────────────────────────────
// Test 8 — Denial replay does not consume capacity
//
// WS1 × WS2: After a denial is committed, replaying it must
// not consume additional capacity units.
// ─────────────────────────────────────────────
#[tokio::test]
async fn test_denial_replay_does_not_consume_capacity() {
    let server = test_server_with_capacity(5).await;

    // Cause a denial (bad action) and commit it
    let bad_key = Uuid::new_v4().to_string();
    let _resp = post_bad_action_with_key(&server, &bad_key).await;

    // Replay the denial 10 times — none should consume capacity
    for _ in 0..10 {
        let replay = post_bad_action_with_key(&server, &bad_key).await;
        assert_eq!(
            replay.status_code(),
            StatusCode::OK,
            "denial replay must return cached result"
        );
    }

    // All 5 capacity units should still be available
    for i in 0..5 {
        let resp = post_action(&server, &format!("after_denial_{}.txt", i)).await;
        assert!(
            resp.status_code().is_success(),
            "request {} should succeed (capacity not consumed by replays), got {}",
            i,
            resp.status_code()
        );
    }
}
