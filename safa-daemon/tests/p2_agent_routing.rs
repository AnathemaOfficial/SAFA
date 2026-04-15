use axum::http::header::{HeaderName, HeaderValue};
use serde_json::json;
use uuid::Uuid;

fn hval(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap()
}

const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");
const X_AGENT_ID: HeaderName = HeaderName::from_static("x-agent-id");

#[tokio::test]
async fn test_missing_agent_id_uses_default_when_single_agent() {
    let server = safa_daemon::server::test_server_multiagent(vec![("default", 10000, 60)]).await;
    let resp = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .json(&json!({
            "adapter": "test", "action": "file_write",
            "target": "test.txt", "magnitude": 1,
            "payload": "hello"
        }))
        .await;
    assert_eq!(resp.status_code(), 200);
}

#[tokio::test]
async fn test_missing_agent_id_rejected_when_multi_agent() {
    let server = safa_daemon::server::test_server_multiagent(vec![
        ("agent_a", 10000, 60),
        ("agent_b", 10000, 60),
    ])
    .await;
    let resp = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .json(&json!({
            "adapter": "test", "action": "file_write",
            "target": "test.txt", "magnitude": 1,
            "payload": "hello"
        }))
        .await;
    assert_eq!(resp.status_code(), 400);
}

#[tokio::test]
async fn test_unknown_agent_id_rejected() {
    let server = safa_daemon::server::test_server_multiagent(vec![("agent_a", 10000, 60)]).await;
    let resp = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .add_header(X_AGENT_ID, hval("unknown"))
        .json(&json!({
            "adapter": "test", "action": "file_write",
            "target": "test.txt", "magnitude": 1,
            "payload": "hello"
        }))
        .await;
    assert_eq!(resp.status_code(), 400);
}

#[tokio::test]
async fn test_valid_agent_id_routes_to_correct_budget() {
    let server =
        safa_daemon::server::test_server_multiagent(vec![("small", 5, 60), ("large", 10000, 60)])
            .await;

    // Exhaust small agent's capacity
    for i in 0..5 {
        let resp = server
            .post("/ama/action")
            .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
            .add_header(X_AGENT_ID, hval("small"))
            .json(&json!({
                "adapter": "test", "action": "file_write",
                "target": format!("test{i}.txt"), "magnitude": 1,
                "payload": "x"
            }))
            .await;
        assert_eq!(resp.status_code(), 200, "request {i} should succeed");
    }

    // Small agent should be exhausted (403)
    let resp = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .add_header(X_AGENT_ID, hval("small"))
        .json(&json!({
            "adapter": "test", "action": "file_write",
            "target": "overflow.txt", "magnitude": 1,
            "payload": "x"
        }))
        .await;
    assert_eq!(resp.status_code(), 403);

    // Large agent unaffected
    let resp = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .add_header(X_AGENT_ID, hval("large"))
        .json(&json!({
            "adapter": "test", "action": "file_write",
            "target": "large.txt", "magnitude": 1,
            "payload": "x"
        }))
        .await;
    assert_eq!(resp.status_code(), 200);
}

#[tokio::test]
async fn test_explicit_agent_id_works_with_single_agent() {
    let server = safa_daemon::server::test_server_multiagent(vec![("myagent", 10000, 60)]).await;
    let resp = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .add_header(X_AGENT_ID, hval("myagent"))
        .json(&json!({
            "adapter": "test", "action": "file_write",
            "target": "test.txt", "magnitude": 1,
            "payload": "hello"
        }))
        .await;
    assert_eq!(resp.status_code(), 200);
}

#[tokio::test]
async fn test_status_shows_per_agent_capacity() {
    let server = safa_daemon::server::test_server_multiagent(vec![
        ("agent_a", 100, 60),
        ("agent_b", 200, 60),
    ])
    .await;

    // Make one request as agent_a
    let _resp = server
        .post("/ama/action")
        .add_header(IDEMPOTENCY_KEY, hval(&Uuid::new_v4().to_string()))
        .add_header(X_AGENT_ID, hval("agent_a"))
        .json(&json!({
            "adapter": "test", "action": "file_write",
            "target": "test.txt", "magnitude": 1,
            "payload": "hello"
        }))
        .await;

    let resp = server.get("/ama/status").await;
    assert_eq!(resp.status_code(), 200);
    let body: serde_json::Value = resp.json();
    assert!(body.get("agents").is_some(), "status should include agents");
    let agents = body["agents"].as_object().unwrap();
    assert!(agents.contains_key("agent_a"));
    assert!(agents.contains_key("agent_b"));
    // agent_a used 1 capacity
    assert_eq!(agents["agent_a"]["capacity_used"], 1);
    assert_eq!(agents["agent_a"]["capacity_max"], 100);
    // agent_b unused
    assert_eq!(agents["agent_b"]["capacity_used"], 0);
    assert_eq!(agents["agent_b"]["capacity_max"], 200);
}
