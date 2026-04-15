// SAFA P3 — Bypass Attempt Tests
//
// Adversarial tests that verify SAFA cannot be circumvented.
// Every test represents a potential attack vector.

use safa_core::config::{AgentConfig, DomainPolicy};
use safa_core::identity::{compute_signature, verify_identity};
use safa_core::manifest::PublicManifest;
use safa_core::newtypes::WorkspacePath;
use std::collections::HashMap;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ── Identity Bypass Attempts ────────────────────────────────

#[test]
fn bypass_identity_agent_spoofing() {
    // Agent "attacker" tries to sign as "victim" using attacker's secret
    let victim_secret = "victim-secret-very-long-at-least-32chars!";
    let attacker_secret = "attacker-secret-long-enough-32chars!!";
    let body = b"{\"action\":\"file_write\"}";

    let ts = now().to_string();
    let attacker_sig = compute_signature(attacker_secret, "victim", &ts, body);

    let result = verify_identity(
        victim_secret,
        "victim",
        Some(&ts),
        Some(&attacker_sig),
        body,
        now(),
    );
    assert!(result.is_err(), "spoofed signature must be rejected");
}

#[test]
fn bypass_identity_replay_expired() {
    // Replay a valid signature after the timestamp window expires
    let secret = "a-valid-secret-that-is-at-least-32-chars";
    let body = b"{\"action\":\"file_read\"}";

    let old_ts = (now() - 600).to_string(); // 10 minutes ago
    let sig = compute_signature(secret, "agent", &old_ts, body);

    let result = verify_identity(secret, "agent", Some(&old_ts), Some(&sig), body, now());
    assert!(
        result.is_err(),
        "replayed expired signature must be rejected"
    );
}

#[test]
fn bypass_identity_body_tampering() {
    // Sign one body, send a different one
    let secret = "a-valid-secret-that-is-at-least-32-chars";
    let original_body = b"{\"action\":\"file_read\",\"target\":\"safe.txt\"}";
    let tampered_body = b"{\"action\":\"shell_exec\",\"target\":\"rm_all\"}";

    let ts = now().to_string();
    let sig = compute_signature(secret, "agent", &ts, original_body);

    let result = verify_identity(secret, "agent", Some(&ts), Some(&sig), tampered_body, now());
    assert!(result.is_err(), "tampered body must be detected");
}

// ── Workspace Bypass Attempts ───────────────────────────────

#[test]
fn bypass_workspace_double_slash() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("agent")).unwrap();

    let result = WorkspacePath::new_with_agent("foo//bar.txt", dir.path(), Some("agent"));
    assert!(result.is_err(), "double slash path must be rejected");
}

#[test]
fn bypass_workspace_null_byte() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("agent")).unwrap();

    // Null bytes in paths can truncate on C-level APIs
    let result = WorkspacePath::new_with_agent("data\0.txt", dir.path(), Some("agent"));
    // std::path handles null bytes — should either error or be safe
    // The key invariant: path must stay in agent workspace
    if let Ok(path) = result {
        let canon = path.canonical().to_string_lossy();
        assert!(canon.contains("agent"), "path must stay in agent workspace");
    }
}

#[test]
fn bypass_workspace_dot_dot_encoded() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("agent")).unwrap();

    // Direct .. is caught, but what about tricky paths?
    let result =
        WorkspacePath::new_with_agent("subdir/../../../etc/passwd", dir.path(), Some("agent"));
    assert!(result.is_err(), "traversal via .. must be rejected");
}

#[test]
fn bypass_workspace_absolute_path() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("agent")).unwrap();

    let result = WorkspacePath::new_with_agent("/etc/passwd", dir.path(), Some("agent"));
    assert!(result.is_err(), "absolute path must be rejected");
}

#[test]
fn bypass_workspace_windows_drive() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("agent")).unwrap();

    let result = WorkspacePath::new_with_agent("C:\\Windows\\system32", dir.path(), Some("agent"));
    assert!(result.is_err(), "Windows drive path must be rejected");
}

// ── Manifest Bypass Attempts ────────────────────────────────

#[test]
fn bypass_manifest_secret_not_leaked() {
    let config = AgentConfig {
        agent_id: "secure-agent".into(),
        max_capacity: 50_000,
        rate_limit_per_window: 30,
        rate_limit_window_secs: 60,
        domain_policies: HashMap::new(),
        secret: Some("super-secret-key-that-must-never-leak!!".into()),
    };

    let manifest = PublicManifest::from_agent_config(&config, "test-bundle");
    let json = serde_json::to_string(&manifest).unwrap();

    assert!(
        !json.contains("super-secret"),
        "secret must never appear in manifest JSON"
    );
    assert!(!json.contains("key-that"), "secret fragments must not leak");
    assert!(
        json.contains("\"identity_bound\":true"),
        "identity_bound flag must be present"
    );
}

#[test]
fn bypass_manifest_hash_tamper_detection() {
    let mut policies = HashMap::new();
    policies.insert(
        "fs.write.workspace".into(),
        DomainPolicy {
            enabled: true,
            max_magnitude_per_action: 1000,
        },
    );

    let config_original = AgentConfig {
        agent_id: "agent".into(),
        max_capacity: 100_000,
        rate_limit_per_window: 60,
        rate_limit_window_secs: 60,
        domain_policies: policies.clone(),
        secret: None,
    };

    // Tamper: change magnitude limit
    let mut policies_tampered = policies;
    policies_tampered
        .get_mut("fs.write.workspace")
        .unwrap()
        .max_magnitude_per_action = 999_999;

    let config_tampered = AgentConfig {
        agent_id: "agent".into(),
        max_capacity: 100_000,
        rate_limit_per_window: 60,
        rate_limit_window_secs: 60,
        domain_policies: policies_tampered,
        secret: None,
    };

    let hash_original =
        PublicManifest::from_agent_config(&config_original, "test-bundle").manifest_hash;
    let hash_tampered =
        PublicManifest::from_agent_config(&config_tampered, "test-bundle").manifest_hash;

    assert_ne!(
        hash_original, hash_tampered,
        "tampered config must produce different hash"
    );
}

#[test]
fn bypass_manifest_hash_tamper_detection_policy_bundle() {
    // Regression test for GPT audit finding #2: manifest_hash must change
    // when the policy bundle (domains/intents/allowlist) changes, even if
    // the per-agent config stays identical. Without this, silent policy
    // drift would leave all manifests reporting the same hash.
    let mut policies = HashMap::new();
    policies.insert(
        "fs.write.workspace".into(),
        DomainPolicy {
            enabled: true,
            max_magnitude_per_action: 1000,
        },
    );

    let config = AgentConfig {
        agent_id: "agent".into(),
        max_capacity: 100_000,
        rate_limit_per_window: 60,
        rate_limit_window_secs: 60,
        domain_policies: policies,
        secret: None,
    };

    let hash_bundle_a = PublicManifest::from_agent_config(&config, "bundle-hash-A").manifest_hash;
    let hash_bundle_b = PublicManifest::from_agent_config(&config, "bundle-hash-B").manifest_hash;

    assert_ne!(
        hash_bundle_a, hash_bundle_b,
        "different bundle hash must produce different manifest hash"
    );
}
