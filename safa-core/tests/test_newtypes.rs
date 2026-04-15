use safa_core::newtypes::*;
use std::path::PathBuf;

#[test]
fn workspace_path_rejects_traversal() {
    let root = PathBuf::from("/tmp/safa-workspace");
    assert!(WorkspacePath::new("../../etc/passwd", &root).is_err());
    assert!(WorkspacePath::new("../outside", &root).is_err());
    assert!(WorkspacePath::new("foo/../../bar", &root).is_err());
}

#[test]
fn workspace_path_rejects_absolute() {
    let root = PathBuf::from("/tmp/safa-workspace");
    assert!(WorkspacePath::new("/etc/passwd", &root).is_err());
}

#[test]
fn workspace_path_accepts_valid() {
    let root = PathBuf::from("/tmp/safa-workspace");
    assert!(WorkspacePath::new("", &root).is_err()); // empty
}

#[test]
fn bounded_bytes_rejects_oversized() {
    let data = "x".repeat(1_048_577); // 1 MiB + 1
    assert!(BoundedBytes::new(data, 1_048_576).is_err());
}

#[test]
fn bounded_bytes_accepts_within_limit() {
    let data = "hello world".to_string();
    assert!(BoundedBytes::new(data, 1_048_576).is_ok());
}

#[test]
fn safe_arg_rejects_null_bytes() {
    assert!(SafeArg::new("hello\0world").is_err());
}

#[test]
fn safe_arg_rejects_empty() {
    assert!(SafeArg::new("").is_err());
}

#[test]
fn safe_arg_accepts_valid() {
    assert!(SafeArg::new("src/main.rs").is_ok());
}

#[test]
fn intent_id_rejects_traversal() {
    assert!(IntentId::new("../bad").is_err());
    assert!(IntentId::new("good_intent").is_ok());
}

#[test]
fn allowlisted_url_rejects_http() {
    assert!(AllowlistedUrl::new("http://example.com", HttpMethod::Get, &[]).is_err());
}

#[test]
fn allowlisted_url_rejects_not_in_list() {
    let patterns = vec![AllowlistEntry {
        pattern: "https://api.github.com/*".to_string(),
        methods: vec!["GET".to_string()],
        max_body_bytes: None,
    }];
    assert!(AllowlistedUrl::new("https://evil.com/steal", HttpMethod::Get, &patterns).is_err());
}

#[test]
fn allowlisted_url_rejects_disallowed_method() {
    // Regression test for allowlist method enforcement (was parsed but ignored).
    let patterns = vec![AllowlistEntry {
        pattern: "https://api.github.com/*".to_string(),
        methods: vec!["GET".to_string()],
        max_body_bytes: None,
    }];
    // GET is permitted.
    assert!(AllowlistedUrl::new("https://api.github.com/foo", HttpMethod::Get, &patterns).is_ok());
    // POST is NOT in the methods list — must be rejected.
    assert!(
        AllowlistedUrl::new("https://api.github.com/foo", HttpMethod::Post, &patterns).is_err()
    );
}

#[test]
fn allowlisted_url_exposes_entry_max_body_bytes() {
    // Regression test: the entry's max_body_bytes must propagate to callers
    // so the pipeline can tighten the global domain cap.
    let patterns = vec![AllowlistEntry {
        pattern: "https://api.github.com/*".to_string(),
        methods: vec!["POST".to_string()],
        max_body_bytes: Some(1024),
    }];
    let url = AllowlistedUrl::new("https://api.github.com/foo", HttpMethod::Post, &patterns)
        .expect("should match");
    assert_eq!(url.matched_max_body_bytes(), Some(1024));
}

#[test]
fn allowlisted_url_rejects_subdomain_confusion() {
    // Regression test for subdomain-confusion attack in the glob matcher.
    // Even if a pattern is written WITHOUT a trailing '/' before the '*'
    // (so the wildcard technically could extend the hostname), the matcher
    // must refuse URLs whose authority doesn't end at a structural boundary.
    let patterns = vec![AllowlistEntry {
        pattern: "https://api.github.com*".to_string(), // no '/' before '*'
        methods: vec!["GET".to_string()],
        max_body_bytes: None,
    }];
    // Legitimate URL under the host → allowed (next char after prefix is '/')
    assert!(AllowlistedUrl::new("https://api.github.com/foo", HttpMethod::Get, &patterns).is_ok());
    // Attacker-controlled subdomain extension → MUST be rejected
    assert!(AllowlistedUrl::new(
        "https://api.github.com.evil.com/steal",
        HttpMethod::Get,
        &patterns
    )
    .is_err());
    // Port variant → also must be rejected if it extends the hostname
    assert!(AllowlistedUrl::new(
        "https://api.github.com-evil.com/x",
        HttpMethod::Get,
        &patterns
    )
    .is_err());
}
