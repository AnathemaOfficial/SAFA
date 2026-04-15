use safa_core::schema::*;

#[test]
fn parses_valid_file_write() {
    let json = r#"{
        "adapter": "generic",
        "action": "file_write",
        "target": "test.txt",
        "magnitude": 1,
        "payload": "hello"
    }"#;
    let req: ActionRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.action, "file_write");
    assert_eq!(req.magnitude, 1);
}

#[test]
fn rejects_missing_action() {
    let json = r#"{"adapter": "x", "target": "t", "magnitude": 1}"#;
    let result: Result<ActionRequest, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn rejects_magnitude_zero() {
    let json = r#"{
        "adapter": "x", "action": "file_write",
        "target": "t", "magnitude": 0, "payload": "x"
    }"#;
    let req: ActionRequest = serde_json::from_str(json).unwrap();
    assert!(validate_magnitude(req.magnitude).is_err());
}

#[test]
fn rejects_magnitude_over_1000() {
    let json = r#"{
        "adapter": "x", "action": "file_write",
        "target": "t", "magnitude": 1001, "payload": "x"
    }"#;
    let req: ActionRequest = serde_json::from_str(json).unwrap();
    assert!(validate_magnitude(req.magnitude).is_err());
}

#[test]
fn parses_shell_exec_with_args() {
    let json = r#"{
        "adapter": "generic",
        "action": "shell_exec",
        "target": "list_dir",
        "magnitude": 1,
        "args": ["src"]
    }"#;
    let req: ActionRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.args, Some(vec!["src".to_string()]));
}

#[test]
fn parses_http_request_with_method() {
    let json = r#"{
        "adapter": "generic",
        "action": "http_request",
        "method": "GET",
        "target": "https://api.github.com/repos",
        "magnitude": 1
    }"#;
    let req: ActionRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.method, Some("GET".to_string()));
}

#[test]
fn rejects_adapter_with_control_chars() {
    let req = ActionRequest {
        adapter: "bad\nadapter".into(),
        action: "file_write".into(),
        target: "x".into(),
        magnitude: 1,
        dry_run: false,
        method: None,
        payload: Some("hello".into()),
        args: None,
    };
    assert!(validate_adapter(&req.adapter).is_err());
}

#[test]
fn rejects_adapter_over_64_chars() {
    let req = ActionRequest {
        adapter: "a".repeat(65),
        action: "file_write".into(),
        target: "x".into(),
        magnitude: 1,
        dry_run: false,
        method: None,
        payload: Some("hello".into()),
        args: None,
    };
    assert!(validate_adapter(&req.adapter).is_err());
}

#[test]
fn accepts_identifier_style_adapter() {
    assert!(validate_adapter("slapy_mobile-preview_1").is_ok());
}
