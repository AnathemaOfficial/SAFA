use safa_core::pipeline::validate_field_exclusivity;
use safa_core::schema::ActionRequest;

fn make_request(
    action: &str,
    payload: Option<String>,
    args: Option<Vec<String>>,
    method: Option<String>,
) -> ActionRequest {
    ActionRequest {
        adapter: "test".into(),
        action: action.into(),
        target: "test.txt".into(),
        magnitude: 1,
        dry_run: false,
        method,
        payload,
        args,
    }
}

#[test]
fn file_write_requires_payload() {
    let req = make_request("file_write", None, None, None);
    assert!(validate_field_exclusivity(&req).is_err());
}

#[test]
fn file_write_rejects_args() {
    let req = make_request(
        "file_write",
        Some("data".into()),
        Some(vec!["x".into()]),
        None,
    );
    assert!(validate_field_exclusivity(&req).is_err());
}

#[test]
fn file_write_valid() {
    let req = make_request("file_write", Some("data".into()), None, None);
    assert!(validate_field_exclusivity(&req).is_ok());
}

#[test]
fn file_read_rejects_payload() {
    let req = make_request("file_read", Some("data".into()), None, None);
    assert!(validate_field_exclusivity(&req).is_err());
}

#[test]
fn file_read_rejects_args() {
    let req = make_request("file_read", None, Some(vec!["x".into()]), None);
    assert!(validate_field_exclusivity(&req).is_err());
}

#[test]
fn shell_exec_requires_args() {
    let req = make_request("shell_exec", None, None, None);
    assert!(validate_field_exclusivity(&req).is_err());
}

#[test]
fn shell_exec_rejects_payload() {
    let req = make_request(
        "shell_exec",
        Some("data".into()),
        Some(vec!["x".into()]),
        None,
    );
    assert!(validate_field_exclusivity(&req).is_err());
}

#[test]
fn http_request_rejects_args() {
    let req = make_request(
        "http_request",
        None,
        Some(vec!["x".into()]),
        Some("GET".into()),
    );
    assert!(validate_field_exclusivity(&req).is_err());
}

#[test]
fn http_request_requires_method() {
    let req = make_request("http_request", None, None, None);
    assert!(validate_field_exclusivity(&req).is_err());
}

#[test]
fn http_request_valid_get() {
    let req = make_request("http_request", None, None, Some("GET".into()));
    assert!(validate_field_exclusivity(&req).is_ok());
}
