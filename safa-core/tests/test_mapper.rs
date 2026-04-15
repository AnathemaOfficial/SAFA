use safa_core::config::*;
use safa_core::mapper::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn maps_file_write_to_domain() {
    let config = test_config();
    let result = map_action("file_write", 10, &config);
    assert!(result.is_ok());
    let mapping = result.unwrap();
    assert_eq!(mapping.domain_id, "fs.write.workspace");
    assert_eq!(mapping.magnitude, 10);
}

#[test]
fn rejects_unknown_action() {
    let config = test_config();
    let result = map_action("unknown_action", 1, &config);
    assert!(result.is_err());
}

#[test]
fn maps_shell_exec_to_domain() {
    let config = test_config();
    let result = map_action("shell_exec", 5, &config);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().domain_id, "proc.exec.bounded");
}

fn test_config() -> AmaConfig {
    let dir = TempDir::new().unwrap();
    let ws = dir.path().join("workspace");
    fs::create_dir(&ws).unwrap();
    write_test_configs(dir.path(), &ws.to_str().unwrap().replace('\\', "\\\\"));
    // Keep dir alive by leaking it (test only)
    let config = AmaConfig::load(dir.path()).unwrap();
    std::mem::forget(dir);
    config
}

fn write_test_configs(dir: &std::path::Path, workspace_root: &str) {
    fs::write(
        dir.join("config.toml"),
        format!(
            r#"
[safa]
workspace_root = "{workspace_root}"
bind_host = "127.0.0.1"
bind_port = 8787

[slime]
mode = "embedded"
max_capacity = 10000

[slime.domains.fs_write_workspace]
enabled = true
max_magnitude_per_action = 100

[slime.domains.fs_read_workspace]
enabled = true
max_magnitude_per_action = 500

[slime.domains.proc_exec_bounded]
enabled = true
max_magnitude_per_action = 50

[slime.domains.net_out_http]
enabled = true
max_magnitude_per_action = 200
"#
        ),
    )
    .unwrap();

    fs::write(
        dir.join("domains.toml"),
        r#"
[meta]
schema_version = "safa-domains-v1"
max_magnitude_claim = 1000

[domains.file_write]
domain_id = "fs.write.workspace"
max_payload_bytes = 1048576
validator = "relative_workspace_path"

[domains.file_read]
domain_id = "fs.read.workspace"
validator = "relative_workspace_path"

[domains.shell_exec]
domain_id = "proc.exec.bounded"
requires_intent = true

[domains.http_request]
domain_id = "net.out.http"
max_payload_bytes = 262144
validator = "allowlisted_url"
"#,
    )
    .unwrap();

    fs::write(
        dir.join("intents.toml"),
        r#"
[meta]
schema_version = "safa-intents-v1"
"#,
    )
    .unwrap();

    fs::write(
        dir.join("allowlist.toml"),
        r#"
[meta]
schema_version = "safa-allowlist-v1"
"#,
    )
    .unwrap();
}
