use safa_core::config::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn loads_valid_config() {
    let dir = TempDir::new().unwrap();
    let ws = dir.path().join("workspace");
    fs::create_dir(&ws).unwrap();

    write_test_configs(dir.path(), ws.to_str().unwrap());

    let result = AmaConfig::load(dir.path());
    assert!(result.is_ok());
}

#[test]
fn rejects_missing_config_file() {
    let dir = TempDir::new().unwrap();
    let result = AmaConfig::load(dir.path());
    assert!(result.is_err());
}

#[test]
fn rejects_relative_workspace_root() {
    let dir = TempDir::new().unwrap();
    write_test_configs(dir.path(), "./relative");
    let result = AmaConfig::load(dir.path());
    assert!(result.is_err());
}

#[test]
fn computes_sha256_hashes() {
    let dir = TempDir::new().unwrap();
    let ws = dir.path().join("workspace");
    fs::create_dir(&ws).unwrap();
    write_test_configs(dir.path(), ws.to_str().unwrap());

    let config = AmaConfig::load(dir.path()).unwrap();
    assert!(!config.boot_hashes.config_hash.is_empty());
    assert!(!config.boot_hashes.domains_hash.is_empty());
}

// ── Task 5: AgentConfig parsing ──────────────────────────────

#[test]
fn test_agent_config_loads_from_toml() {
    let toml_str = r#"
[agent]
agent_id = "openclaw"
max_capacity = 5000
rate_limit_per_window = 30
rate_limit_window_secs = 60

[agent.domains.fs_write_workspace]
enabled = true
max_magnitude_per_action = 100

[agent.domains.fs_read_workspace]
enabled = true
max_magnitude_per_action = 500
"#;
    let agent_config = safa_core::config::AgentConfig::from_toml_str(toml_str).unwrap();
    assert_eq!(agent_config.agent_id, "openclaw");
    assert_eq!(agent_config.max_capacity, 5000);
    assert_eq!(agent_config.rate_limit_per_window, 30);
    assert_eq!(agent_config.rate_limit_window_secs, 60);
    assert_eq!(agent_config.domain_policies.len(), 2);
    assert!(agent_config
        .domain_policies
        .contains_key("fs.write.workspace"));
}

#[test]
fn test_agent_config_defaults_rate_limits() {
    let toml_str = r#"
[agent]
agent_id = "minimal"
max_capacity = 1000

[agent.domains.fs_read_workspace]
enabled = true
max_magnitude_per_action = 100
"#;
    let agent_config = AgentConfig::from_toml_str(toml_str).unwrap();
    assert_eq!(agent_config.rate_limit_per_window, 60);
    assert_eq!(agent_config.rate_limit_window_secs, 60);
}

#[test]
fn test_agent_config_rejects_empty_agent_id() {
    let toml_str = r#"
[agent]
agent_id = ""
max_capacity = 1000
"#;
    assert!(AgentConfig::from_toml_str(toml_str).is_err());
}

#[test]
fn test_agent_config_rejects_invalid_agent_id() {
    let toml_str = r#"
[agent]
agent_id = "bad agent!"
max_capacity = 1000
"#;
    assert!(AgentConfig::from_toml_str(toml_str).is_err());
}

#[test]
fn test_agent_config_rejects_zero_capacity() {
    let toml_str = r#"
[agent]
agent_id = "test"
max_capacity = 0
"#;
    assert!(AgentConfig::from_toml_str(toml_str).is_err());
}

#[test]
fn test_agent_config_rejects_magnitude_exceeding_capacity() {
    let toml_str = r#"
[agent]
agent_id = "test"
max_capacity = 100

[agent.domains.fs_write_workspace]
enabled = true
max_magnitude_per_action = 200
"#;
    assert!(AgentConfig::from_toml_str(toml_str).is_err());
}

// ── Task 6: Load agent configs from directory ──────────────

#[test]
fn test_load_agent_configs_from_directory() {
    let dir = TempDir::new().unwrap();
    let agents_dir = dir.path().join("agents");
    fs::create_dir(&agents_dir).unwrap();

    fs::write(
        agents_dir.join("agent_a.toml"),
        r#"
[agent]
agent_id = "agent-a"
max_capacity = 5000

[agent.domains.fs_write_workspace]
enabled = true
max_magnitude_per_action = 100
"#,
    )
    .unwrap();

    fs::write(
        agents_dir.join("agent_b.toml"),
        r#"
[agent]
agent_id = "agent-b"
max_capacity = 3000

[agent.domains.fs_read_workspace]
enabled = true
max_magnitude_per_action = 200
"#,
    )
    .unwrap();

    let agents = safa_core::config::load_agent_configs(&agents_dir).unwrap();
    assert_eq!(agents.len(), 2);
    assert!(agents.contains_key("agent-a"));
    assert!(agents.contains_key("agent-b"));
}

#[test]
fn test_load_agent_configs_rejects_duplicate_agent_id() {
    let dir = TempDir::new().unwrap();
    let agents_dir = dir.path().join("agents");
    fs::create_dir(&agents_dir).unwrap();

    fs::write(
        agents_dir.join("one.toml"),
        r#"
[agent]
agent_id = "same-id"
max_capacity = 5000
"#,
    )
    .unwrap();

    fs::write(
        agents_dir.join("two.toml"),
        r#"
[agent]
agent_id = "same-id"
max_capacity = 3000
"#,
    )
    .unwrap();

    assert!(safa_core::config::load_agent_configs(&agents_dir).is_err());
}

#[test]
fn test_load_agent_configs_rejects_empty_directory() {
    let dir = TempDir::new().unwrap();
    let agents_dir = dir.path().join("agents");
    fs::create_dir(&agents_dir).unwrap();

    assert!(safa_core::config::load_agent_configs(&agents_dir).is_err());
}

// ── Task 7: Backward compat — existing tests still work with no agents/ dir ──

#[test]
fn backward_compat_synthesizes_default_agent() {
    let dir = TempDir::new().unwrap();
    let ws = dir.path().join("workspace");
    fs::create_dir(&ws).unwrap();

    write_test_configs(dir.path(), ws.to_str().unwrap());

    let config = AmaConfig::load(dir.path()).unwrap();
    // Should have synthesized a "default" agent from [slime] section
    assert_eq!(config.agents.len(), 1);
    assert!(config.agents.contains_key("default"));
    assert_eq!(config.agents["default"].max_capacity, 10000);
    assert_eq!(config.agents["default"].domain_policies.len(), 4);
    assert_eq!(config.default_agent_id, Some("default".to_string()));
}

#[test]
fn loads_agent_configs_from_agents_dir() {
    let dir = TempDir::new().unwrap();
    let ws = dir.path().join("workspace");
    fs::create_dir(&ws).unwrap();
    let agents_dir = dir.path().join("agents");
    fs::create_dir(&agents_dir).unwrap();

    // Write config.toml WITHOUT slime.max_capacity and domains
    let workspace_root_escaped = ws.to_str().unwrap().replace('\\', "\\\\");
    fs::write(
        dir.path().join("config.toml"),
        format!(
            r#"
[safa]
workspace_root = "{workspace_root_escaped}"
bind_host = "127.0.0.1"
bind_port = 8787

[slime]
mode = "embedded"
"#
        ),
    )
    .unwrap();

    // Write agent config
    fs::write(
        agents_dir.join("openclaw.toml"),
        r#"
[agent]
agent_id = "openclaw"
max_capacity = 8000
rate_limit_per_window = 30
rate_limit_window_secs = 60

[agent.domains.fs_write_workspace]
enabled = true
max_magnitude_per_action = 100

[agent.domains.fs_read_workspace]
enabled = true
max_magnitude_per_action = 500

[agent.domains.proc_exec_bounded]
enabled = true
max_magnitude_per_action = 50

[agent.domains.net_out_http]
enabled = true
max_magnitude_per_action = 200
"#,
    )
    .unwrap();

    // Write other config files
    fs::write(
        dir.path().join("domains.toml"),
        r#"
[meta]
schema_version = "safa-domains-v1"

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
        dir.path().join("intents.toml"),
        r#"
[meta]
schema_version = "safa-intents-v1"
"#,
    )
    .unwrap();

    fs::write(
        dir.path().join("allowlist.toml"),
        r#"
[meta]
schema_version = "safa-allowlist-v1"
"#,
    )
    .unwrap();

    let config = AmaConfig::load(dir.path()).unwrap();
    assert_eq!(config.agents.len(), 1);
    assert!(config.agents.contains_key("openclaw"));
    assert_eq!(config.agents["openclaw"].max_capacity, 8000);
    assert_eq!(config.default_agent_id, Some("openclaw".to_string()));
    // boot_hashes should include agents_hash
    assert!(!config.boot_hashes.agents_hash.is_empty());
}

/// Helper: write minimal valid config files into a directory.
fn write_test_configs(dir: &std::path::Path, workspace_root: &str) {
    // On Windows, backslashes in TOML strings must be escaped.
    let workspace_root_escaped = workspace_root.replace('\\', "\\\\");
    fs::write(
        dir.join("config.toml"),
        format!(
            r#"
[safa]
workspace_root = "{workspace_root_escaped}"
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
