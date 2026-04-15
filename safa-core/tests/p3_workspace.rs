// SAFA P3 — Per-Agent Workspace Isolation Tests
//
// Validates that:
// - Agents are confined to their own workspace subdirectory
// - Symlink attacks are detected and rejected
// - Cross-agent path access is impossible

use safa_core::newtypes::WorkspacePath;
use std::fs;

fn setup_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    // Create per-agent workspace dirs
    fs::create_dir_all(dir.path().join("agent-alpha")).unwrap();
    fs::create_dir_all(dir.path().join("agent-beta")).unwrap();
    // Create a file in agent-alpha's workspace
    fs::write(dir.path().join("agent-alpha/data.txt"), "alpha data").unwrap();
    // Create a file in agent-beta's workspace
    fs::write(dir.path().join("agent-beta/data.txt"), "beta data").unwrap();
    // Create a file OUTSIDE any agent workspace (at root level)
    fs::write(dir.path().join("secret.txt"), "top secret").unwrap();
    dir
}

#[test]
fn agent_can_access_own_workspace() {
    let ws = setup_workspace();
    let result = WorkspacePath::new_with_agent("data.txt", ws.path(), Some("agent-alpha"));
    assert!(result.is_ok());
}

#[test]
fn agent_cannot_access_other_agent_workspace_via_traversal() {
    let ws = setup_workspace();
    // agent-alpha tries to access agent-beta's files via ../agent-beta/
    let result =
        WorkspacePath::new_with_agent("../agent-beta/data.txt", ws.path(), Some("agent-alpha"));
    assert!(result.is_err());
}

#[test]
fn agent_cannot_access_root_workspace_via_traversal() {
    let ws = setup_workspace();
    // agent-alpha tries to escape to the root workspace
    let result = WorkspacePath::new_with_agent("../secret.txt", ws.path(), Some("agent-alpha"));
    assert!(result.is_err());
}

#[test]
fn agent_workspace_new_file_confined() {
    let ws = setup_workspace();
    // Creating a new file should stay in agent's workspace
    let result = WorkspacePath::new_with_agent("new_file.txt", ws.path(), Some("agent-alpha"));
    assert!(result.is_ok());
    let path = result.unwrap();
    // Canonical path must contain the agent's workspace segment
    let canon_str = path.canonical().to_string_lossy().to_string();
    assert!(
        canon_str.contains("agent-alpha"),
        "canonical path '{}' must contain agent workspace",
        canon_str,
    );
}

#[test]
fn no_agent_id_uses_global_workspace() {
    let ws = setup_workspace();
    fs::write(ws.path().join("global.txt"), "global").unwrap();
    let result = WorkspacePath::new("global.txt", ws.path());
    assert!(result.is_ok());
}

// Symlink tests — Unix only
#[cfg(unix)]
mod symlink_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn symlink_escape_detected() {
        let ws = setup_workspace();
        // Create a symlink inside agent-alpha's workspace pointing outside
        let escape_link = ws.path().join("agent-alpha/escape");
        symlink(ws.path().join("agent-beta"), &escape_link).unwrap();

        // agent-alpha tries to follow the symlink to agent-beta
        let result =
            WorkspacePath::new_with_agent("escape/data.txt", ws.path(), Some("agent-alpha"));
        assert!(result.is_err(), "symlink escape should be detected");
    }

    #[test]
    fn symlink_to_parent_detected() {
        let ws = setup_workspace();
        // Create a symlink inside agent-alpha pointing to root workspace
        let parent_link = ws.path().join("agent-alpha/parent");
        symlink(ws.path(), &parent_link).unwrap();

        let result =
            WorkspacePath::new_with_agent("parent/secret.txt", ws.path(), Some("agent-alpha"));
        assert!(result.is_err(), "symlink to parent should be detected");
    }

    #[test]
    fn symlink_within_agent_workspace_allowed() {
        let ws = setup_workspace();
        // Create a subdir and symlink within the same agent workspace
        fs::create_dir_all(ws.path().join("agent-alpha/subdir")).unwrap();
        fs::write(ws.path().join("agent-alpha/subdir/real.txt"), "real").unwrap();
        let internal_link = ws.path().join("agent-alpha/link.txt");
        symlink(
            ws.path().join("agent-alpha/subdir/real.txt"),
            &internal_link,
        )
        .unwrap();

        // Following a symlink within the same workspace is fine
        let result = WorkspacePath::new_with_agent("link.txt", ws.path(), Some("agent-alpha"));
        assert!(result.is_ok(), "internal symlink should be allowed");
    }
}
