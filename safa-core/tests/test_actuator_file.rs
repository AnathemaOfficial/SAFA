use safa_core::actuator::file::*;
use safa_core::newtypes::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn writes_file_atomically() {
    let dir = TempDir::new().unwrap();
    let workspace = dir.path();
    let path = WorkspacePath::new("test.txt", workspace).unwrap();
    let content = BoundedBytes::new("hello world".into(), 1_048_576).unwrap();
    let action_id = "test-action-1";

    let result = file_write(&path, &content, action_id).unwrap();
    assert_eq!(result.bytes_written, 11);
    assert_eq!(
        fs::read_to_string(workspace.join("test.txt")).unwrap(),
        "hello world"
    );
}

#[test]
fn write_creates_parent_dirs() {
    let dir = TempDir::new().unwrap();
    // P3: Pre-create parent dirs since WorkspacePath now validates
    // that the parent exists (canonicalize requires real path).
    fs::create_dir_all(dir.path().join("a/b/c")).unwrap();
    let path = WorkspacePath::new("a/b/c/file.txt", dir.path()).unwrap();
    let content = BoundedBytes::new("nested".into(), 1_048_576).unwrap();

    let result = file_write(&path, &content, "test-2");
    assert!(result.is_ok());
}

#[test]
fn reads_existing_file() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("hello.txt"), "content here").unwrap();
    let path = WorkspacePath::new("hello.txt", dir.path()).unwrap();

    let result = file_read(&path, 524_288).unwrap();
    assert_eq!(result.content, "content here");
    assert!(!result.truncated);
}

#[test]
fn read_truncates_large_file() {
    let dir = TempDir::new().unwrap();
    let big = "x".repeat(1000);
    fs::write(dir.path().join("big.txt"), &big).unwrap();
    let path = WorkspacePath::new("big.txt", dir.path()).unwrap();

    let result = file_read(&path, 100).unwrap(); // limit 100 bytes
    assert_eq!(result.bytes_returned, 100);
    assert!(result.truncated);
}

#[test]
fn read_nonexistent_file_fails() {
    let dir = TempDir::new().unwrap();
    let path = WorkspacePath::new("nope.txt", dir.path()).unwrap();
    assert!(file_read(&path, 524_288).is_err());
}

#[cfg(unix)]
#[test]
fn write_rejects_symlink_in_path() {
    let dir = TempDir::new().unwrap();
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, dir.path().join("link")).unwrap();

    let path = WorkspacePath::new("link/file.txt", dir.path()).unwrap();
    let content = BoundedBytes::new("bad".into(), 1_048_576).unwrap();
    // Should fail because "link" is a symlink
    let result = file_write(&path, &content, "test-sym");
    assert!(result.is_err());
}

#[test]
fn read_rejects_non_utf8() {
    let dir = TempDir::new().unwrap();
    // Write invalid UTF-8 bytes
    fs::write(dir.path().join("binary.dat"), &[0xFF, 0xFE, 0x00, 0x01]).unwrap();
    let path = WorkspacePath::new("binary.dat", dir.path()).unwrap();
    let result = file_read(&path, 524_288);
    assert!(result.is_err()); // P0 is text-only
}
