use crate::errors::AmaError;
use crate::newtypes::{BoundedBytes, WorkspacePath};
use std::fs;
use std::io::Read;
use std::path::Path;

/// Result of a file write operation.
#[derive(Debug)]
pub struct FileWriteResult {
    pub bytes_written: u64,
}

/// Result of a file read operation.
#[derive(Debug)]
pub struct FileReadResult {
    pub content: String,
    pub bytes_returned: u64,
    pub total_bytes: u64,
    pub truncated: bool,
}

/// Atomic file write: write to .ama.<action_id>.tmp then rename.
pub fn file_write(
    path: &WorkspacePath,
    content: &BoundedBytes,
    action_id: &str,
) -> Result<FileWriteResult, AmaError> {
    let target = path.canonical();

    // Verify every path component is not a symlink (Unix)
    verify_no_symlinks(target)?;

    // Verify target is regular file or doesn't exist
    if target.exists() {
        let meta = target
            .symlink_metadata()
            .map_err(|e| AmaError::ServiceUnavailable {
                message: format!("cannot stat target: {}", e),
            })?;
        if !meta.is_file() {
            return Err(AmaError::Validation {
                error_class: "invalid_target".into(),
                message: "target is not a regular file".into(),
            });
        }
    }

    // Create parent directories if needed
    if let Some(parent) = target.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| AmaError::ServiceUnavailable {
                message: format!("cannot create directories: {}", e),
            })?;
            // Set permissions on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).map_err(|e| {
                    AmaError::ServiceUnavailable {
                        message: format!("cannot set dir permissions: {}", e),
                    }
                })?;
            }
        }
    }

    // Write to temp file
    let tmp_name = format!(
        "{}.ama.{}.tmp",
        target.file_name().unwrap_or_default().to_string_lossy(),
        action_id
    );
    let tmp_path = target.with_file_name(&tmp_name);

    let write_result = fs::write(&tmp_path, content.as_str());
    if let Err(e) = write_result {
        // Cleanup temp on failure
        let _ = fs::remove_file(&tmp_path);
        return Err(AmaError::ServiceUnavailable {
            message: format!("write failed: {}", e),
        });
    }

    // Set file permissions (0644) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o644));
    }

    // Atomic rename
    if let Err(e) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(AmaError::ServiceUnavailable {
            message: format!("atomic rename failed: {}", e),
        });
    }

    Ok(FileWriteResult {
        bytes_written: content.len() as u64,
    })
}

/// Bounded file read with truncation.
pub fn file_read(path: &WorkspacePath, max_bytes: usize) -> Result<FileReadResult, AmaError> {
    let target = path.canonical();

    // Verify no symlinks in path
    verify_no_symlinks(target)?;

    // File must exist
    if !target.exists() {
        return Err(AmaError::ServiceUnavailable {
            message: "file does not exist".into(),
        });
    }

    // Must be regular file
    let meta = target
        .symlink_metadata()
        .map_err(|e| AmaError::ServiceUnavailable {
            message: format!("cannot stat: {}", e),
        })?;
    if !meta.is_file() {
        return Err(AmaError::Validation {
            error_class: "invalid_target".into(),
            message: "not a regular file".into(),
        });
    }

    let total_bytes = meta.len();

    // Bounded read
    let mut file = fs::File::open(target).map_err(|e| AmaError::ServiceUnavailable {
        message: format!("cannot open: {}", e),
    })?;
    let read_size = std::cmp::min(total_bytes as usize, max_bytes);
    let mut buf = vec![0u8; read_size];
    file.read_exact(&mut buf)
        .map_err(|e| AmaError::ServiceUnavailable {
            message: format!("read error: {}", e),
        })?;

    // UTF-8 check (P0 is text-only)
    let content = String::from_utf8(buf).map_err(|_| AmaError::Validation {
        error_class: "encoding_error".into(),
        message: "file content is not valid UTF-8 (P0 is text-only)".into(),
    })?;

    let truncated = total_bytes as usize > max_bytes;

    Ok(FileReadResult {
        bytes_returned: content.len() as u64,
        total_bytes,
        content,
        truncated,
    })
}

/// Verify no path component is a symlink. On non-Unix, this is a no-op.
fn verify_no_symlinks(path: &Path) -> Result<(), AmaError> {
    #[cfg(unix)]
    {
        // Check every ancestor starting from the root
        let mut check = std::path::PathBuf::new();
        for component in path.components() {
            check.push(component);
            if check.exists() {
                let meta = check
                    .symlink_metadata()
                    .map_err(|e| AmaError::ServiceUnavailable {
                        message: format!("lstat failed on {}: {}", check.display(), e),
                    })?;
                if meta.file_type().is_symlink() {
                    return Err(AmaError::Validation {
                        error_class: "invalid_target".into(),
                        message: format!("symlink in path: {}", check.display()),
                    });
                }
            }
        }
    }
    let _ = path; // suppress unused warning on Windows
    Ok(())
}

/// Clean up orphan .ama.*.tmp files in a directory (called at startup).
pub fn cleanup_orphan_temps(workspace_root: &Path) -> usize {
    let mut cleaned = 0;
    if let Ok(entries) = walkdir(workspace_root) {
        for path in entries {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.contains(".ama.")
                    && name.ends_with(".tmp")
                    && fs::remove_file(&path).is_ok()
                {
                    cleaned += 1;
                }
            }
        }
    }
    cleaned
}

/// Simple recursive directory walker for cleanup.
fn walkdir(dir: &Path) -> Result<Vec<std::path::PathBuf>, std::io::Error> {
    let mut results = vec![];
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                results.extend(walkdir(&path)?);
            } else {
                results.push(path);
            }
        }
    }
    Ok(results)
}
