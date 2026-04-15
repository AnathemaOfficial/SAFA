use crate::errors::AmaError;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

/// Result of a shell exec operation.
#[derive(Debug)]
pub struct ShellExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub truncated: bool,
}

struct CapturedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

/// Execute a binary with arguments in a new process group.
///
/// - Uses execv (via Command::new), never sh -c
/// - Fresh minimal environment
/// - Process group isolation (setpgid)
/// - Kill sequence: SIGTERM -> 2s -> SIGKILL to PGID
/// - Bounded output capture
pub async fn shell_exec(
    binary: &str,
    args: &[&str],
    working_dir: &str,
    action_id: &str,
    timeout: Duration,
    max_output_bytes: usize,
) -> Result<ShellExecResult, AmaError> {
    use std::os::unix::process::CommandExt;

    let mut cmd = Command::new(binary);
    cmd.args(args)
        .current_dir(working_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Fresh minimal environment — no inherited variables
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", working_dir)
        .env("LANG", "en_US.UTF-8")
        .env("SAFA_ACTION_ID", action_id);

    // SAFETY: pre_exec runs after fork, before exec in child process.
    // setpgid(0,0) puts the child in its own process group so the daemon
    // can kill the whole tree on timeout. We propagate the setpgid failure
    // — previously the return value was discarded and the child would
    // continue in the parent's process group, silently breaking
    // kill-containment (Qwen audit finding HIGH-03).
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn().map_err(|e| AmaError::ServiceUnavailable {
        message: format!("failed to spawn process: {}", e),
    })?;

    // Copilot audit finding H-03: treat a missing child PID as fatal.
    // Previously `child.id().unwrap_or(0) as i32` meant that if the OS ever
    // failed to report a PID (post-wait on some platforms, transient error),
    // the subsequent timeout `kill(-pid, SIG...)` became `kill(-0, ...)`
    // which signals the ENTIRE process group of the caller — i.e. the
    // SAFA daemon itself and any co-grouped ancestors. We now fail the
    // action cleanly rather than self-kill.
    let pid: i32 = match child.id() {
        Some(raw) => raw as i32,
        None => {
            // Best-effort cleanup: try to kill the child by handle
            // (non-group) so it doesn't dangle.
            let _ = child.kill().await;
            return Err(AmaError::ServiceUnavailable {
                message: "could not obtain child PID; aborting action to preserve daemon".into(),
            });
        }
    };

    // Take ownership of stdout/stderr handles
    let mut stdout_handle = child.stdout.take().unwrap();
    let mut stderr_handle = child.stderr.take().unwrap();

    // Bounded output capture with timeout
    let result = tokio::time::timeout(timeout, async {
        let (stdout_capture, stderr_capture, status) = tokio::join!(
            drain_bounded_output(&mut stdout_handle, max_output_bytes),
            drain_bounded_output(&mut stderr_handle, max_output_bytes),
            child.wait(),
        );

        let stdout_capture = stdout_capture.map_err(|e| AmaError::ServiceUnavailable {
            message: format!("stdout read failed: {}", e),
        })?;
        let stderr_capture = stderr_capture.map_err(|e| AmaError::ServiceUnavailable {
            message: format!("stderr read failed: {}", e),
        })?;
        let status = status.map_err(|e| AmaError::ServiceUnavailable {
            message: format!("wait failed: {}", e),
        })?;

        // UTF-8 validation (P0 is text-only)
        let stdout =
            String::from_utf8(stdout_capture.bytes).map_err(|_| AmaError::ServiceUnavailable {
                message: "stdout contains non-UTF-8 data".into(),
            })?;
        let stderr =
            String::from_utf8(stderr_capture.bytes).map_err(|_| AmaError::ServiceUnavailable {
                message: "stderr contains non-UTF-8 data".into(),
            })?;

        Ok(ShellExecResult {
            stdout,
            stderr,
            exit_code: status.code().unwrap_or(-1),
            truncated: stdout_capture.truncated || stderr_capture.truncated,
        })
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => {
            // Timeout — execute kill sequence
            // SIGTERM to entire process group
            if pid > 0 {
                unsafe {
                    libc::kill(-pid, libc::SIGTERM);
                }
            }
            // Wait 2 seconds then SIGKILL
            tokio::time::sleep(Duration::from_secs(2)).await;
            if pid > 0 {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
            }
            // Reap the child
            let _ = child.wait().await;

            Ok(ShellExecResult {
                stdout: String::new(),
                stderr: "process killed: timeout exceeded".into(),
                exit_code: -1,
                truncated: false,
            })
        }
    }
}

async fn drain_bounded_output<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_output_bytes: usize,
) -> std::io::Result<CapturedOutput> {
    let mut retained = Vec::with_capacity(max_output_bytes.min(8192));
    let mut chunk = [0u8; 8192];
    let mut truncated = false;

    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }

        let remaining = max_output_bytes.saturating_sub(retained.len());
        let copy_len = remaining.min(n);
        if copy_len > 0 {
            retained.extend_from_slice(&chunk[..copy_len]);
        }
        if copy_len < n {
            truncated = true;
        }
    }

    Ok(CapturedOutput {
        bytes: retained,
        truncated,
    })
}
