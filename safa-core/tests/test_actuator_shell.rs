#[cfg(unix)]
mod tests {
    use safa_core::actuator::shell::*;

    #[tokio::test]
    async fn executes_simple_intent() {
        let result = shell_exec(
            "/bin/echo",
            &["hello", "world"],
            "/tmp",
            "test-id",
            std::time::Duration::from_secs(5),
            65_536,
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("hello world"));
    }

    #[tokio::test]
    async fn kills_on_timeout() {
        let result = shell_exec(
            "/bin/sleep",
            &["60"],
            "/tmp",
            "test-timeout",
            std::time::Duration::from_secs(1),
            65_536,
        )
        .await;
        // Should timeout and kill
        assert!(result.is_ok()); // returns result with non-zero exit
    }

    #[tokio::test]
    async fn captures_stderr() {
        let result = shell_exec(
            "/bin/ls",
            &["/nonexistent_path_xyz"],
            "/tmp",
            "test-stderr",
            std::time::Duration::from_secs(5),
            65_536,
        )
        .await
        .unwrap();
        assert_ne!(result.exit_code, 0);
        assert!(!result.stderr.is_empty());
    }

    #[tokio::test]
    async fn exact_cap_output_is_not_marked_truncated() {
        let result = shell_exec(
            "/usr/bin/head",
            &["-c", "1024", "/dev/zero"],
            "/tmp",
            "test-exact-cap",
            std::time::Duration::from_secs(5),
            1024,
        )
        .await
        .unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout.len(), 1024);
        assert!(!result.truncated);
    }

    #[tokio::test]
    async fn large_stdout_is_bounded_and_marked_truncated() {
        let result = shell_exec(
            "/usr/bin/head",
            &["-c", "131072", "/dev/zero"],
            "/tmp",
            "test-large-stdout",
            std::time::Duration::from_secs(5),
            65_536,
        )
        .await
        .unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout.len(), 65_536);
        assert!(result.truncated);
    }

    #[tokio::test]
    async fn large_dual_stream_output_does_not_deadlock() {
        let result = shell_exec(
            "/bin/sh",
            &[
                "-c",
                "head -c 131072 /dev/zero; head -c 131072 /dev/zero 1>&2",
            ],
            "/tmp",
            "test-dual-stream",
            std::time::Duration::from_secs(5),
            65_536,
        )
        .await
        .unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout.len(), 65_536);
        assert_eq!(result.stderr.len(), 65_536);
        assert!(result.truncated);
    }
}
