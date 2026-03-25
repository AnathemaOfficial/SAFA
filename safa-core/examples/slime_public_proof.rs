use safa_core::config::AmaConfig;
use safa_core::mapper::map_action;
use safa_core::pipeline::validate_field_exclusivity;
use safa_core::schema::{validate_magnitude, ActionRequest};
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use uuid::Uuid;

type DynError = Box<dyn std::error::Error>;
type DynResult<T> = Result<T, DynError>;

struct RunnerGuard {
    child: Child,
}

impl RunnerGuard {
    fn spawn(slime_runner_dir: &Path, egress_file: &Path) -> DynResult<Self> {
        let mut child = Command::new("cargo")
            .arg("run")
            .arg("--quiet")
            .arg("--features")
            .arg("integration_demo")
            .current_dir(slime_runner_dir)
            .env("SLIME_DEMO_EGRESS_FILE", egress_file)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;

        for _ in 0..40 {
            if TcpStream::connect("127.0.0.1:8080").is_ok() {
                return Ok(Self { child });
            }

            if let Some(status) = child.try_wait()? {
                return Err(format!(
                    "slime-runner exited before becoming ready: {status}; stderr: {}",
                    take_stderr(&mut child)
                )
                .into());
            }

            thread::sleep(Duration::from_millis(250));
        }

        Err("timed out waiting for slime-runner on 127.0.0.1:8080".into())
    }
}

impl Drop for RunnerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn take_stderr(child: &mut Child) -> String {
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    stderr
}

fn main() -> DynResult<()> {
    if TcpStream::connect("127.0.0.1:8080").is_ok() {
        return Err("127.0.0.1:8080 is already in use; stop the existing service before running this demo".into());
    }

    let slime_runner_dir = slime_runner_dir()?;
    let temp_root = std::env::temp_dir().join(format!("safa-slime-proof-{}", Uuid::new_v4()));
    let workspace_root = temp_root.join("workspace");
    let config_root = temp_root.join("config");
    let egress_file = temp_root.join("egress.bin");

    fs::create_dir_all(&workspace_root)?;
    fs::create_dir_all(&config_root)?;
    write_demo_config(&config_root, &workspace_root)?;

    let config = AmaConfig::load(&config_root)?;

    let allowed_request = ActionRequest {
        adapter: "integration-demo".into(),
        action: "file_write".into(),
        target: "allowed.txt".into(),
        magnitude: 7,
        dry_run: false,
        method: None,
        payload: Some("proof".into()),
        args: None,
    };
    let denied_request = ActionRequest {
        adapter: "integration-demo".into(),
        action: "file_read".into(),
        target: "denied.txt".into(),
        magnitude: 3,
        dry_run: false,
        method: None,
        payload: None,
        args: None,
    };

    let allowed_handoff = prepare_handoff(&allowed_request, &config)?;
    let denied_handoff = prepare_handoff(&denied_request, &config)?;

    let _runner = RunnerGuard::spawn(&slime_runner_dir, &egress_file)?;

    let allowed_response = post_to_slime(&allowed_handoff.0, allowed_handoff.1)?;
    if !allowed_response.contains("{\"status\":\"AUTHORIZED\"}") {
        return Err(format!("expected AUTHORIZED, got: {allowed_response}").into());
    }

    let effect = fs::read(&egress_file)?;
    if effect.len() != 32 {
        return Err(format!("expected one 32-byte authorized effect, got {} bytes", effect.len()).into());
    }

    let observed_domain = u64::from_le_bytes(effect[0..8].try_into()?);
    let observed_magnitude = u64::from_le_bytes(effect[8..16].try_into()?);
    if observed_domain != 0 || observed_magnitude != allowed_handoff.1 {
        return Err(format!(
            "unexpected authorized effect: domain_id={observed_domain}, magnitude={observed_magnitude}"
        )
        .into());
    }

    let denied_response = post_to_slime(&denied_handoff.0, denied_handoff.1)?;
    if !denied_response.contains("{\"status\":\"IMPOSSIBLE\"}") {
        return Err(format!("expected IMPOSSIBLE, got: {denied_response}").into());
    }

    let final_effect = fs::read(&egress_file)?;
    if final_effect.len() != 32 {
        return Err(format!(
            "impossible path should not append egress data; observed {} bytes",
            final_effect.len()
        )
        .into());
    }

    println!("SAFA -> SLIME public proof passed");
    println!("allowed handoff: domain={}, magnitude={}", allowed_handoff.0, allowed_handoff.1);
    println!("denied handoff: domain={}, magnitude={}", denied_handoff.0, denied_handoff.1);
    println!("egress bytes written: {}", final_effect.len());
    println!("slime runner dir: {}", slime_runner_dir.display());
    println!("proof root: {}", temp_root.display());

    Ok(())
}

fn prepare_handoff(request: &ActionRequest, config: &AmaConfig) -> DynResult<(String, u64)> {
    validate_magnitude(request.magnitude)?;
    validate_field_exclusivity(request)?;

    let mapping = map_action(&request.action, request.magnitude, config)?;
    Ok((mapping.domain_id, mapping.magnitude))
}

fn post_to_slime(domain: &str, magnitude: u64) -> DynResult<String> {
    let body = format!(r#"{{"domain":"{domain}","magnitude":{magnitude}}}"#);
    let request = format!(
        "POST /action HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );

    let mut stream = TcpStream::connect("127.0.0.1:8080")?;
    stream.write_all(request.as_bytes())?;
    stream.shutdown(Shutdown::Write)?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn slime_runner_dir() -> DynResult<PathBuf> {
    if let Some(path) = std::env::var_os("SLIME_RUNNER_DIR") {
        let path = PathBuf::from(path);
        if path.is_dir() {
            return Ok(path);
        }
        return Err(format!("SLIME_RUNNER_DIR does not exist: {}", path.display()).into());
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let projects_dir = manifest_dir
        .ancestors()
        .nth(3)
        .ok_or("could not derive projects directory from CARGO_MANIFEST_DIR")?;
    let derived = projects_dir
        .join("slime-phase1b")
        .join("SLIME")
        .join("noncanon")
        .join("implementation_bundle")
        .join("slime-runner");

    if derived.is_dir() {
        return Ok(derived);
    }

    Err(format!(
        "could not find slime-runner at {}; set SLIME_RUNNER_DIR explicitly",
        derived.display()
    )
    .into())
}

fn write_demo_config(config_root: &Path, workspace_root: &Path) -> DynResult<()> {
    let workspace_root = workspace_root.to_string_lossy().replace('\\', "\\\\");

    fs::write(
        config_root.join("config.toml"),
        format!(
            r#"
[safa]
workspace_root = "{workspace_root}"
bind_host = "127.0.0.1"
bind_port = 8787

[slime]
mode = "embedded"
max_capacity = 100

[slime.domains.test]
enabled = true
max_magnitude_per_action = 20

[slime.domains.unknown_demo]
enabled = true
max_magnitude_per_action = 20
"#
        ),
    )?;

    fs::write(
        config_root.join("domains.toml"),
        r#"
[meta]
schema_version = "safa-domains-v1"

[domains.file_write]
domain_id = "test"
max_payload_bytes = 1048576
validator = "relative_workspace_path"

[domains.file_read]
domain_id = "unknown.demo"
validator = "relative_workspace_path"
"#,
    )?;

    fs::write(
        config_root.join("intents.toml"),
        r#"
[meta]
schema_version = "safa-intents-v1"
"#,
    )?;

    fs::write(
        config_root.join("allowlist.toml"),
        r#"
[meta]
schema_version = "safa-allowlist-v1"
"#,
    )?;

    Ok(())
}
