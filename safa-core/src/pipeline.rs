use crate::audit::{compute_request_hash, log_audit, timestamp_now, AuditEntry};
use crate::canonical::{ActionResult, CanonicalAction};
use crate::config::AmaConfig;
use crate::errors::AmaError;
use crate::mapper::map_action;
use crate::newtypes::*;
use crate::schema::{validate_adapter, validate_magnitude, ActionRequest, ActionResponse};
use crate::slime::{SlimeAuthorizer, SlimeVerdict};
use std::time::{Duration, Instant};

/// Per-action timeout durations from spec.
fn action_timeout(action: &str) -> Duration {
    match action {
        "file_write" | "file_read" => Duration::from_secs(5),
        "shell_exec" | "http_request" => Duration::from_secs(15),
        _ => Duration::from_secs(5),
    }
}

/// Validate mutual exclusivity of payload/args per action class.
pub fn validate_field_exclusivity(request: &ActionRequest) -> Result<(), AmaError> {
    match request.action.as_str() {
        "file_write" => {
            if request.payload.is_none() {
                return Err(AmaError::Validation {
                    error_class: "missing_field".into(),
                    message: "file_write requires 'payload'".into(),
                });
            }
            if request.args.is_some() {
                return Err(AmaError::Validation {
                    error_class: "invalid_field".into(),
                    message: "file_write does not accept 'args'".into(),
                });
            }
        }
        "file_read" => {
            if request.payload.is_some() {
                return Err(AmaError::Validation {
                    error_class: "invalid_field".into(),
                    message: "file_read does not accept 'payload'".into(),
                });
            }
            if request.args.is_some() {
                return Err(AmaError::Validation {
                    error_class: "invalid_field".into(),
                    message: "file_read does not accept 'args'".into(),
                });
            }
        }
        "shell_exec" => {
            if request.args.is_none() {
                return Err(AmaError::Validation {
                    error_class: "missing_field".into(),
                    message: "shell_exec requires 'args'".into(),
                });
            }
            if request.payload.is_some() {
                return Err(AmaError::Validation {
                    error_class: "invalid_field".into(),
                    message: "shell_exec does not accept 'payload'".into(),
                });
            }
        }
        "http_request" => {
            if request.args.is_some() {
                return Err(AmaError::Validation {
                    error_class: "invalid_field".into(),
                    message: "http_request does not accept 'args'".into(),
                });
            }
            if request.method.is_none() {
                return Err(AmaError::Validation {
                    error_class: "missing_field".into(),
                    message: "http_request requires 'method'".into(),
                });
            }
        }
        _ => {}
    }
    Ok(())
}

/// Canonicalize: construct type-safe newtypes from raw request.
/// P3: agent_id enables per-agent workspace isolation.
fn canonicalize(
    request: &ActionRequest,
    config: &AmaConfig,
    agent_id: Option<&str>,
) -> Result<CanonicalAction, AmaError> {
    match request.action.as_str() {
        "file_write" => {
            let path =
                WorkspacePath::new_with_agent(&request.target, &config.workspace_root, agent_id)?;
            let max_payload = config
                .domain_mappings
                .get("file_write")
                .and_then(|m| m.max_payload_bytes)
                .unwrap_or(1_048_576);
            let content =
                BoundedBytes::new(request.payload.clone().unwrap_or_default(), max_payload)?;
            Ok(CanonicalAction::FileWrite { path, content })
        }
        "file_read" => {
            let path =
                WorkspacePath::new_with_agent(&request.target, &config.workspace_root, agent_id)?;
            Ok(CanonicalAction::FileRead { path })
        }
        "shell_exec" => {
            let intent = IntentId::new(&request.target)?;
            let intent_config =
                config
                    .intents
                    .get(intent.as_str())
                    .ok_or_else(|| AmaError::Validation {
                        error_class: "unknown_intent".into(),
                        message: format!("intent '{}' not in intents.toml", intent.as_str()),
                    })?;
            let raw_args = request.args.as_deref().unwrap_or(&[]);
            let placeholder_count = intent_config
                .args_template
                .iter()
                .filter(|t| t.contains("{{"))
                .count();
            if raw_args.len() != placeholder_count {
                return Err(AmaError::Validation {
                    error_class: "invalid_args".into(),
                    message: format!(
                        "intent '{}' expects {} args, got {}",
                        intent.as_str(),
                        placeholder_count,
                        raw_args.len()
                    ),
                });
            }
            let mut args = Vec::new();
            for (i, raw_arg) in raw_args.iter().enumerate() {
                let safe = SafeArg::new(raw_arg)?;
                if let Some(validator) = intent_config.validators.get(i) {
                    if validator.as_str() == "relative_workspace_path" {
                        WorkspacePath::new_with_agent(raw_arg, &config.workspace_root, agent_id)?;
                    }
                }
                args.push(safe);
            }
            Ok(CanonicalAction::ShellExec { intent, args })
        }
        "http_request" => {
            let method_str = request.method.as_deref().unwrap_or("");
            let method = HttpMethod::parse(method_str)?;
            let url = AllowlistedUrl::new(&request.target, method, &config.allowlist)?;
            let body = match &request.payload {
                Some(data) => {
                    // Effective body cap = min(global domain cap, allowlist entry cap).
                    // This enforces the per-entry `max_body_bytes` declared in
                    // allowlist.toml in addition to the global domain cap from
                    // domains.toml. Previously only the global cap was applied.
                    let domain_max = config
                        .domain_mappings
                        .get("http_request")
                        .and_then(|m| m.max_payload_bytes)
                        .unwrap_or(262_144);
                    let effective_max = match url.matched_max_body_bytes() {
                        Some(entry_max) => domain_max.min(entry_max),
                        None => domain_max,
                    };
                    Some(BoundedBytes::new(data.clone(), effective_max)?)
                }
                None => None,
            };
            Ok(CanonicalAction::HttpRequest { method, url, body })
        }
        _ => Err(AmaError::Validation {
            error_class: "unknown_action".into(),
            message: format!("unknown action: {}", request.action),
        }),
    }
}

/// Execute the canonical action (actuation step) with per-action timeout.
async fn actuate(
    action: CanonicalAction,
    action_id: &str,
    config: &AmaConfig,
) -> Result<ActionResult, AmaError> {
    match action {
        CanonicalAction::FileWrite { path, content } => {
            let timeout = action_timeout("file_write");
            let result = tokio::time::timeout(timeout, async {
                crate::actuator::file::file_write(&path, &content, action_id)
            })
            .await
            .map_err(|_| AmaError::ServiceUnavailable {
                message: "file_write timed out".into(),
            })??;
            Ok(ActionResult::FileWrite {
                bytes_written: result.bytes_written,
            })
        }
        CanonicalAction::FileRead { path } => {
            let timeout = action_timeout("file_read");
            let result = tokio::time::timeout(timeout, async {
                crate::actuator::file::file_read(&path, 524_288)
            })
            .await
            .map_err(|_| AmaError::ServiceUnavailable {
                message: "file_read timed out".into(),
            })??;
            Ok(ActionResult::FileRead {
                content: result.content,
                bytes_returned: result.bytes_returned,
                total_bytes: result.total_bytes,
                truncated: result.truncated,
            })
        }
        #[cfg(unix)]
        CanonicalAction::ShellExec { intent, args } => {
            let intent_config = config.intents.get(intent.as_str()).ok_or_else(|| {
                AmaError::ServiceUnavailable {
                    message: "intent config not found at actuation".into(),
                }
            })?;
            let mut exec_args: Vec<String> = Vec::new();
            for tmpl in &intent_config.args_template {
                if let Some(idx_str) = tmpl.strip_prefix("{{").and_then(|s| s.strip_suffix("}}")) {
                    if let Ok(idx) = idx_str.parse::<usize>() {
                        if let Some(arg) = args.get(idx) {
                            exec_args.push(arg.as_str().to_string());
                            continue;
                        }
                    }
                }
                exec_args.push(tmpl.clone());
            }
            let working_dir = intent_config
                .working_dir
                .as_deref()
                .unwrap_or(config.workspace_root.to_str().unwrap_or("/tmp"));
            let timeout = action_timeout("shell_exec");
            let arg_refs: Vec<&str> = exec_args.iter().map(|s| s.as_str()).collect();
            let result = crate::actuator::shell::shell_exec(
                &intent_config.binary,
                &arg_refs,
                working_dir,
                action_id,
                timeout,
                65_536,
            )
            .await?;
            Ok(ActionResult::ShellExec {
                stdout: result.stdout,
                stderr: result.stderr,
                exit_code: result.exit_code,
                truncated: result.truncated,
            })
        }
        #[cfg(not(unix))]
        CanonicalAction::ShellExec { .. } => Err(AmaError::ServiceUnavailable {
            message: "shell_exec is only supported on Unix/Linux".into(),
        }),
        CanonicalAction::HttpRequest { method, url, body } => {
            let timeout_dur = action_timeout("http_request");
            let result = tokio::time::timeout(timeout_dur, async {
                crate::actuator::http::http_request(method, &url, body.as_ref(), &config.allowlist)
                    .await
            })
            .await
            .map_err(|_| AmaError::ServiceUnavailable {
                message: "http_request timed out".into(),
            })??;
            Ok(ActionResult::HttpResponse {
                status_code: result.status_code,
                body: result.body,
                truncated: result.truncated,
            })
        }
    }
}

/// Full pipeline: validate -> map -> authorize -> actuate.
pub async fn process_action(
    request: ActionRequest,
    config: &AmaConfig,
    authorizer: &dyn SlimeAuthorizer,
    action_id: String,
    session_id: &str,
    agent_id: Option<&str>,
) -> Result<ActionResponse, AmaError> {
    let start = Instant::now();

    // 1. Validate magnitude
    validate_adapter(&request.adapter)?;
    validate_magnitude(request.magnitude)?;

    // 2. Validate mutual exclusivity of payload/args per action
    validate_field_exclusivity(&request)?;

    // 3. Canonicalize (construct newtypes — structural validation)
    //    P3: pass agent_id for per-agent workspace isolation
    let canonical = canonicalize(&request, config, agent_id)?;

    // 4. Map to domain
    let mapping = map_action(&request.action, request.magnitude, config)?;

    // Compute request hash for audit
    let request_hash = compute_request_hash(&request.action, &request.target, request.magnitude);

    // 5. Dry-run check BEFORE capacity reservation
    if request.dry_run {
        let verdict = authorizer.check_only(&mapping.domain_id, mapping.magnitude);
        let status_str = match verdict {
            SlimeVerdict::Authorized => "authorized",
            SlimeVerdict::Impossible => "impossible",
        };
        log_audit(&AuditEntry {
            timestamp: timestamp_now(),
            session_id: session_id.into(),
            action_id: action_id.clone(),
            adapter: request.adapter.clone(),
            action: request.action.clone(),
            domain_id: mapping.domain_id.clone(),
            magnitude_effective: mapping.magnitude,
            duration_ms: start.elapsed().as_millis() as u64,
            status: status_str.into(),
            request_hash: request_hash.clone(),
            truncated: false,
        });
        return match verdict {
            SlimeVerdict::Authorized => Ok(ActionResponse {
                status: "authorized".into(),
                action_id,
                dry_run: true,
                result: None,
            }),
            SlimeVerdict::Impossible => Err(AmaError::Impossible),
        };
    }

    // 6. Reserve capacity (atomic CAS)
    match authorizer.try_reserve(&mapping.domain_id, mapping.magnitude) {
        SlimeVerdict::Authorized => {}
        SlimeVerdict::Impossible => {
            log_audit(&AuditEntry {
                timestamp: timestamp_now(),
                session_id: session_id.into(),
                action_id: action_id.clone(),
                adapter: request.adapter.clone(),
                action: request.action.clone(),
                domain_id: mapping.domain_id.clone(),
                magnitude_effective: mapping.magnitude,
                duration_ms: start.elapsed().as_millis() as u64,
                status: "impossible".into(),
                request_hash,
                truncated: false,
            });
            return Err(AmaError::Impossible);
        }
    }

    // 7. Actuate
    let result = actuate(canonical, &action_id, config).await;

    let (status_str, truncated) = match &result {
        Ok(r) => ("authorized", r.is_truncated()),
        Err(_) => ("error", false),
    };

    log_audit(&AuditEntry {
        timestamp: timestamp_now(),
        session_id: session_id.into(),
        action_id: action_id.clone(),
        adapter: request.adapter.clone(),
        action: request.action.clone(),
        domain_id: mapping.domain_id,
        magnitude_effective: mapping.magnitude,
        duration_ms: start.elapsed().as_millis() as u64,
        status: status_str.into(),
        request_hash,
        truncated,
    });

    let result = result?;

    Ok(ActionResponse {
        status: "authorized".into(),
        action_id,
        dry_run: false,
        result: Some(serde_json::to_value(&result).unwrap()),
    })
}
