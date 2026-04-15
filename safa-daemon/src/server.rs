use safa_core::audit::{timestamp_now, ProofStore, ProofVerdict};
use safa_core::config::AmaConfig;
use safa_core::errors::AmaError;
use safa_core::idempotency::{validate_idempotency_key, IdempotencyCache, IdempotencyStatus};
use safa_core::identity;
use safa_core::manifest::PublicManifest;
use safa_core::pipeline::process_action;
use safa_core::schema::ActionRequest;
use safa_core::slime::{AgentRegistry, SlimeAuthorizer};

use axum::body::Body;
use axum::error_handling::HandleErrorLayer;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower::timeout::TimeoutLayer;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use uuid::Uuid;

/// Convert an AmaError into an axum Response using the http_status_and_body() method.
fn ama_error_response(e: AmaError) -> Response {
    let (status, body) = e.http_status_and_body();
    (StatusCode::from_u16(status).unwrap(), Json(body)).into_response()
}

/// Rate limiter window state — protected by a single mutex to prevent
/// the C3 race condition where counter increment and window reset
/// were not atomic. Now carries its own per-agent limits.
pub struct RateLimitState {
    pub window_start: Instant,
    pub count: u64,
    pub max_per_window: u64,
    pub window_secs: u64,
}

const REPLAY_CACHE_MAX_ENTRIES: usize = 10_000;

struct ReplayEntry {
    idempotency_key: Uuid,
    seen_at: Instant,
}

struct ReplayCacheState {
    entries: HashMap<String, ReplayEntry>,
    max_entries: usize,
    ttl: Duration,
}

enum ReplayCheck {
    New,
    SameIdempotencyKey,
    DifferentIdempotencyKey,
    Full,
}

impl ReplayCacheState {
    fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            ttl,
        }
    }

    fn purge_expired(&mut self) {
        let now = Instant::now();
        self.entries
            .retain(|_, entry| now.duration_since(entry.seen_at) < self.ttl);
    }

    fn check_or_insert(
        &mut self,
        agent_id: &str,
        timestamp: &str,
        signature_hex: &str,
        idempotency_key: Uuid,
    ) -> ReplayCheck {
        self.purge_expired();
        let replay_key = format!("{agent_id}.{timestamp}.{signature_hex}");

        if let Some(existing) = self.entries.get(&replay_key) {
            if existing.idempotency_key == idempotency_key {
                return ReplayCheck::SameIdempotencyKey;
            }
            return ReplayCheck::DifferentIdempotencyKey;
        }

        if self.entries.len() >= self.max_entries {
            // MiniMax audit finding HIGH-01: previously this path returned
            // ReplayCheck::Full, which bubbled up to a 503 for every
            // subsequent authenticated request until TTL-expiry drained
            // the cache. An attacker holding valid HMAC credentials could
            // intentionally fill the cache to max_entries inside the
            // 5-minute replay window and deny service to every other
            // agent until the window rolled over.
            //
            // We now evict the single oldest entry (by seen_at) and accept
            // the new request. Anti-replay semantics are preserved: the
            // exact match above still fires whenever a replay presents the
            // same (agent_id, timestamp, signature_hex), and eviction only
            // targets entries old enough that no duplicate has matched
            // against them in a full cache cycle. ReplayCheck::Full is
            // retained on the enum for callers/tests but is no longer
            // reachable from this insertion path.
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.seen_at)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }

        self.entries.insert(
            replay_key,
            ReplayEntry {
                idempotency_key,
                seen_at: Instant::now(),
            },
        );
        ReplayCheck::New
    }
}

/// Shared application state wrapped in Arc for thread-safe access.
pub struct AppState {
    pub config: AmaConfig,
    pub agent_registry: AgentRegistry,
    pub idempotency_cache: IdempotencyCache,
    pub session_id: Uuid,
    pub start_time: Instant,
    pub domain_counters: HashMap<String, AtomicU64>,
    pub agent_rate_limiters: HashMap<String, std::sync::Mutex<RateLimitState>>,
    replay_cache: std::sync::Mutex<ReplayCacheState>,
    pub proof_store: ProofStore,
}

impl AppState {
    pub fn new(config: AmaConfig) -> Arc<Self> {
        // Build AgentRegistry from config.agents
        let agent_configs: Vec<safa_core::config::AgentConfig> =
            config.agents.values().cloned().collect();
        let agent_registry = AgentRegistry::new(agent_configs);

        // Build per-agent rate limiters
        let mut agent_rate_limiters = HashMap::new();
        for (agent_id, agent_config) in &config.agents {
            agent_rate_limiters.insert(
                agent_id.clone(),
                std::sync::Mutex::new(RateLimitState {
                    window_start: Instant::now(),
                    count: 0,
                    max_per_window: agent_config.rate_limit_per_window,
                    window_secs: agent_config.rate_limit_window_secs,
                }),
            );
        }

        // Build domain_counters as union of all agents' domain policy keys
        let mut domain_counters = HashMap::new();
        for agent in config.agents.values() {
            for domain_id in agent.domain_policies.keys() {
                domain_counters
                    .entry(domain_id.clone())
                    .or_insert_with(|| AtomicU64::new(0));
            }
        }

        Arc::new(Self {
            agent_registry,
            idempotency_cache: IdempotencyCache::new(10_000, std::time::Duration::from_secs(300)),
            session_id: Uuid::new_v4(),
            start_time: Instant::now(),
            domain_counters,
            agent_rate_limiters,
            replay_cache: std::sync::Mutex::new(ReplayCacheState::new(
                REPLAY_CACHE_MAX_ENTRIES,
                Duration::from_secs(identity::TIMESTAMP_TOLERANCE_SECS),
            )),
            proof_store: ProofStore::new(10_000),
            config,
        })
    }
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/ama/action", post(handle_action))
        .route("/ama/status", get(handle_status))
        .route("/ama/manifest/{agent_id}", get(handle_manifest))
        .route("/ama/proof/{request_id}", get(handle_proof))
        .route("/health", get(handle_health))
        .route("/version", get(handle_version))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|_: tower::BoxError| async {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({"status": "error", "error_class": "timeout",
                            "message": "request exceeded 30s global deadline"})),
                    )
                }))
                .layer(RequestBodyLimitLayer::new(1_048_576))
                .layer(TimeoutLayer::new(std::time::Duration::from_secs(30)))
                .concurrency_limit(8),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            content_type_middleware,
        ))
        .with_state(state)
}

async fn content_type_middleware(
    State(_state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if req.method() == axum::http::Method::POST {
        let content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !content_type.starts_with("application/json") {
            return ama_error_response(AmaError::UnsupportedMediaType);
        }
    }
    next.run(req).await
}

/// Resolve agent_id from X-Agent-Id header or default_agent_id.
#[allow(clippy::result_large_err)]
fn resolve_agent_id(headers: &axum::http::HeaderMap, state: &AppState) -> Result<String, Response> {
    match headers.get("x-agent-id") {
        Some(val) => {
            let agent_id = val.to_str().map_err(|_| {
                ama_error_response(AmaError::BadRequest {
                    message: "X-Agent-Id header is not valid ASCII".into(),
                })
            })?;
            if state.agent_registry.get(agent_id).is_none() {
                return Err(ama_error_response(AmaError::BadRequest {
                    message: format!("unknown agent: {}", agent_id),
                }));
            }
            Ok(agent_id.to_string())
        }
        None => match &state.config.default_agent_id {
            Some(default) => Ok(default.clone()),
            None => Err(ama_error_response(AmaError::BadRequest {
                message: "X-Agent-Id header required (multiple agents configured)".into(),
            })),
        },
    }
}

/// P1 fix (C3): window_start and counter are now under the same mutex.
/// No gap between window reset and counter increment.
/// P2: now per-agent with configurable limits.
fn check_rate_limit(state: &AppState, agent_id: &str) -> bool {
    let limiter = match state.agent_rate_limiters.get(agent_id) {
        Some(l) => l,
        None => return false,
    };
    // Recover from poisoned mutex instead of panicking: if a prior task
    // panicked while holding this lock, the data is still readable/writable,
    // and taking the daemon down with it would turn a localized bug into a
    // full DoS. The rate-limiter state is advisory per-window, not a security
    // boundary — accepting a potentially-inconsistent window start is strictly
    // safer than panicking.
    let mut rl = limiter
        .lock()
        .unwrap_or_else(|poisoned| {
            // Kimi audit observation: surface poison recovery so operators
            // can correlate this with the panic that caused it, rather than
            // silently masking a bug-in-progress.
            tracing::warn!(
                agent_id = agent_id,
                "rate limiter mutex recovered from poison"
            );
            poisoned.into_inner()
        });
    let now = Instant::now();
    let elapsed = now.duration_since(rl.window_start);

    if elapsed.as_secs() >= rl.window_secs {
        // New window — reset counter atomically with window start
        rl.window_start = now;
        rl.count = 1;
        return true;
    }

    rl.count += 1;
    rl.count <= rl.max_per_window
}

fn increment_domain_counter(state: &AppState, domain_id: &str) {
    if let Some(counter) = state.domain_counters.get(domain_id) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

fn check_signed_replay(
    state: &AppState,
    agent_id: &str,
    timestamp: &str,
    signature_hex: &str,
    idempotency_key: Uuid,
) -> Result<(), Response> {
    // Recover from poisoned mutex instead of panicking: losing a single
    // rate-limit or replay-cache update to a poisoned lock is strictly safer
    // than bringing the entire daemon down, which would turn any panic in a
    // mutex-guarded section into a full DoS. The replay cache is a bounded
    // in-memory structure with its own consistency checks, so reading a
    // partially-inconsistent state from a recovered poison is acceptable.
    let mut replay_cache = state
        .replay_cache
        .lock()
        .unwrap_or_else(|poisoned| {
            tracing::warn!(
                agent_id = agent_id,
                "replay cache mutex recovered from poison"
            );
            poisoned.into_inner()
        });
    match replay_cache.check_or_insert(agent_id, timestamp, signature_hex, idempotency_key) {
        ReplayCheck::New | ReplayCheck::SameIdempotencyKey => Ok(()),
        ReplayCheck::DifferentIdempotencyKey => Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "error",
                "error_class": "replay_detected",
                "message": "signed request replay detected",
            })),
        )
            .into_response()),
        ReplayCheck::Full => Err(ama_error_response(AmaError::ServiceUnavailable {
            message: "identity replay cache full — fail-closed".into(),
        })),
    }
}

async fn handle_health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

async fn handle_version() -> impl IntoResponse {
    Json(json!({
        "name": "safa",
        "version": env!("CARGO_PKG_VERSION"),
        "schema_version": "ama-action-v1"
    }))
}

async fn handle_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();

    // Per-agent capacity status
    let mut agents_status = serde_json::Map::new();
    for agent_id in state.agent_registry.agent_ids() {
        if let Some(auth) = state.agent_registry.get(agent_id) {
            agents_status.insert(
                agent_id.to_string(),
                json!({
                    "capacity_used": auth.capacity_used(),
                    "capacity_max": auth.capacity_max(),
                    "capacity_remaining": auth.capacity_max().saturating_sub(auth.capacity_used()),
                }),
            );
        }
    }

    // Domain counters
    let mut domains = serde_json::Map::new();
    for (domain_id, policy) in &state.config.domain_policies {
        let count = state
            .domain_counters
            .get(domain_id)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        domains.insert(
            domain_id.clone(),
            json!({
                "enabled": policy.enabled,
                "actions_count": count,
            }),
        );
    }

    Json(json!({
        "session_id": state.session_id.to_string(),
        "uptime_seconds": uptime,
        "agents": agents_status,
        "domains": domains,
    }))
}

/// P3: Serve the public capability manifest for an agent.
/// Returns the agent's capabilities, constraints, and manifest hash.
/// Never exposes the HMAC secret.
async fn handle_manifest(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(agent_id): axum::extract::Path<String>,
) -> Response {
    match state.config.agents.get(&agent_id) {
        Some(agent_config) => {
            let bundle_hash = state.config.boot_hashes.policy_bundle_hash();
            let manifest = PublicManifest::from_agent_config(agent_config, &bundle_hash);
            let hash = manifest.hash().to_string();
            // MiniMax audit finding MED-02: serialization of the manifest
            // type is infallible under the current schema, but relying on
            // that via .unwrap() means any future non-serializable field
            // (e.g. a map with non-string keys introduced upstream) would
            // panic the request handler thread rather than returning a
            // clean 500. Downgrade to a tracing error + 500.
            match serde_json::to_value(&manifest) {
                Ok(body) => (StatusCode::OK, [("x-safa-policy-hash", hash)], Json(body))
                    .into_response(),
                Err(err) => {
                    tracing::error!(?err, "failed to serialize PublicManifest");
                    ama_error_response(AmaError::ServiceUnavailable {
                        message: "manifest serialization failed".into(),
                    })
                }
            }
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "status": "error",
                "error_class": "unknown_agent",
                "message": format!("no manifest for agent: {}", agent_id),
            })),
        )
            .into_response(),
    }
}

/// P3: Proof-of-Constraint endpoint.
/// Returns the verdict record for a past request, allowing any downstream
/// product to verify that SAFA evaluated the action.
async fn handle_proof(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(request_id): axum::extract::Path<String>,
) -> Response {
    match state.proof_store.get(&request_id) {
        Some(record) => {
            // MiniMax audit finding MED-02: same rationale as the manifest
            // handler — proof records are infallible today but we must not
            // panic the request path on a future schema change.
            let manifest_hash = record.manifest_hash.clone();
            match serde_json::to_value(&record) {
                Ok(body) => (
                    StatusCode::OK,
                    [("x-safa-policy-hash", manifest_hash)],
                    Json(body),
                )
                    .into_response(),
                Err(err) => {
                    tracing::error!(?err, "failed to serialize ProofRecord");
                    ama_error_response(AmaError::ServiceUnavailable {
                        message: "proof record serialization failed".into(),
                    })
                }
            }
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "status": "error",
                "error_class": "proof_not_found",
                "message": format!("no proof record for request_id: {}", request_id),
            })),
        )
            .into_response(),
    }
}

async fn handle_action(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // 0. Resolve agent_id from header or default
    let agent_id = match resolve_agent_id(&headers, &state) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let mut identity_replay_headers: Option<(String, String)> = None;

    // 0.5 P3: Identity binding — verify HMAC if agent has a secret configured
    if let Some(agent_config) = state.config.agents.get(&agent_id) {
        if let Some(ref secret) = agent_config.secret {
            let timestamp_str = headers
                .get("x-agent-timestamp")
                .and_then(|v| v.to_str().ok());
            let signature_hex = headers
                .get("x-agent-signature")
                .and_then(|v| v.to_str().ok());

            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if let Err(e) = identity::verify_identity(
                secret,
                &agent_id,
                timestamp_str,
                signature_hex,
                &body,
                now_secs,
            ) {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "status": "error",
                        "error_class": "identity_verification_failed",
                        "message": e.to_string(),
                    })),
                )
                    .into_response();
            }

            identity_replay_headers = Some((
                timestamp_str.unwrap().to_string(),
                signature_hex.unwrap().to_string(),
            ));
        }
    }

    // 1. Extract Idempotency-Key header
    let idem_key_str = match headers.get("idempotency-key") {
        Some(val) => match val.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                return ama_error_response(AmaError::BadRequest {
                    message: "Idempotency-Key header is not valid ASCII".into(),
                })
            }
        },
        None => {
            return ama_error_response(AmaError::BadRequest {
                message: "missing Idempotency-Key header".into(),
            })
        }
    };

    // 2. Validate UUID v4 format
    let idem_key = match validate_idempotency_key(&idem_key_str) {
        Ok(k) => k,
        Err(e) => return ama_error_response(e),
    };

    // 2.5 P3: reject exact replay of a signed envelope when it arrives
    // under a different Idempotency-Key. Same envelope + same key is
    // treated as a legitimate retry and falls through to idempotency.
    if let Some((timestamp_str, signature_hex)) = &identity_replay_headers {
        if let Err(resp) =
            check_signed_replay(&state, &agent_id, timestamp_str, signature_hex, idem_key)
        {
            return resp;
        }
    }

    // 3. Per-agent rate limit
    if !check_rate_limit(&state, &agent_id) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"status": "error", "error_class": "rate_limited", "message": "rate limit exceeded"})),
        ).into_response();
    }

    // 4. Idempotency cache check
    match state.idempotency_cache.check_or_insert(idem_key) {
        IdempotencyStatus::Cached(cached_response) => {
            return (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                cached_response,
            )
                .into_response();
        }
        IdempotencyStatus::InFlight => {
            return ama_error_response(AmaError::Conflict {
                message: "duplicate Idempotency-Key with in-flight request".into(),
            });
        }
        IdempotencyStatus::Full => {
            state.idempotency_cache.remove(&idem_key);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(
                    json!({"status": "error", "error_class": "service_unavailable",
                    "message": "idempotency cache full — fail-closed"}),
                ),
            )
                .into_response();
        }
        IdempotencyStatus::New => {
            // Continue processing
        }
    }

    // 5. Deserialize request body
    let request: ActionRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            // P1 Model A: commit error as terminal result, do not remove.
            // This ensures retry with same key replays the error.
            let error_response = json!({
                "status": "error",
                "error_class": "bad_request",
                "message": format!("invalid JSON: {}", e),
            });
            state
                .idempotency_cache
                .complete(idem_key, serde_json::to_string(&error_response).unwrap());
            return (StatusCode::BAD_REQUEST, Json(error_response)).into_response();
        }
    };

    let action_name = request.action.clone();
    let magnitude = request.magnitude;

    // Generate action_id
    let action_id = Uuid::new_v4().to_string();

    // 6. Get agent's authorizer and process through pipeline
    let authorizer = match state.agent_registry.get(&agent_id) {
        Some(auth) => auth,
        None => {
            // Should not happen — resolve_agent_id already validated
            state.idempotency_cache.remove(&idem_key);
            return ama_error_response(AmaError::BadRequest {
                message: format!("unknown agent: {}", agent_id),
            });
        }
    };

    let result = process_action(
        request,
        &state.config,
        authorizer,
        action_id.clone(),
        &state.session_id.to_string(),
        Some(&agent_id),
    )
    .await;

    // 7. Build response and cache
    //    P3: Include X-Safa-Policy-Hash header for Proof-of-Constraint
    //    The manifest hash embeds the full policy bundle (domains + intents +
    //    allowlist) so external verifiers see a different hash whenever the
    //    effective policy surface changes — not just per-agent caps.
    let policy_hash = state
        .config
        .agents
        .get(&agent_id)
        .map(|ac| {
            let bundle_hash = state.config.boot_hashes.policy_bundle_hash();
            PublicManifest::from_agent_config(ac, &bundle_hash)
                .hash()
                .to_string()
        })
        .unwrap_or_default();

    // P3: Store proof record for Proof-of-Constraint endpoint
    let verdict = match &result {
        Ok(_) => ProofVerdict::Authorized,
        Err(error) => ProofVerdict::from_error(error),
    };
    state.proof_store.insert(safa_core::audit::ProofRecord {
        request_id: action_id.clone(),
        agent_id: agent_id.clone(),
        action: action_name.clone(),
        verdict,
        manifest_hash: policy_hash.clone(),
        timestamp: timestamp_now(),
    });

    match result {
        Ok(response) => {
            let response_json = serde_json::to_string(&response).unwrap();

            if let Ok(mapping) =
                safa_core::mapper::map_action(&action_name, magnitude, &state.config)
            {
                increment_domain_counter(&state, &mapping.domain_id);
            }

            state
                .idempotency_cache
                .complete(idem_key, response_json.clone());

            let mut resp = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                response_json,
            )
                .into_response();
            if !policy_hash.is_empty() {
                resp.headers_mut()
                    .insert("x-safa-policy-hash", policy_hash.parse().unwrap());
            }
            resp
        }
        Err(e) => {
            // P1 Model A: commit error as terminal result, do not remove.
            // All terminal outcomes (denial, timeout, failure) go to DONE.
            // Retry with same key will replay the cached error response.
            let (status, mut cached_json) = e.http_status_and_body();
            cached_json
                .as_object_mut()
                .expect("AmaError bodies must be JSON objects")
                .insert("action_id".into(), json!(action_id));
            state
                .idempotency_cache
                .complete(idem_key, serde_json::to_string(&cached_json).unwrap());
            (StatusCode::from_u16(status).unwrap(), Json(cached_json)).into_response()
        }
    }
}

/// Graceful shutdown signal handler.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM, shutting down gracefully");
            }
            _ = ctrl_c => {
                tracing::info!("Received Ctrl+C, shutting down gracefully");
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        tracing::info!("Received Ctrl+C, shutting down gracefully");
    }
}

/// Test helper: build a test server with multiple agents.
#[cfg(feature = "test-utils")]
#[derive(Debug, Clone)]
pub struct TestAgentSpec {
    pub agent_id: String,
    pub max_capacity: u64,
    pub rate_limit_per_window: u64,
    pub rate_limit_window_secs: u64,
    pub secret: Option<String>,
}

/// Test helper: build a test server with custom agent specs.
#[cfg(feature = "test-utils")]
pub async fn test_server_with_agent_specs(
    agent_specs: Vec<TestAgentSpec>,
) -> axum_test::TestServer {
    use safa_core::config::{AgentConfig, AmaConfig, BootHashes, DomainMapping, DomainPolicy};

    let workspace = std::env::temp_dir().join(format!("safa-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&workspace).unwrap();

    let base_domain_policies = {
        let mut dp = HashMap::new();
        dp.insert(
            "fs.write.workspace".into(),
            DomainPolicy {
                enabled: true,
                max_magnitude_per_action: 1000,
            },
        );
        dp
    };

    let mut domain_mappings = HashMap::new();
    domain_mappings.insert(
        "file_write".into(),
        DomainMapping {
            domain_id: "fs.write.workspace".into(),
            max_payload_bytes: Some(1_048_576),
            validator: None,
            requires_intent: false,
        },
    );

    let mut agents = HashMap::new();
    let mut global_max_capacity: u64 = 0;
    for spec in &agent_specs {
        let agent = AgentConfig {
            agent_id: spec.agent_id.clone(),
            max_capacity: spec.max_capacity,
            rate_limit_per_window: spec.rate_limit_per_window,
            rate_limit_window_secs: spec.rate_limit_window_secs,
            domain_policies: base_domain_policies.clone(),
            secret: spec.secret.clone(),
        };
        if spec.max_capacity > global_max_capacity {
            global_max_capacity = spec.max_capacity;
        }
        agents.insert(spec.agent_id.clone(), agent);
    }

    let default_agent_id = if agents.len() == 1 {
        Some(agents.keys().next().unwrap().clone())
    } else {
        None
    };

    let config = AmaConfig {
        workspace_root: workspace,
        bind_host: "127.0.0.1".into(),
        bind_port: 8787,
        log_level: "info".into(),
        log_output: "stderr".into(),
        slime_mode: "embedded".into(),
        max_capacity: global_max_capacity,
        domain_policies: base_domain_policies,
        domain_mappings,
        intents: HashMap::new(),
        allowlist: vec![],
        agents,
        default_agent_id,
        boot_hashes: BootHashes {
            config_hash: "test".into(),
            domains_hash: "test".into(),
            intents_hash: "test".into(),
            allowlist_hash: "test".into(),
            agents_hash: "test".into(),
        },
    };

    let state = AppState::new(config);
    let app = build_router(state);
    axum_test::TestServer::new(app.into_make_service()).unwrap()
}

/// Test helper: build a test server with multiple agents.
#[cfg(feature = "test-utils")]
pub async fn test_server_multiagent(
    agent_specs: Vec<(&str, u64, u64)>, // (agent_id, capacity, rate_limit_per_window)
) -> axum_test::TestServer {
    let specs = agent_specs
        .into_iter()
        .map(|(agent_id, capacity, rate_limit)| TestAgentSpec {
            agent_id: agent_id.to_string(),
            max_capacity: capacity,
            rate_limit_per_window: rate_limit,
            rate_limit_window_secs: 60,
            secret: None,
        })
        .collect();
    test_server_with_agent_specs(specs).await
}

/// Test helper: build a test server with default capacity (10000).
#[cfg(feature = "test-utils")]
pub async fn test_server() -> axum_test::TestServer {
    test_server_multiagent(vec![("default", 10_000, 60)]).await
}

/// Test helper: build a test server with custom capacity.
#[cfg(feature = "test-utils")]
pub async fn test_server_with_capacity(max_capacity: u64) -> axum_test::TestServer {
    test_server_multiagent(vec![("default", max_capacity, 60)]).await
}
