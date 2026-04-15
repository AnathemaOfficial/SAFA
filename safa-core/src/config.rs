use crate::errors::AmaError;
use crate::newtypes::AllowlistEntry;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

// ── Boot Hashes ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BootHashes {
    pub config_hash: String,
    pub domains_hash: String,
    pub intents_hash: String,
    pub allowlist_hash: String,
    pub agents_hash: String,
}

impl BootHashes {
    /// Deterministic hash covering the full *effective policy* — the actual
    /// rules that govern whether an action is permitted.
    ///
    /// Covers: domain→action mappings (`domains.toml`), intent templates
    /// (`intents.toml`), and the URL allowlist (`allowlist.toml`). Does NOT
    /// include `config.toml` (deployment-specific: workspace path, bind host)
    /// nor the per-agent HMAC secrets.
    ///
    /// This value is embedded in every `PublicManifest` so that any change
    /// to the effective policy surface — even one that leaves an agent's
    /// own caps untouched — produces a visibly different proof hash.
    ///
    /// MiniMax audit finding MED-03: this hash is computed over the RAW
    /// TOML file bytes at load time (see `load_config`), not over a
    /// canonicalized parse tree. That means two policy files that are
    /// semantically identical but differ in whitespace, key ordering, or
    /// comment content will produce different policy bundle hashes. This
    /// is INTENTIONAL and it IS the feature — the point of the bundle
    /// hash is to attest to the exact file state an operator deployed,
    /// not just the logical policy that state happens to express. An
    /// external auditor who wants to verify a daemon's `manifest_hash`
    /// against an expected value must check the exact bytes of the
    /// policy files in place, not re-canonicalize first. A whitespace
    /// change committed by a code formatter is a real operational event
    /// that the attestation surfaces; suppressing it behind canonicalization
    /// would let a text editor silently invalidate downstream consumers'
    /// hash comparisons without flipping the attested hash.
    pub fn policy_bundle_hash(&self) -> String {
        // Canonical concatenation with explicit field labels: any reordering,
        // renaming, or addition of fields produces a different hash.
        let combined = format!(
            "safa-policy-bundle-v1|domains={}|intents={}|allowlist={}",
            self.domains_hash, self.intents_hash, self.allowlist_hash
        );
        sha256_hex(combined.as_bytes())
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Detect known placeholder secrets shipped in the repository's sample configs.
/// The loader refuses to boot any agent whose resolved secret matches one of
/// these patterns, to prevent accidental production deployment with a secret
/// that is public in the git history.
fn is_known_placeholder(secret: &str) -> bool {
    let lower = secret.to_ascii_lowercase();
    // Catch the historical committed samples and any future REPLACE_ME / change-me
    // markers. Patterns are matched case-insensitively as substrings.
    const PLACEHOLDER_MARKERS: &[&str] = &[
        "replace_me",
        "change-me",
        "change_me",
        "changeme",
        "placeholder",
        "not-for-production",
        "not_for_production",
        "your-secret",
        "your_own_secret",
        "example-secret",
    ];
    PLACEHOLDER_MARKERS.iter().any(|m| lower.contains(m))
}

// ── TOML raw structs (serde) ─────────────────────────────────

#[derive(Deserialize)]
struct RawConfig {
    safa: RawSafa,
    slime: RawSlime,
}

#[derive(Deserialize)]
struct RawSafa {
    workspace_root: String,
    #[serde(default = "default_host")]
    bind_host: String,
    #[serde(default = "default_port")]
    bind_port: u16,
    #[serde(default = "default_log_level")]
    log_level: String,
    #[serde(default = "default_log_output")]
    log_output: String,
}

fn default_host() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    8787
}
fn default_log_level() -> String {
    "info".into()
}
fn default_log_output() -> String {
    "stderr".into()
}

#[derive(Deserialize)]
struct RawSlime {
    mode: String,
    #[serde(default)]
    max_capacity: Option<u64>,
    #[serde(default)]
    domains: HashMap<String, RawDomainPolicy>,
}

// ── Agent config raw structs ────────────────────────────────

#[derive(Deserialize)]
struct RawAgentConfig {
    agent: RawAgent,
}

#[derive(Deserialize)]
struct RawAgent {
    agent_id: String,
    max_capacity: u64,
    #[serde(default = "default_rate_limit_per_window")]
    rate_limit_per_window: u64,
    #[serde(default = "default_rate_limit_window_secs")]
    rate_limit_window_secs: u64,
    /// P3: HMAC shared secret for identity binding. Optional for backward
    /// compatibility — if absent, identity verification is skipped for this
    /// agent (localhost-only acceptable in P2 mode).
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    domains: HashMap<String, RawDomainPolicy>,
}

fn default_rate_limit_per_window() -> u64 {
    60
}
fn default_rate_limit_window_secs() -> u64 {
    60
}

#[derive(Deserialize, Clone)]
struct RawDomainPolicy {
    enabled: bool,
    max_magnitude_per_action: u64,
}

#[derive(Deserialize)]
struct RawDomains {
    meta: RawMeta,
    domains: HashMap<String, RawDomainEntry>,
}

#[derive(Deserialize)]
struct RawMeta {
    schema_version: String,
}

#[derive(Deserialize, Clone)]
struct RawDomainEntry {
    domain_id: String,
    #[serde(default)]
    max_payload_bytes: Option<usize>,
    #[serde(default)]
    validator: Option<String>,
    #[serde(default)]
    requires_intent: Option<bool>,
}

#[derive(Deserialize)]
struct RawIntents {
    meta: RawMeta,
    #[serde(default)]
    intents: HashMap<String, RawIntentEntry>,
}

#[derive(Deserialize, Clone)]
struct RawIntentEntry {
    binary: String,
    args_template: Vec<String>,
    #[serde(default)]
    validators: Vec<String>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
}

#[derive(Deserialize)]
struct RawAllowlist {
    meta: RawMeta,
    #[serde(default)]
    urls: Vec<RawAllowlistUrl>,
}

#[derive(Deserialize, Clone)]
struct RawAllowlistUrl {
    pattern: String,
    methods: Vec<String>,
    #[serde(default)]
    max_body_bytes: Option<usize>,
}

// ── Public types ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DomainPolicy {
    pub enabled: bool,
    pub max_magnitude_per_action: u64,
}

#[derive(Debug, Clone)]
pub struct DomainMapping {
    pub domain_id: String,
    pub max_payload_bytes: Option<usize>,
    pub validator: Option<String>,
    pub requires_intent: bool,
}

#[derive(Debug, Clone)]
pub struct IntentMapping {
    pub binary: String,
    pub args_template: Vec<String>,
    pub validators: Vec<String>,
    pub working_dir: Option<String>,
}

/// Per-agent configuration with capacity, rate limits, and domain policies.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub agent_id: String,
    pub max_capacity: u64,
    pub rate_limit_per_window: u64,
    pub rate_limit_window_secs: u64,
    pub domain_policies: HashMap<String, DomainPolicy>,
    /// P3: HMAC shared secret for identity binding.
    /// When Some, all requests for this agent MUST include valid HMAC headers.
    /// When None, identity verification is skipped (P2 backward compat).
    pub secret: Option<String>,
}

impl AgentConfig {
    /// Parse an AgentConfig from a TOML string.
    pub fn from_toml_str(toml_str: &str) -> Result<Self, AmaError> {
        let raw: RawAgentConfig =
            toml::from_str(toml_str).map_err(|e| AmaError::ServiceUnavailable {
                message: format!("agent config parse error: {e}"),
            })?;

        let agent = raw.agent;

        // Validate agent_id: non-empty, alphanumeric/underscore/hyphen only
        if agent.agent_id.is_empty() {
            return Err(AmaError::ServiceUnavailable {
                message: "agent_id must not be empty".into(),
            });
        }
        if !agent
            .agent_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Err(AmaError::ServiceUnavailable {
                message: format!(
                    "agent_id '{}' contains invalid characters (only alphanumeric, _, -)",
                    agent.agent_id
                ),
            });
        }

        // Validate capacity
        if agent.max_capacity == 0 {
            return Err(AmaError::ServiceUnavailable {
                message: "agent max_capacity must be > 0".into(),
            });
        }

        // Validate rate limits
        if agent.rate_limit_per_window == 0 {
            return Err(AmaError::ServiceUnavailable {
                message: "agent rate_limit_per_window must be > 0".into(),
            });
        }
        if agent.rate_limit_window_secs == 0 {
            return Err(AmaError::ServiceUnavailable {
                message: "agent rate_limit_window_secs must be > 0".into(),
            });
        }

        // Normalize domain keys (underscore -> dot) and validate
        let mut domain_policies = HashMap::new();
        for (key, raw_policy) in &agent.domains {
            let domain_id = key.replace('_', ".");
            // max_magnitude_per_action constraints only apply to enabled domains.
            // A disabled domain's magnitude is irrelevant (the domain returns
            // Impossible before any magnitude check), so `= 0` is legitimate.
            if raw_policy.enabled {
                if raw_policy.max_magnitude_per_action == 0 {
                    return Err(AmaError::ServiceUnavailable {
                        message: format!(
                            "agent '{}' domain '{}': max_magnitude_per_action must be > 0 when enabled",
                            agent.agent_id, domain_id
                        ),
                    });
                }
                if raw_policy.max_magnitude_per_action > agent.max_capacity {
                    return Err(AmaError::ServiceUnavailable {
                        message: format!(
                            "agent '{}' domain '{}': max_magnitude_per_action ({}) > max_capacity ({})",
                            agent.agent_id, domain_id,
                            raw_policy.max_magnitude_per_action, agent.max_capacity
                        ),
                    });
                }
            }
            domain_policies.insert(
                domain_id,
                DomainPolicy {
                    enabled: raw_policy.enabled,
                    max_magnitude_per_action: raw_policy.max_magnitude_per_action,
                },
            );
        }

        // P3: Resolve the effective secret.
        // Precedence: SAFA_AGENT_SECRET_<AGENT_ID> env var > TOML `secret` field.
        // The env var route keeps real secrets out of version control; the TOML
        // route is kept for local/dev convenience, but committed placeholders
        // are refused at boot to prevent accidental prod exposure.
        let env_var_name = format!(
            "SAFA_AGENT_SECRET_{}",
            agent.agent_id.to_uppercase().replace('-', "_")
        );
        let resolved_secret: Option<String> = match std::env::var(&env_var_name) {
            Ok(v) if !v.is_empty() => Some(v),
            _ => agent.secret.clone(),
        };

        // P3: Validate secret if present (must be non-empty hex-compatible)
        if let Some(ref s) = resolved_secret {
            if s.is_empty() {
                return Err(AmaError::ServiceUnavailable {
                    message: format!(
                        "agent '{}': secret must not be empty if specified",
                        agent.agent_id
                    ),
                });
            }
            if s.len() < 32 {
                return Err(AmaError::ServiceUnavailable {
                    message: format!(
                        "agent '{}': secret must be at least 32 characters",
                        agent.agent_id
                    ),
                });
            }
            if is_known_placeholder(s) {
                return Err(AmaError::ServiceUnavailable {
                    message: format!(
                        "agent '{}': secret is a known placeholder — set a real secret in config or via {} env var (generate with: openssl rand -hex 32)",
                        agent.agent_id, env_var_name
                    ),
                });
            }
        }

        Ok(Self {
            agent_id: agent.agent_id,
            max_capacity: agent.max_capacity,
            rate_limit_per_window: agent.rate_limit_per_window,
            rate_limit_window_secs: agent.rate_limit_window_secs,
            domain_policies,
            secret: resolved_secret,
        })
    }
}

/// Load all agent configs from a directory of .toml files.
/// Returns a map of agent_id -> AgentConfig. Rejects duplicates and empty dirs.
pub fn load_agent_configs(agents_dir: &Path) -> Result<HashMap<String, AgentConfig>, AmaError> {
    let mut agents = HashMap::new();

    let entries: Vec<_> = fs::read_dir(agents_dir)
        .map_err(|e| AmaError::ServiceUnavailable {
            message: format!("cannot read agents directory: {e}"),
        })?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().and_then(|e| e.to_str()) == Some("toml"))
        .collect();

    if entries.is_empty() {
        return Err(AmaError::ServiceUnavailable {
            message: "agents directory contains no .toml files".into(),
        });
    }

    for entry in entries {
        let path = entry.path();
        let contents = fs::read_to_string(&path).map_err(|e| AmaError::ServiceUnavailable {
            message: format!("cannot read {}: {e}", path.display()),
        })?;

        let agent_config = AgentConfig::from_toml_str(&contents)?;

        if agents.contains_key(&agent_config.agent_id) {
            return Err(AmaError::ServiceUnavailable {
                message: format!(
                    "duplicate agent_id '{}' in agents directory",
                    agent_config.agent_id
                ),
            });
        }

        agents.insert(agent_config.agent_id.clone(), agent_config);
    }

    Ok(agents)
}

#[derive(Debug, Clone)]
pub struct AmaConfig {
    pub workspace_root: PathBuf,
    pub bind_host: String,
    pub bind_port: u16,
    pub log_level: String,
    pub log_output: String,
    pub slime_mode: String,
    pub max_capacity: u64,
    pub domain_policies: HashMap<String, DomainPolicy>,
    pub domain_mappings: HashMap<String, DomainMapping>,
    pub intents: HashMap<String, IntentMapping>,
    pub allowlist: Vec<AllowlistEntry>,
    pub agents: HashMap<String, AgentConfig>,
    pub default_agent_id: Option<String>,
    pub boot_hashes: BootHashes,
}

impl AmaConfig {
    /// Load and validate all config files. Refuses to return on any error.
    pub fn load(config_dir: &Path) -> Result<Self, AmaError> {
        // ── Read raw files ───────────────────────────────────
        let config_bytes = Self::read_file(config_dir, "config.toml")?;
        let domains_bytes = Self::read_file(config_dir, "domains.toml")?;
        let intents_bytes = Self::read_file(config_dir, "intents.toml")?;
        let allowlist_bytes = Self::read_file(config_dir, "allowlist.toml")?;

        // ── Compute SHA-256 hashes (agents_hash added later) ──
        let config_hash = sha256_hex(&config_bytes);
        let domains_hash = sha256_hex(&domains_bytes);
        let intents_hash = sha256_hex(&intents_bytes);
        let allowlist_hash = sha256_hex(&allowlist_bytes);

        // ── Parse TOML ───────────────────────────────────────
        let raw_config: RawConfig = toml::from_str(
            std::str::from_utf8(&config_bytes)
                .map_err(|e| Self::boot_err(format!("config.toml not UTF-8: {e}")))?,
        )
        .map_err(|e| Self::boot_err(format!("config.toml parse error: {e}")))?;

        let raw_domains: RawDomains = toml::from_str(
            std::str::from_utf8(&domains_bytes)
                .map_err(|e| Self::boot_err(format!("domains.toml not UTF-8: {e}")))?,
        )
        .map_err(|e| Self::boot_err(format!("domains.toml parse error: {e}")))?;

        let raw_intents: RawIntents = toml::from_str(
            std::str::from_utf8(&intents_bytes)
                .map_err(|e| Self::boot_err(format!("intents.toml not UTF-8: {e}")))?,
        )
        .map_err(|e| Self::boot_err(format!("intents.toml parse error: {e}")))?;

        let raw_allowlist: RawAllowlist = toml::from_str(
            std::str::from_utf8(&allowlist_bytes)
                .map_err(|e| Self::boot_err(format!("allowlist.toml not UTF-8: {e}")))?,
        )
        .map_err(|e| Self::boot_err(format!("allowlist.toml parse error: {e}")))?;

        // ── Validate schema versions ─────────────────────────
        Self::check_schema(
            "safa-domains-v1",
            &raw_domains.meta.schema_version,
            "domains.toml",
        )?;
        Self::check_schema(
            "safa-intents-v1",
            &raw_intents.meta.schema_version,
            "intents.toml",
        )?;
        Self::check_schema(
            "safa-allowlist-v1",
            &raw_allowlist.meta.schema_version,
            "allowlist.toml",
        )?;

        // ── Validate workspace_root ──────────────────────────
        // Environment variable SAFA_WORKSPACE_ROOT overrides the TOML value,
        // to keep deployment paths out of committed config.
        let workspace_root_str = std::env::var("SAFA_WORKSPACE_ROOT")
            .unwrap_or_else(|_| raw_config.safa.workspace_root.clone());

        // Reject known placeholder strings shipped in the committed example
        // config — an operator MUST set a real path either in config.toml or
        // via SAFA_WORKSPACE_ROOT before the daemon can boot.
        if workspace_root_str.contains("REPLACE") || workspace_root_str.contains("/path/to/") {
            return Err(Self::boot_err(format!(
                "workspace_root is still a placeholder: '{}'. Set a real absolute path in config.toml or via SAFA_WORKSPACE_ROOT env var.",
                workspace_root_str
            )));
        }

        let workspace_root = PathBuf::from(&workspace_root_str);
        if !workspace_root.is_absolute() {
            return Err(Self::boot_err("workspace_root must be absolute".into()));
        }
        if !workspace_root.is_dir() {
            return Err(Self::boot_err(format!(
                "workspace_root does not exist or is not a directory: {}",
                workspace_root.display()
            )));
        }

        // ── Validate bind_host ───────────────────────────────
        if raw_config.safa.bind_host != "127.0.0.1" {
            return Err(Self::boot_err(format!(
                "P0 requires bind_host = 127.0.0.1, got '{}'",
                raw_config.safa.bind_host
            )));
        }

        // ── Validate slime mode ──────────────────────────────
        if raw_config.slime.mode != "embedded" {
            return Err(Self::boot_err(format!(
                "P0 requires slime.mode = embedded, got '{}'",
                raw_config.slime.mode
            )));
        }

        // ── Load agents: either from agents/ dir or backward compat from [slime] ──
        let agents_dir = config_dir.join("agents");
        let (agents, default_agent_id, domain_policies, max_capacity, agents_hash) =
            if agents_dir.is_dir() {
                // P2 path: load agent configs from agents/ directory
                let agent_configs = load_agent_configs(&agents_dir)?;

                // Compute agents_hash: sort file hashes alphabetically
                let mut agent_hashes: Vec<String> = Vec::new();
                let mut entries: Vec<_> = fs::read_dir(&agents_dir)
                    .map_err(|e| Self::boot_err(format!("cannot read agents dir: {e}")))?
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("toml"))
                    .collect();
                entries.sort_by_key(|e| e.path());
                for entry in &entries {
                    let bytes = fs::read(entry.path()).map_err(|e| {
                        Self::boot_err(format!("cannot read {}: {e}", entry.path().display()))
                    })?;
                    agent_hashes.push(sha256_hex(&bytes));
                }
                let combined = agent_hashes.join("");
                let agents_hash = sha256_hex(combined.as_bytes());

                // Union of all agent domain_policies for backward compat fields
                let mut all_domain_policies = HashMap::new();
                let mut global_max_capacity: u64 = 0;
                for agent in agent_configs.values() {
                    if agent.max_capacity > global_max_capacity {
                        global_max_capacity = agent.max_capacity;
                    }
                    for (did, policy) in &agent.domain_policies {
                        all_domain_policies
                            .entry(did.clone())
                            .or_insert_with(|| policy.clone());
                    }
                }

                // Cross-validate: every domain_id in agent configs must exist in domains.toml
                for agent in agent_configs.values() {
                    for domain_id in agent.domain_policies.keys() {
                        let found = raw_domains
                            .domains
                            .values()
                            .any(|d| d.domain_id == *domain_id);
                        if !found {
                            return Err(Self::boot_err(format!(
                                "agent '{}' references domain '{}' not defined in domains.toml",
                                agent.agent_id, domain_id
                            )));
                        }
                    }
                }

                let default_id = if agent_configs.len() == 1 {
                    Some(agent_configs.keys().next().unwrap().clone())
                } else {
                    None
                };

                (
                    agent_configs,
                    default_id,
                    all_domain_policies,
                    global_max_capacity,
                    agents_hash,
                )
            } else {
                // Backward compat: synthesize "default" agent from [slime] section
                let slime_capacity = raw_config.slime.max_capacity.ok_or_else(|| {
                    Self::boot_err(
                        "slime.max_capacity is required when no agents/ directory exists".into(),
                    )
                })?;
                if slime_capacity == 0 {
                    return Err(Self::boot_err("slime.max_capacity must be > 0".into()));
                }
                if raw_config.slime.domains.is_empty() {
                    return Err(Self::boot_err(
                        "slime.domains is required when no agents/ directory exists".into(),
                    ));
                }

                let mut domain_policies = HashMap::new();
                for (key, raw_policy) in &raw_config.slime.domains {
                    let domain_id = key.replace('_', ".");
                    if raw_policy.max_magnitude_per_action == 0 {
                        return Err(Self::boot_err(format!(
                            "domain '{}': max_magnitude_per_action must be > 0",
                            domain_id
                        )));
                    }
                    if raw_policy.max_magnitude_per_action > slime_capacity {
                        return Err(Self::boot_err(format!(
                            "domain '{}': max_magnitude_per_action ({}) > max_capacity ({})",
                            domain_id, raw_policy.max_magnitude_per_action, slime_capacity
                        )));
                    }
                    domain_policies.insert(
                        domain_id,
                        DomainPolicy {
                            enabled: raw_policy.enabled,
                            max_magnitude_per_action: raw_policy.max_magnitude_per_action,
                        },
                    );
                }

                let default_agent = AgentConfig {
                    agent_id: "default".into(),
                    max_capacity: slime_capacity,
                    rate_limit_per_window: 60,
                    rate_limit_window_secs: 60,
                    domain_policies: domain_policies.clone(),
                    secret: None, // P2 backward compat: no identity binding
                };

                let mut agents = HashMap::new();
                agents.insert("default".into(), default_agent);

                (
                    agents,
                    Some("default".into()),
                    domain_policies,
                    slime_capacity,
                    String::new(),
                )
            };

        // ── Build domain mappings ────────────────────────────
        let mut domain_mappings = HashMap::new();
        for (action, entry) in &raw_domains.domains {
            // Cross-reference: domain_id must exist in config.toml policies
            if !domain_policies.contains_key(&entry.domain_id) {
                return Err(Self::boot_err(format!(
                    "domains.toml action '{}' references domain_id '{}' not in config.toml",
                    action, entry.domain_id
                )));
            }
            domain_mappings.insert(
                action.clone(),
                DomainMapping {
                    domain_id: entry.domain_id.clone(),
                    max_payload_bytes: entry.max_payload_bytes,
                    validator: entry.validator.clone(),
                    requires_intent: entry.requires_intent.unwrap_or(false),
                },
            );
        }

        // ── Build intent mappings ────────────────────────────
        let mut intents = HashMap::new();
        for (name, raw_intent) in &raw_intents.intents {
            // Boot-time binary existence check.
            //
            // MiniMax audit finding MED-01: on Windows this check is
            // skipped by design — the production deployment target is
            // Linux (see README + systemd units + FP-4 hardening), and
            // Windows developer machines may have the declared binaries
            // at paths that don't match the linux-oriented `intents.toml`
            // (e.g. `/usr/bin/bash` on a Windows dev checkout). Keeping
            // the check Unix-only means Windows devs can build + run
            // unit tests without rewriting their intents.toml, at the
            // cost of deferring the "binary missing" error from boot to
            // actuation time on Windows. That trade is explicitly
            // accepted because Windows is not a production target.
            #[cfg(unix)]
            {
                let bin_path = Path::new(&raw_intent.binary);
                if !bin_path.exists() {
                    return Err(Self::boot_err(format!(
                        "intent '{}': binary '{}' does not exist",
                        name, raw_intent.binary
                    )));
                }
            }
            let working_dir = raw_intent
                .working_dir
                .as_ref()
                .map(|wd| wd.replace("{{workspace_root}}", workspace_root.to_str().unwrap_or("")));
            intents.insert(
                name.clone(),
                IntentMapping {
                    binary: raw_intent.binary.clone(),
                    args_template: raw_intent.args_template.clone(),
                    validators: raw_intent.validators.clone(),
                    working_dir,
                },
            );
        }

        // ── Build allowlist ──────────────────────────────────
        let allowlist: Vec<AllowlistEntry> = raw_allowlist
            .urls
            .iter()
            .map(|u| AllowlistEntry {
                pattern: u.pattern.clone(),
                methods: u.methods.clone(),
                max_body_bytes: u.max_body_bytes,
            })
            .collect();

        let boot_hashes = BootHashes {
            config_hash,
            domains_hash,
            intents_hash,
            allowlist_hash,
            agents_hash,
        };

        Ok(Self {
            workspace_root,
            bind_host: raw_config.safa.bind_host,
            bind_port: raw_config.safa.bind_port,
            log_level: raw_config.safa.log_level,
            log_output: raw_config.safa.log_output,
            slime_mode: raw_config.slime.mode,
            max_capacity,
            domain_policies,
            domain_mappings,
            intents,
            allowlist,
            agents,
            default_agent_id,
            boot_hashes,
        })
    }

    fn read_file(dir: &Path, name: &str) -> Result<Vec<u8>, AmaError> {
        let path = dir.join(name);
        fs::read(&path)
            .map_err(|e| Self::boot_err(format!("cannot read {}: {}", path.display(), e)))
    }

    fn check_schema(expected: &str, got: &str, file: &str) -> Result<(), AmaError> {
        if got != expected {
            return Err(Self::boot_err(format!(
                "{}: unrecognized schema_version '{}' (expected '{}')",
                file, got, expected
            )));
        }
        Ok(())
    }

    fn boot_err(msg: String) -> AmaError {
        AmaError::ServiceUnavailable { message: msg }
    }
}
