// SAFA P3 — Capability Manifest & Proof-of-Constraint
//
// Each agent's capabilities are expressed as a PublicManifest — a snapshot
// of what the agent is allowed to do, without exposing secrets.
//
// The manifest is hashed (SHA-256 over canonical JSON with sorted keys)
// to produce a deterministic fingerprint that can be:
//   - exposed via X-Safa-Policy-Hash response header
//   - queried via /ama/manifest/{agent_id}
//   - verified by any external auditor
//
// This is the "Proof-of-Constraint" — verifiable evidence that an agent
// operates under a specific, auditable set of rules.

use crate::config::AgentConfig;
use serde::Serialize;
use sha2::{Sha256, Digest};
use std::collections::BTreeMap;

/// Public representation of an agent's capability manifest.
/// Contains everything needed to audit what the agent can do,
/// but NEVER exposes the HMAC secret.
///
/// The `manifest_hash` is computed over the per-agent capability fields AND
/// the `policy_bundle_hash` covering the effective policy surface
/// (`domains.toml`, `intents.toml`, `allowlist.toml`). Any change to the
/// policy bundle — even one that doesn't touch the agent's own caps —
/// produces a visibly different `manifest_hash`, so consumers of the
/// Proof-of-Constraint cannot miss a silent policy drift.
#[derive(Debug, Clone, Serialize)]
pub struct PublicManifest {
    /// Schema version for manifest format stability.
    pub schema_version: &'static str,
    /// The agent this manifest describes.
    pub agent_id: String,
    /// Whether this agent uses HMAC identity binding.
    pub identity_bound: bool,
    /// Maximum thermodynamic capacity for this agent.
    pub max_capacity: u64,
    /// Rate limit: max actions per window.
    pub rate_limit_per_window: u64,
    /// Rate limit: window duration in seconds.
    pub rate_limit_window_secs: u64,
    /// Domain capabilities — sorted map for deterministic hashing.
    /// Key = domain_id, Value = domain capability descriptor.
    pub domains: BTreeMap<String, DomainCapability>,
    /// SHA-256 over `domains.toml` + `intents.toml` + `allowlist.toml`
    /// (via `BootHashes::policy_bundle_hash()`). Changing any of those files
    /// changes every agent's `manifest_hash`.
    pub policy_bundle_hash: String,
    /// SHA-256 hash of this manifest's canonical JSON representation.
    /// Includes all fields above — including `policy_bundle_hash` — so that
    /// the effective policy is attested, not just the agent's own caps.
    pub manifest_hash: String,
}

/// Public descriptor of what an agent can do within a single domain.
#[derive(Debug, Clone, Serialize)]
pub struct DomainCapability {
    pub enabled: bool,
    pub max_magnitude_per_action: u64,
}

/// Intermediate struct for hashing — same as PublicManifest but without
/// the manifest_hash field (which would create circular dependency).
#[derive(Serialize)]
struct ManifestForHashing {
    schema_version: &'static str,
    agent_id: String,
    identity_bound: bool,
    max_capacity: u64,
    rate_limit_per_window: u64,
    rate_limit_window_secs: u64,
    domains: BTreeMap<String, DomainCapability>,
    /// Embedded here so the final manifest_hash captures changes in
    /// domains.toml / intents.toml / allowlist.toml.
    policy_bundle_hash: String,
}

const MANIFEST_SCHEMA_VERSION: &str = "safa-manifest-v2";

impl PublicManifest {
    /// Build a PublicManifest from an AgentConfig and the effective-policy
    /// bundle hash (obtained via `BootHashes::policy_bundle_hash()`).
    ///
    /// The secret is never included — only a boolean indicating whether
    /// identity binding is active.
    ///
    /// `policy_bundle_hash` MUST reflect the currently-loaded
    /// `domains.toml` / `intents.toml` / `allowlist.toml` so that the
    /// manifest hash flips whenever any of those files change. Passing
    /// a stale or fabricated value weakens the attestation.
    pub fn from_agent_config(config: &AgentConfig, policy_bundle_hash: &str) -> Self {
        let domains: BTreeMap<String, DomainCapability> = config
            .domain_policies
            .iter()
            .map(|(domain_id, policy)| {
                (
                    domain_id.clone(),
                    DomainCapability {
                        enabled: policy.enabled,
                        max_magnitude_per_action: policy.max_magnitude_per_action,
                    },
                )
            })
            .collect();

        let hashable = ManifestForHashing {
            schema_version: MANIFEST_SCHEMA_VERSION,
            agent_id: config.agent_id.clone(),
            identity_bound: config.secret.is_some(),
            max_capacity: config.max_capacity,
            rate_limit_per_window: config.rate_limit_per_window,
            rate_limit_window_secs: config.rate_limit_window_secs,
            domains: domains.clone(),
            policy_bundle_hash: policy_bundle_hash.to_string(),
        };

        // Canonical JSON: serde_json with sorted keys (BTreeMap guarantees order)
        let canonical_json = serde_json::to_string(&hashable)
            .expect("ManifestForHashing must serialize");

        let mut hasher = Sha256::new();
        hasher.update(canonical_json.as_bytes());
        let manifest_hash = format!("{:x}", hasher.finalize());

        Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            agent_id: config.agent_id.clone(),
            identity_bound: config.secret.is_some(),
            max_capacity: config.max_capacity,
            rate_limit_per_window: config.rate_limit_per_window,
            rate_limit_window_secs: config.rate_limit_window_secs,
            domains,
            policy_bundle_hash: policy_bundle_hash.to_string(),
            manifest_hash,
        }
    }

    /// Returns just the hash string for use in HTTP headers.
    pub fn hash(&self) -> &str {
        &self.manifest_hash
    }

    /// Returns the embedded policy bundle hash for independent verification.
    pub fn policy_bundle_hash(&self) -> &str {
        &self.policy_bundle_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentConfig, DomainPolicy};
    use std::collections::HashMap;

    fn test_agent(with_secret: bool) -> AgentConfig {
        let mut domain_policies = HashMap::new();
        domain_policies.insert(
            "fs.write.workspace".into(),
            DomainPolicy {
                enabled: true,
                max_magnitude_per_action: 1000,
            },
        );
        domain_policies.insert(
            "http.request".into(),
            DomainPolicy {
                enabled: true,
                max_magnitude_per_action: 500,
            },
        );

        AgentConfig {
            agent_id: "test-agent".into(),
            max_capacity: 100_000,
            rate_limit_per_window: 60,
            rate_limit_window_secs: 60,
            domain_policies,
            secret: if with_secret {
                Some("a]3kf9$mZp!wL2xR7vN8qB4cY6hT0jDs".into())
            } else {
                None
            },
        }
    }

    const TEST_BUNDLE_HASH: &str = "test-policy-bundle-hash-abc123";

    #[test]
    fn test_manifest_from_config() {
        let config = test_agent(false);
        let manifest = PublicManifest::from_agent_config(&config, TEST_BUNDLE_HASH);

        assert_eq!(manifest.schema_version, "safa-manifest-v2");
        assert_eq!(manifest.agent_id, "test-agent");
        assert!(!manifest.identity_bound);
        assert_eq!(manifest.max_capacity, 100_000);
        assert_eq!(manifest.domains.len(), 2);
        assert_eq!(manifest.policy_bundle_hash, TEST_BUNDLE_HASH);
        assert!(!manifest.manifest_hash.is_empty());
    }

    #[test]
    fn test_manifest_never_leaks_secret() {
        let config = test_agent(true);
        let manifest = PublicManifest::from_agent_config(&config, TEST_BUNDLE_HASH);

        // identity_bound is true, but the actual secret is never in the manifest
        assert!(manifest.identity_bound);
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(!json.contains("a]3kf9"));
        assert!(!json.contains("secret"));
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let config = test_agent(true);
        let m1 = PublicManifest::from_agent_config(&config, TEST_BUNDLE_HASH);
        let m2 = PublicManifest::from_agent_config(&config, TEST_BUNDLE_HASH);
        assert_eq!(m1.manifest_hash, m2.manifest_hash);
    }

    #[test]
    fn test_manifest_hash_changes_with_config() {
        let config_a = test_agent(true);
        let mut config_b = test_agent(true);
        config_b.max_capacity = 50_000; // Different capacity

        let m_a = PublicManifest::from_agent_config(&config_a, TEST_BUNDLE_HASH);
        let m_b = PublicManifest::from_agent_config(&config_b, TEST_BUNDLE_HASH);
        assert_ne!(m_a.manifest_hash, m_b.manifest_hash);
    }

    #[test]
    fn test_manifest_hash_changes_with_identity_binding() {
        let config_bound = test_agent(true);
        let config_unbound = test_agent(false);

        let m_bound = PublicManifest::from_agent_config(&config_bound, TEST_BUNDLE_HASH);
        let m_unbound = PublicManifest::from_agent_config(&config_unbound, TEST_BUNDLE_HASH);
        assert_ne!(m_bound.manifest_hash, m_unbound.manifest_hash);
    }

    #[test]
    fn test_manifest_hash_changes_with_policy_bundle() {
        // Regression test for GPT audit finding #2: manifest hash must flip
        // when the effective-policy bundle (domains/intents/allowlist) changes,
        // even if the per-agent config is identical.
        let config = test_agent(true);
        let m_bundle_a = PublicManifest::from_agent_config(&config, "bundle-hash-A");
        let m_bundle_b = PublicManifest::from_agent_config(&config, "bundle-hash-B");
        assert_ne!(m_bundle_a.manifest_hash, m_bundle_b.manifest_hash);
        assert_ne!(m_bundle_a.policy_bundle_hash, m_bundle_b.policy_bundle_hash);
    }

    #[test]
    fn test_policy_bundle_hash_exposed() {
        // The embedded bundle hash must be independently readable, so external
        // auditors can verify the bundle out-of-band.
        let config = test_agent(false);
        let manifest = PublicManifest::from_agent_config(&config, TEST_BUNDLE_HASH);
        assert_eq!(manifest.policy_bundle_hash(), TEST_BUNDLE_HASH);
    }

    #[test]
    fn test_domains_sorted_in_manifest() {
        let config = test_agent(false);
        let manifest = PublicManifest::from_agent_config(&config, TEST_BUNDLE_HASH);

        let keys: Vec<&String> = manifest.domains.keys().collect();
        assert_eq!(keys[0], "fs.write.workspace");
        assert_eq!(keys[1], "http.request");
    }

    #[test]
    fn test_manifest_serializes_cleanly() {
        let config = test_agent(true);
        let manifest = PublicManifest::from_agent_config(&config, TEST_BUNDLE_HASH);
        let json = serde_json::to_string_pretty(&manifest);
        assert!(json.is_ok());
    }
}
