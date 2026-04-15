use crate::config::{AgentConfig, DomainPolicy};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlimeVerdict {
    Authorized,
    Impossible,
}

pub type DomainId = String;

pub trait SlimeAuthorizer: Send + Sync {
    fn try_reserve(&self, domain_id: &DomainId, magnitude: u64) -> SlimeVerdict;
    fn check_only(&self, domain_id: &DomainId, magnitude: u64) -> SlimeVerdict;
    fn capacity_used(&self) -> u64;
    fn capacity_max(&self) -> u64;
    fn session_id(&self) -> &Uuid;
}

pub struct P0Authorizer {
    capacity: AtomicU64,
    max_capacity: u64,
    domains: HashMap<DomainId, DomainPolicy>,
    session_id: Uuid,
}

impl P0Authorizer {
    pub fn new(max_capacity: u64, domains: Vec<(DomainId, DomainPolicy)>) -> Self {
        Self {
            capacity: AtomicU64::new(0),
            max_capacity,
            domains: domains.into_iter().collect(),
            session_id: Uuid::new_v4(),
        }
    }

    fn check_policy(
        &self,
        domain_id: &DomainId,
        magnitude: u64,
    ) -> Result<&DomainPolicy, SlimeVerdict> {
        let policy = match self.domains.get(domain_id) {
            Some(p) => p,
            None => return Err(SlimeVerdict::Impossible),
        };
        if !policy.enabled {
            return Err(SlimeVerdict::Impossible);
        }
        if magnitude > policy.max_magnitude_per_action {
            return Err(SlimeVerdict::Impossible);
        }
        Ok(policy)
    }
}

impl SlimeAuthorizer for P0Authorizer {
    fn try_reserve(&self, domain_id: &DomainId, magnitude: u64) -> SlimeVerdict {
        if let Err(v) = self.check_policy(domain_id, magnitude) {
            return v;
        }
        loop {
            let current = self.capacity.load(Ordering::Acquire);
            match current.checked_add(magnitude) {
                Some(new) if new <= self.max_capacity => {
                    match self.capacity.compare_exchange_weak(
                        current,
                        new,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return SlimeVerdict::Authorized,
                        Err(_) => continue,
                    }
                }
                _ => return SlimeVerdict::Impossible,
            }
        }
    }

    fn check_only(&self, domain_id: &DomainId, magnitude: u64) -> SlimeVerdict {
        if let Err(v) = self.check_policy(domain_id, magnitude) {
            return v;
        }
        let current = self.capacity.load(Ordering::Acquire);
        match current.checked_add(magnitude) {
            Some(new) if new <= self.max_capacity => SlimeVerdict::Authorized,
            _ => SlimeVerdict::Impossible,
        }
    }

    fn capacity_used(&self) -> u64 {
        self.capacity.load(Ordering::Acquire)
    }

    fn capacity_max(&self) -> u64 {
        self.max_capacity
    }

    fn session_id(&self) -> &Uuid {
        &self.session_id
    }
}

/// Registry of per-agent P0Authorizer instances with independent capacity counters.
pub struct AgentRegistry {
    agents: HashMap<String, P0Authorizer>,
}

impl AgentRegistry {
    pub fn new(configs: Vec<AgentConfig>) -> Self {
        let mut agents = HashMap::new();
        for config in configs {
            let domains: Vec<(DomainId, DomainPolicy)> =
                config.domain_policies.into_iter().collect();
            let authorizer = P0Authorizer::new(config.max_capacity, domains);
            agents.insert(config.agent_id, authorizer);
        }
        Self { agents }
    }

    pub fn get(&self, agent_id: &str) -> Option<&P0Authorizer> {
        self.agents.get(agent_id)
    }

    pub fn agent_ids(&self) -> Vec<&str> {
        self.agents.keys().map(|s| s.as_str()).collect()
    }

    pub fn len(&self) -> usize {
        self.agents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }
}
