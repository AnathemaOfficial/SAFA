use crate::errors::AmaError;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

const MAX_KEY_BYTES: usize = 128;

/// Validate Idempotency-Key header format.
pub fn validate_idempotency_key(key: &str) -> Result<Uuid, AmaError> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(AmaError::BadRequest {
            message: "Idempotency-Key must be 1-128 bytes".into(),
        });
    }
    // Parse as UUID v4
    let uuid = Uuid::parse_str(key).map_err(|_| AmaError::BadRequest {
        message: "Idempotency-Key must be a valid UUID v4".into(),
    })?;
    // Verify it's actually version 4
    if uuid.get_version_num() != 4 {
        return Err(AmaError::BadRequest {
            message: "Idempotency-Key must be UUID v4".into(),
        });
    }
    Ok(uuid)
}

/// Status returned when checking the idempotency cache.
#[derive(Debug)]
pub enum IdempotencyStatus {
    /// Key not seen before — proceed with processing.
    New,
    /// Key is currently being processed by another request.
    InFlight,
    /// Key was processed before — return cached result.
    Cached(String),
    /// Cache is full and all entries within TTL — 503.
    Full,
}

#[derive(Debug)]
struct CacheEntry {
    result: Option<String>,
    created_at: Instant,
    in_flight: bool,
}

/// Idempotency cache with TTL and fail-closed overflow.
pub struct IdempotencyCache {
    entries: DashMap<Uuid, CacheEntry>,
    max_entries: usize,
    ttl: Duration,
}

impl IdempotencyCache {
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            max_entries,
            ttl,
        }
    }

    /// Check if key exists. If new, insert as in-flight.
    ///
    /// P1 fix: uses DashMap::entry() API for atomic ABSENT → IN_FLIGHT
    /// transition. This guarantees that exactly one thread wins execution
    /// ownership under concurrent submission (Invariant I1/I2).
    ///
    /// IMPORTANT: No calls to self.entries.len(), self.entries.remove(),
    /// or self.purge_expired() may occur while an entry() lock is held,
    /// as DashMap shard locks are not reentrant and this would deadlock.
    pub fn check_or_insert(&self, key: Uuid) -> IdempotencyStatus {
        // Purge expired entries and snapshot capacity BEFORE taking
        // the entry lock. This avoids deadlock from calling len() or
        // retain() while holding a shard write-lock.
        self.purge_expired();
        let at_capacity = self.entries.len() >= self.max_entries;

        // Atomic reservation via entry() API — check + insert under
        // the same shard lock. No gap between check and insert.
        match self.entries.entry(key) {
            Entry::Occupied(mut occupied) => {
                let entry = occupied.get();
                if entry.created_at.elapsed() > self.ttl {
                    // Expired — overwrite in-place as new IN_FLIGHT.
                    // We reuse the occupied slot to avoid dropping the
                    // lock and re-acquiring (which would create a race).
                    let entry = occupied.get_mut();
                    entry.result = None;
                    entry.created_at = Instant::now();
                    entry.in_flight = true;
                    IdempotencyStatus::New
                } else if entry.in_flight {
                    IdempotencyStatus::InFlight
                } else if let Some(ref result) = entry.result {
                    IdempotencyStatus::Cached(result.clone())
                } else {
                    // Defensive: in_flight=false but no result
                    IdempotencyStatus::InFlight
                }
            }
            Entry::Vacant(vacant) => {
                // Check capacity (fail-closed: 503 if full).
                // Uses pre-computed snapshot to avoid deadlock.
                if at_capacity {
                    return IdempotencyStatus::Full;
                }

                // Atomic ABSENT → IN_FLIGHT: we are the sole owner
                vacant.insert(CacheEntry {
                    result: None,
                    created_at: Instant::now(),
                    in_flight: true,
                });
                IdempotencyStatus::New
            }
        }
    }

    /// Mark a key as completed with its cached result.
    pub fn complete(&self, key: Uuid, result: String) {
        if let Some(mut entry) = self.entries.get_mut(&key) {
            entry.in_flight = false;
            entry.result = Some(result);
        }
    }

    /// Remove a key from the cache.
    ///
    /// WARNING (P1): Under Model A, all terminal outcomes (including
    /// failures, timeouts, denials) should be committed via complete(),
    /// NOT removed. This method should only be used for internal cleanup
    /// (e.g., TTL eviction). Using remove() after a failure allows
    /// duplicate execution on retry, violating Invariant I2.
    pub fn remove(&self, key: &Uuid) {
        self.entries.remove(key);
    }

    /// Purge entries beyond TTL.
    fn purge_expired(&self) {
        let now = Instant::now();
        self.entries
            .retain(|_, entry| now.duration_since(entry.created_at) < self.ttl);
    }

    /// Current cache size (for /ama/status).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
