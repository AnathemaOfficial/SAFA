use safa_core::idempotency::*;
use std::time::Duration;
use uuid::Uuid;

#[test]
fn validates_uuid_v4_format() {
    assert!(validate_idempotency_key("550e8400-e29b-41d4-a716-446655440000").is_ok());
    assert!(validate_idempotency_key("not-a-uuid").is_err());
    assert!(validate_idempotency_key("").is_err());
}

#[test]
fn rejects_key_over_128_bytes() {
    let long = "a".repeat(129);
    assert!(validate_idempotency_key(&long).is_err());
}

#[test]
fn insert_and_lookup() {
    let cache = IdempotencyCache::new(10_000, Duration::from_secs(300));
    let key = Uuid::new_v4();

    // First insert: should mark as in-flight
    let status = cache.check_or_insert(key);
    assert!(matches!(status, IdempotencyStatus::New));

    // Second check: should detect in-flight
    let status = cache.check_or_insert(key);
    assert!(matches!(status, IdempotencyStatus::InFlight));
}

#[test]
fn returns_cached_result() {
    let cache = IdempotencyCache::new(10_000, Duration::from_secs(300));
    let key = Uuid::new_v4();
    let cached_body = r#"{"status":"authorized"}"#.to_string();

    cache.check_or_insert(key);
    cache.complete(key, cached_body.clone());

    let status = cache.check_or_insert(key);
    match status {
        IdempotencyStatus::Cached(body) => assert_eq!(body, cached_body),
        _ => panic!("expected Cached"),
    }
}

#[test]
fn cache_full_returns_service_unavailable() {
    let cache = IdempotencyCache::new(3, Duration::from_secs(300));

    // Fill the cache
    for _ in 0..3 {
        let key = Uuid::new_v4();
        cache.check_or_insert(key);
        cache.complete(key, "done".into());
    }

    // Next insert should return Full (503)
    let key = Uuid::new_v4();
    let status = cache.check_or_insert(key);
    assert!(matches!(status, IdempotencyStatus::Full));
}

#[test]
fn expired_entries_are_purged() {
    let cache = IdempotencyCache::new(3, Duration::from_millis(10));
    let key = Uuid::new_v4();
    cache.check_or_insert(key);
    cache.complete(key, "done".into());

    // Wait for expiry
    std::thread::sleep(Duration::from_millis(20));

    // Insert should succeed after purge
    let key2 = Uuid::new_v4();
    let status = cache.check_or_insert(key2);
    assert!(matches!(status, IdempotencyStatus::New));
}
