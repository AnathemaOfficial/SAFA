/// P1 Idempotency State Machine Tests
///
/// These tests validate the canonical state machine: ABSENT → IN_FLIGHT → DONE
///
/// Reference: docs/SAFA_IDEMPOTENCY_STATE_MACHINE.md
///
/// Expected behavior on P0 code:
///   - Tests 1, 3, 4, 8: PASS (sequential semantics already work)
///   - Test 2, 7: FAIL (race condition in check-then-insert)
///   - Tests 5, 6: FAIL (P0 uses remove() instead of commit-to-DONE)
use safa_core::idempotency::{IdempotencyCache, IdempotencyStatus};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use uuid::Uuid;

/// Test 1 — Sequential Replay
///
/// POST key=A → New (execute) → complete
/// POST key=A → Cached (replay)
///
/// Validates: ABSENT → IN_FLIGHT → DONE → replay
#[test]
fn test_idempotency_sequential_replay() {
    let cache = IdempotencyCache::new(10_000, Duration::from_secs(300));
    let key = Uuid::new_v4();

    // First request: should be New (ABSENT → IN_FLIGHT)
    let status = cache.check_or_insert(key);
    assert!(
        matches!(status, IdempotencyStatus::New),
        "first request must be New"
    );

    // Complete the action (IN_FLIGHT → DONE)
    cache.complete(key, r#"{"result":"success"}"#.to_string());

    // Second request with same key: must replay (DONE → replay)
    let status = cache.check_or_insert(key);
    match status {
        IdempotencyStatus::Cached(body) => {
            assert_eq!(body, r#"{"result":"success"}"#);
        }
        other => panic!("expected Cached replay, got {:?}", other),
    }
}

/// Test 2 — Concurrent Duplicate (CORE RACE TEST)
///
/// Two threads submit same key simultaneously.
/// Exactly one must get New. The other must get InFlight or Cached.
/// Action must execute exactly once.
///
/// This test MUST FAIL on P0 (check-then-insert race).
#[test]
fn test_idempotency_concurrent_duplicate() {
    let cache = Arc::new(IdempotencyCache::new(10_000, Duration::from_secs(300)));
    let key = Uuid::new_v4();
    let new_count = Arc::new(AtomicUsize::new(0));

    let mut handles = vec![];

    for _ in 0..2 {
        let cache = Arc::clone(&cache);
        let new_count = Arc::clone(&new_count);
        handles.push(std::thread::spawn(move || {
            let status = cache.check_or_insert(key);
            if matches!(status, IdempotencyStatus::New) {
                new_count.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let winners = new_count.load(Ordering::SeqCst);
    assert_eq!(
        winners, 1,
        "INVARIANT I1 VIOLATED: {} threads acquired execution ownership (expected exactly 1)",
        winners
    );
}

/// Test 3 — Duplicate During IN_FLIGHT
///
/// POST key=A → New (action starts, not yet complete)
/// POST key=A → must return InFlight (Policy A)
///
/// Validates: no second execution while first is in progress
#[test]
fn test_idempotency_duplicate_during_inflight() {
    let cache = IdempotencyCache::new(10_000, Duration::from_secs(300));
    let key = Uuid::new_v4();

    // First request acquires ownership
    let status = cache.check_or_insert(key);
    assert!(matches!(status, IdempotencyStatus::New));

    // Do NOT call complete() — action is still in flight

    // Second request while first is executing
    let status = cache.check_or_insert(key);
    assert!(
        matches!(status, IdempotencyStatus::InFlight),
        "duplicate during IN_FLIGHT must return InFlight (Policy A), got {:?}",
        status
    );
}

/// Test 4 — Replay After Success
///
/// Execute action, commit success, then replay.
/// Replay must return identical committed result.
#[test]
fn test_idempotency_replay_after_success() {
    let cache = IdempotencyCache::new(10_000, Duration::from_secs(300));
    let key = Uuid::new_v4();

    // Acquire and complete
    cache.check_or_insert(key);
    let result = r#"{"status":"authorized","output":"file created"}"#.to_string();
    cache.complete(key, result.clone());

    // First replay
    let status = cache.check_or_insert(key);
    match &status {
        IdempotencyStatus::Cached(body) => assert_eq!(body, &result),
        other => panic!("expected Cached, got {:?}", other),
    }

    // Second replay — must be identical
    let status = cache.check_or_insert(key);
    match status {
        IdempotencyStatus::Cached(body) => assert_eq!(body, result),
        other => panic!("expected Cached on second replay, got {:?}", other),
    }
}

/// Test 5 — Replay After Timeout (Model A)
///
/// Action times out → must commit timeout result into DONE.
/// Replay must return the committed timeout, NOT allow re-execution.
///
/// This tests Model A: all terminal outcomes go to DONE.
/// P0 uses remove() on failure, which violates Model A.
#[test]
fn test_idempotency_replay_after_timeout() {
    let cache = IdempotencyCache::new(10_000, Duration::from_secs(300));
    let key = Uuid::new_v4();

    // Acquire execution ownership
    let status = cache.check_or_insert(key);
    assert!(matches!(status, IdempotencyStatus::New));

    // Timeout occurs — Model A says commit the timeout as terminal result
    let timeout_result =
        r#"{"status":"timeout","message":"execution exceeded deadline"}"#.to_string();
    cache.complete(key, timeout_result.clone());

    // Replay after timeout — must return committed timeout, not New
    let status = cache.check_or_insert(key);
    match status {
        IdempotencyStatus::Cached(body) => {
            assert_eq!(
                body, timeout_result,
                "replay must return committed timeout result"
            );
        }
        other => panic!(
            "Model A violation: after timeout commit, replay returned {:?} instead of Cached",
            other
        ),
    }
}

/// Test 6 — Replay After Deterministic Denial (Model A)
///
/// Action denied after acquiring ownership → must commit denial into DONE.
/// Replay must return same denial.
///
/// P0 bug: if remove() is called on denial, key goes back to ABSENT,
/// allowing a second execution attempt.
#[test]
fn test_idempotency_replay_after_denial() {
    let cache = IdempotencyCache::new(10_000, Duration::from_secs(300));
    let key = Uuid::new_v4();

    // Acquire execution ownership
    let status = cache.check_or_insert(key);
    assert!(matches!(status, IdempotencyStatus::New));

    // Denial occurs — Model A says commit the denial as terminal result
    let denial_result = r#"{"status":"denied","reason":"capacity exhausted"}"#.to_string();
    cache.complete(key, denial_result.clone());

    // Replay after denial — must return committed denial, not allow re-execution
    let status = cache.check_or_insert(key);
    match status {
        IdempotencyStatus::Cached(body) => {
            assert_eq!(
                body, denial_result,
                "replay must return committed denial result"
            );
        }
        other => panic!(
            "Model A violation: after denial commit, replay returned {:?} instead of Cached",
            other
        ),
    }
}

/// Test 7 — Many Concurrent Same Key (Stress Race Test)
///
/// 10 threads submit the same key simultaneously.
/// Exactly ONE must get New. All others must get InFlight or Cached.
/// This is the extreme version of Test 2.
///
/// This test MUST FAIL on P0 (check-then-insert race).
#[test]
fn test_idempotency_many_concurrent_same_key() {
    let cache = Arc::new(IdempotencyCache::new(10_000, Duration::from_secs(300)));
    let key = Uuid::new_v4();
    let new_count = Arc::new(AtomicUsize::new(0));
    let num_threads = 10;

    // Use a barrier so all threads start simultaneously
    let barrier = Arc::new(std::sync::Barrier::new(num_threads));
    let mut handles = vec![];

    for _ in 0..num_threads {
        let cache = Arc::clone(&cache);
        let new_count = Arc::clone(&new_count);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait(); // all threads release at the same time
            let status = cache.check_or_insert(key);
            if matches!(status, IdempotencyStatus::New) {
                new_count.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let winners = new_count.load(Ordering::SeqCst);
    assert_eq!(
        winners, 1,
        "INVARIANT I1/I2 VIOLATED: {} threads acquired execution ownership out of {} (expected exactly 1)",
        winners, num_threads
    );
}

/// Test 8 — Different Keys in Parallel
///
/// Multiple threads with DIFFERENT keys must all succeed independently.
/// Idempotency must not block unrelated keys.
#[test]
fn test_idempotency_parallel_different_keys() {
    let cache = Arc::new(IdempotencyCache::new(10_000, Duration::from_secs(300)));
    let new_count = Arc::new(AtomicUsize::new(0));
    let num_threads = 5;

    let barrier = Arc::new(std::sync::Barrier::new(num_threads));
    let mut handles = vec![];

    for _ in 0..num_threads {
        let cache = Arc::clone(&cache);
        let new_count = Arc::clone(&new_count);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let unique_key = Uuid::new_v4(); // each thread gets its own key
            barrier.wait();
            let status = cache.check_or_insert(unique_key);
            if matches!(status, IdempotencyStatus::New) {
                new_count.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let winners = new_count.load(Ordering::SeqCst);
    assert_eq!(
        winners, num_threads,
        "all {} threads with different keys should get New, but only {} did",
        num_threads, winners
    );
}
