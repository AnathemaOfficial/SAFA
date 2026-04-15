use safa_core::config::DomainPolicy;
use safa_core::slime::*;
use std::sync::Arc;
use std::thread;

#[test]
fn authorizes_valid_domain() {
    let auth = test_authorizer(10000);
    let verdict = auth.try_reserve(&"fs.write.workspace".into(), 10);
    assert!(matches!(verdict, SlimeVerdict::Authorized));
}

#[test]
fn rejects_unknown_domain() {
    let auth = test_authorizer(10000);
    let verdict = auth.try_reserve(&"unknown.domain".into(), 1);
    assert!(matches!(verdict, SlimeVerdict::Impossible));
}

#[test]
fn rejects_disabled_domain() {
    let auth = test_authorizer_with_disabled(10000);
    let verdict = auth.try_reserve(&"fs.write.workspace".into(), 1);
    assert!(matches!(verdict, SlimeVerdict::Impossible));
}

#[test]
fn rejects_over_per_action_limit() {
    let auth = test_authorizer(10000);
    let verdict = auth.try_reserve(&"fs.write.workspace".into(), 101);
    assert!(matches!(verdict, SlimeVerdict::Impossible));
}

#[test]
fn capacity_exhaustion() {
    let auth = test_authorizer(100);
    assert!(matches!(
        auth.try_reserve(&"fs.read.workspace".into(), 50),
        SlimeVerdict::Authorized
    ));
    assert!(matches!(
        auth.try_reserve(&"fs.read.workspace".into(), 50),
        SlimeVerdict::Authorized
    ));
    assert!(matches!(
        auth.try_reserve(&"fs.read.workspace".into(), 1),
        SlimeVerdict::Impossible
    ));
}

#[test]
fn capacity_never_exceeds_max_concurrent() {
    let auth = Arc::new(test_authorizer(1000));
    let mut handles = vec![];

    for _ in 0..100 {
        let auth = Arc::clone(&auth);
        handles.push(thread::spawn(move || {
            auth.try_reserve(&"fs.read.workspace".into(), 10)
        }));
    }

    let authorized_count: usize = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|v| matches!(v, SlimeVerdict::Authorized))
        .count();

    assert_eq!(authorized_count, 100);
    assert_eq!(auth.capacity_used(), 1000);
}

#[test]
fn check_only_does_not_consume_capacity() {
    let auth = test_authorizer(100);
    let verdict = auth.check_only(&"fs.write.workspace".into(), 50);
    assert!(matches!(verdict, SlimeVerdict::Authorized));
    assert_eq!(auth.capacity_used(), 0);
}

#[test]
fn check_only_reports_impossible_when_full() {
    let auth = test_authorizer(10);
    auth.try_reserve(&"fs.read.workspace".into(), 10);
    let verdict = auth.check_only(&"fs.read.workspace".into(), 1);
    assert!(matches!(verdict, SlimeVerdict::Impossible));
}

fn test_authorizer(max_cap: u64) -> P0Authorizer {
    P0Authorizer::new(
        max_cap,
        vec![
            (
                "fs.write.workspace".into(),
                DomainPolicy {
                    enabled: true,
                    max_magnitude_per_action: 100,
                },
            ),
            (
                "fs.read.workspace".into(),
                DomainPolicy {
                    enabled: true,
                    max_magnitude_per_action: 500,
                },
            ),
            (
                "proc.exec.bounded".into(),
                DomainPolicy {
                    enabled: true,
                    max_magnitude_per_action: 50,
                },
            ),
            (
                "net.out.http".into(),
                DomainPolicy {
                    enabled: true,
                    max_magnitude_per_action: 200,
                },
            ),
        ],
    )
}

#[test]
fn test_agent_registry_independent_capacity() {
    use safa_core::config::{AgentConfig, DomainPolicy};
    use safa_core::slime::{AgentRegistry, SlimeAuthorizer, SlimeVerdict};
    use std::collections::HashMap;

    let mut domain_policies = HashMap::new();
    domain_policies.insert(
        "fs.write.workspace".into(),
        DomainPolicy {
            enabled: true,
            max_magnitude_per_action: 100,
        },
    );

    let agents = vec![
        AgentConfig {
            agent_id: "agent_a".into(),
            max_capacity: 500,
            rate_limit_per_window: 60,
            rate_limit_window_secs: 60,
            domain_policies: domain_policies.clone(),
            secret: None,
        },
        AgentConfig {
            agent_id: "agent_b".into(),
            max_capacity: 300,
            rate_limit_per_window: 60,
            rate_limit_window_secs: 60,
            domain_policies: domain_policies.clone(),
            secret: None,
        },
    ];

    let registry = AgentRegistry::new(agents);

    // Agent A can reserve independently
    let auth_a = registry.get("agent_a").unwrap();
    assert_eq!(
        auth_a.try_reserve(&"fs.write.workspace".into(), 100),
        SlimeVerdict::Authorized
    );
    assert_eq!(auth_a.capacity_used(), 100);

    // Agent B is unaffected
    let auth_b = registry.get("agent_b").unwrap();
    assert_eq!(auth_b.capacity_used(), 0);
    assert_eq!(
        auth_b.try_reserve(&"fs.write.workspace".into(), 100),
        SlimeVerdict::Authorized
    );

    // Agent A can exhaust its own budget
    for _ in 0..4 {
        auth_a.try_reserve(&"fs.write.workspace".into(), 100);
    }
    assert_eq!(auth_a.capacity_used(), 500);
    assert_eq!(
        auth_a.try_reserve(&"fs.write.workspace".into(), 1),
        SlimeVerdict::Impossible
    );

    // Agent B still has budget
    assert_eq!(
        auth_b.try_reserve(&"fs.write.workspace".into(), 100),
        SlimeVerdict::Authorized
    );
}

fn test_authorizer_with_disabled(max_cap: u64) -> P0Authorizer {
    P0Authorizer::new(
        max_cap,
        vec![(
            "fs.write.workspace".into(),
            DomainPolicy {
                enabled: false,
                max_magnitude_per_action: 100,
            },
        )],
    )
}
