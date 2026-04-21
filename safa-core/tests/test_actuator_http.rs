use safa_core::actuator::http::*;

#[tokio::test]
async fn rejects_loopback_ip() {
    assert!(is_private_ip("127.0.0.1".parse().unwrap()));
    assert!(is_private_ip("::1".parse().unwrap()));
}

#[tokio::test]
async fn rejects_rfc1918() {
    assert!(is_private_ip("10.0.0.1".parse().unwrap()));
    assert!(is_private_ip("192.168.1.1".parse().unwrap()));
    assert!(is_private_ip("172.16.0.1".parse().unwrap()));
}

#[tokio::test]
async fn rejects_link_local() {
    assert!(is_private_ip("169.254.1.1".parse().unwrap()));
    assert!(is_private_ip("fe80::1".parse().unwrap()));
    assert!(is_private_ip("febf::1".parse().unwrap()));
}

#[tokio::test]
async fn rejects_ipv6_unique_local() {
    assert!(is_private_ip("fc00::1".parse().unwrap()));
    assert!(is_private_ip("fd12:3456:789a::1".parse().unwrap()));
}

#[tokio::test]
async fn accepts_public_ip() {
    assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
    assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
    assert!(!is_private_ip("2001:4860:4860::8888".parse().unwrap()));
}

#[tokio::test]
async fn rejects_metadata_endpoint() {
    assert!(is_private_ip("169.254.169.254".parse().unwrap()));
}
