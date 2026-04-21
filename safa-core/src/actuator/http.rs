use crate::errors::AmaError;
use crate::newtypes::{AllowlistEntry, AllowlistedUrl, BoundedBytes, HttpMethod};
use reqwest::redirect::Policy;
use std::net::IpAddr;
use std::time::Duration;

const MAX_RESPONSE_BYTES: usize = 262_144; // 256 KiB
const MAX_REDIRECTS: usize = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
const USER_AGENT: &str = "SAFA/0.1.0";

/// Result of an HTTP request.
#[derive(Debug)]
pub struct HttpResult {
    pub status_code: u16,
    pub body: String,
    pub truncated: bool,
}

/// Check if an IP address is private/loopback/link-local/metadata.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()           // 127.0.0.0/8
            || v4.is_private()         // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || v4.is_link_local()      // 169.254.0.0/16 (includes metadata 169.254.169.254)
            || v4.is_broadcast()
            || v4.is_unspecified()
            || v4.octets()[0] == 0 // 0.0.0.0/8
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let is_unique_local = (octets[0] & 0xfe) == 0xfc; // fc00::/7
            let is_link_local = octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80; // fe80::/10
            v6.is_loopback()           // ::1
            || v6.is_unspecified()     // ::
            || is_unique_local
            || is_link_local
            // IPv4-mapped IPv6 addresses
            || v6.to_ipv4_mapped().is_some_and(|v4| {
                v4.is_loopback() || v4.is_private() || v4.is_link_local()
            })
        }
    }
}

/// Resolve hostname and validate all IPs are safe (not private/loopback).
async fn validate_dns(host: &str) -> Result<(), AmaError> {
    use tokio::net::lookup_host;

    let addrs: Vec<_> = lookup_host(format!("{}:443", host))
        .await
        .map_err(|e| AmaError::ServiceUnavailable {
            message: format!("DNS resolution failed: {}", e),
        })?
        .collect();

    if addrs.is_empty() {
        return Err(AmaError::ServiceUnavailable {
            message: "DNS resolved to no addresses".into(),
        });
    }

    for addr in &addrs {
        if is_private_ip(addr.ip()) {
            return Err(AmaError::Validation {
                error_class: "invalid_target".into(),
                message: format!("URL resolves to private/loopback IP: {}", addr.ip()),
            });
        }
    }

    Ok(())
}

/// Execute an HTTP request with full safety checks.
pub async fn http_request(
    method: HttpMethod,
    url: &AllowlistedUrl,
    body: Option<&BoundedBytes>,
    allowlist: &[AllowlistEntry],
) -> Result<HttpResult, AmaError> {
    let url_str = url.as_str();

    // Extract host for DNS validation
    let parsed = reqwest::Url::parse(url_str).map_err(|e| AmaError::Validation {
        error_class: "invalid_target".into(),
        message: format!("invalid URL: {}", e),
    })?;
    let host = parsed.host_str().ok_or_else(|| AmaError::Validation {
        error_class: "invalid_target".into(),
        message: "URL has no host".into(),
    })?;

    // DNS/IP safety check — resolve and validate before connecting
    validate_dns(host).await?;

    // Build reqwest client with safety constraints
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .redirect(Policy::limited(MAX_REDIRECTS))
        .https_only(true) // HTTPS only
        .danger_accept_invalid_certs(false) // TLS validation ON
        .build()
        .map_err(|e| AmaError::ServiceUnavailable {
            message: format!("HTTP client build failed: {}", e),
        })?;

    // Build request
    let request = match method {
        HttpMethod::Get => client.get(url_str),
        HttpMethod::Post => {
            let mut req = client.post(url_str);
            if let Some(body_data) = body {
                req = req
                    .body(body_data.as_str().to_string())
                    .header("Content-Type", "application/json");
            }
            req
        }
    };

    // Execute
    let mut response: reqwest::Response = request.send().await.map_err(|e| {
        if e.is_redirect() {
            AmaError::Validation {
                error_class: "redirect_error".into(),
                message: "redirect limit exceeded or POST redirect rejected".into(),
            }
        } else if e.is_timeout() {
            AmaError::ServiceUnavailable {
                message: "HTTP request timed out".into(),
            }
        } else {
            AmaError::ServiceUnavailable {
                message: format!("HTTP request failed: {}", e),
            }
        }
    })?;

    // Re-validate the actual remote IP after connection (DNS rebinding protection)
    // Post-connect IP revalidation (DNS rebinding guard).
    //
    // Claude audit finding H2 / Copilot audit finding H-01: previously
    // `if let Some(remote_addr) = response.remote_addr()` silently skipped
    // the private-IP check when reqwest could not report the remote
    // address (proxy paths, some TLS configurations, certain redirect
    // chains). An attacker able to force that condition bypassed the
    // DNS-rebinding defence entirely. We now fail-closed when the remote
    // address is unknown — the post-connect check is the only layer that
    // catches a DNS record that rebound between `validate_dns` and the
    // reqwest connect.
    let remote_addr = response.remote_addr().ok_or_else(|| AmaError::Validation {
        error_class: "invalid_target".into(),
        message: "could not determine remote IP for post-connect validation".into(),
    })?;
    let ip = remote_addr.ip();
    if is_private_ip(ip) {
        return Err(AmaError::Validation {
            error_class: "invalid_target".into(),
            message: format!("response came from private IP: {}", ip),
        });
    }

    // Validate final URL against allowlist (after redirects).
    // We revalidate with the ORIGINAL method — this is conservative: if a
    // redirect leads to a URL where only a different method is allowed,
    // the request is rejected (fail-closed). For reqwest's default redirect
    // policy this matches real behavior for 307/308 (method preserved) and is
    // slightly tighter than needed for 301/302/303 (POST -> GET conversion).
    let final_url = response.url().as_str();
    if final_url != url_str {
        let _ = AllowlistedUrl::new(final_url, method, allowlist).map_err(|_| {
            AmaError::Validation {
                error_class: "redirect_error".into(),
                message: "redirect target not in allowlist".into(),
            }
        })?;
    }

    let status_code = response.status().as_u16();

    // Bounded body read (256 KiB max) while streaming chunks from reqwest.
    let mut body_bytes = Vec::with_capacity(MAX_RESPONSE_BYTES.min(8192));
    let mut truncated = false;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| AmaError::ServiceUnavailable {
            message: format!("failed to read response body: {}", e),
        })?
    {
        if append_bounded_bytes(&mut body_bytes, &chunk, MAX_RESPONSE_BYTES) {
            truncated = true;
            break;
        }
    }

    // UTF-8 check (P0 text-only)
    let body_text = String::from_utf8(body_bytes).map_err(|_| AmaError::ServiceUnavailable {
        message: "response body is not valid UTF-8 (P0 is text-only)".into(),
    })?;

    Ok(HttpResult {
        status_code,
        body: body_text,
        truncated,
    })
}

fn append_bounded_bytes(buffer: &mut Vec<u8>, chunk: &[u8], max_bytes: usize) -> bool {
    let remaining = max_bytes.saturating_sub(buffer.len());
    if remaining == 0 {
        return !chunk.is_empty();
    }

    let copy_len = remaining.min(chunk.len());
    buffer.extend_from_slice(&chunk[..copy_len]);
    copy_len < chunk.len()
}

#[cfg(test)]
mod tests {
    use super::append_bounded_bytes;

    #[test]
    fn append_bounded_bytes_keeps_under_cap_payloads() {
        let mut buffer = Vec::new();
        let truncated = append_bounded_bytes(&mut buffer, b"hello", 16);
        assert!(!truncated);
        assert_eq!(buffer, b"hello");
    }

    #[test]
    fn append_bounded_bytes_accepts_exact_cap_without_truncation() {
        let mut buffer = Vec::new();
        assert!(!append_bounded_bytes(&mut buffer, b"hello", 5));
        assert_eq!(buffer, b"hello");
    }

    #[test]
    fn append_bounded_bytes_truncates_when_chunk_overflows_cap() {
        let mut buffer = Vec::new();
        let truncated = append_bounded_bytes(&mut buffer, b"hello world", 5);
        assert!(truncated);
        assert_eq!(buffer, b"hello");
    }

    #[test]
    fn append_bounded_bytes_truncates_when_more_data_arrives_after_full_buffer() {
        let mut buffer = b"hello".to_vec();
        let truncated = append_bounded_bytes(&mut buffer, b"!", 5);
        assert!(truncated);
        assert_eq!(buffer, b"hello");
    }
}
