//! Request access logging attributed to the external client IP (BUNYIP-328).
//!
//! actix's `Logger::default()` logs `%a`, the immediate socket peer. Behind
//! Traefik that is the proxy's internal IP, so every request line was
//! attributed to the reverse proxy rather than the client that made the
//! request. This builds a `Logger` whose client field is resolved by
//! [`extract_client_ip`], which honours the proxy's `X-Forwarded-For` (and
//! `X-Real-IP`) header ONLY when the peer is a configured trusted proxy
//! (`TRUSTED_PROXY_CIDR`) - the same trusted resolution the rate-limit records
//! already use, so log lines and rate-limit entries point at the same external
//! client.

use actix_web::dev::ServiceRequest;
use actix_web::middleware::Logger;

use crate::middleware::extract_client_ip;

/// Render the external client IP for an access-log line, falling back to `-`
/// (the common-log-format empty field) when it cannot be determined.
fn client_ip_field(req: &ServiceRequest) -> String {
    extract_client_ip(req.request())
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "-".to_string())
}

/// A request access `Logger` that logs the trusted external client IP in place
/// of the socket peer (`%a`). Otherwise it mirrors actix's default format:
/// request line, status, response size, referer, user-agent, and time taken.
pub fn access_logger() -> Logger {
    Logger::new("%{client_ip}xi \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\" %T")
        .custom_request_replace("client_ip", client_ip_field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    /// Without a `Config` in app data no proxy is trusted, so a forged
    /// `X-Forwarded-For` is ignored and the access-log field is the socket peer.
    /// This proves the log field never trusts a spoofed header by default; the
    /// trusted-proxy resolution itself is unit-tested in
    /// `bunyip_domain::middleware::auth`.
    #[test]
    fn access_log_field_ignores_spoofed_xff_without_trusted_proxy_config() {
        let req = TestRequest::default()
            .peer_addr("198.51.100.9:5555".parse().unwrap())
            .insert_header(("X-Forwarded-For", "203.0.113.7"))
            .to_srv_request();
        assert_eq!(client_ip_field(&req), "198.51.100.9");
    }

    /// When the peer address is unavailable the field renders as `-` rather
    /// than panicking or emitting an empty token.
    #[test]
    fn access_log_field_renders_dash_when_peer_unknown() {
        let req = TestRequest::default().to_srv_request();
        assert_eq!(client_ip_field(&req), "-");
    }
}
