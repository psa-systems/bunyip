//! Client-IP forwarding for an SSR BFF (BUNYIP-311; lifted to web-kit in
//! BUNYIP-589).
//!
//! A BFF is the only thing the browser talks to (through an edge proxy), and it
//! calls its backend API server-to-server. Without help the backend sees the
//! BFF process as the peer, so the end-user's browser IP is lost for API-side
//! logging, rate-limiting, and audit.
//!
//! This module closes that gap for the second hop of the trust chain
//! (edge proxy -> BFF -> backend API):
//!
//! 1. A per-request middleware ([`forward_client_ip`]) resolves the end-user IP
//!    from the inbound request. It honours the inbound `X-Forwarded-For` /
//!    `X-Real-IP` (set by the edge proxy) ONLY when the BFF's own socket peer is
//!    one of the trusted-proxy CIDRs passed in as state. For any other peer it
//!    resolves to `None` and forwards nothing, so a client hitting the BFF
//!    directly cannot spoof its IP into the API's logs.
//! 2. The resolved IP is stashed in a task-local for the duration of the
//!    request. The consumer's outbound API calls read it via [`current`] and,
//!    when present, set `X-Forwarded-For` on the call. Routing the forward
//!    through the outbound send paths covers every call at one choke point
//!    rather than threading the IP through every handler call site.
//!
//! The backend then treats the BFF as its own trusted proxy and reads the
//! forwarded IP as the external client.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;

tokio::task_local! {
    /// The end-user IP resolved for the in-flight request, or `None` when the
    /// inbound peer is not a trusted proxy (so nothing may be forwarded).
    static CLIENT_IP: Option<IpAddr>;

    /// BUNYIP-409: the end-user's browser `User-Agent` for the in-flight
    /// request. Forwarded to the backend so its session rows record a real
    /// device (the server-to-server call would otherwise carry the BFF's
    /// HTTP-client UA or none, leaving sessions as "Unknown device"). Unlike the
    /// IP this is not gated on the trusted proxy: a spoofed UA only mislabels the
    /// spoofer's own session, so there is no cross-user surface to protect.
    static CLIENT_UA: Option<String>;
}

/// The end-user IP resolved for the current request, if any.
///
/// Returns `None` outside a request scope (e.g. a background poll) via
/// `try_with`, so callers never panic on a missing task-local.
pub fn current() -> Option<IpAddr> {
    CLIENT_IP.try_with(|ip| *ip).unwrap_or(None)
}

/// BUNYIP-409: the end-user's browser `User-Agent` for the current request, if
/// any. `None` outside a request scope (never panics).
pub fn current_ua() -> Option<String> {
    CLIENT_UA.try_with(|ua| ua.clone()).unwrap_or(None)
}

/// Axum middleware: resolve the end-user IP once per request and run the rest
/// of the stack inside a task-local scope so [`current`] can see it on every
/// outbound API call the handler makes. The middleware state is the trusted
/// proxy CIDRs (the consumer wires it with `from_fn_with_state`).
pub async fn forward_client_ip(
    State(trusted): State<Arc<Vec<ipnetwork::IpNetwork>>>,
    req: Request,
    next: Next,
) -> Response {
    // Compute the resolved IP from borrows BEFORE moving `req` into `next.run`.
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    let forwarded_for = req
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok());
    let real_ip = req.headers().get("X-Real-IP").and_then(|v| v.to_str().ok());
    let resolved = resolve_forwarded_ip(peer, forwarded_for, real_ip, &trusted);

    // BUNYIP-409: capture the browser User-Agent to forward alongside the IP so
    // the backend records the real device on the session row. Bounded to 512
    // bytes (the API truncates to 256 anyway) so a crafted oversized header
    // cannot bloat the forwarded request.
    let ua = req
        .headers()
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(512).collect::<String>());

    CLIENT_UA
        .scope(ua, CLIENT_IP.scope(resolved, next.run(req)))
        .await
}

/// Pure resolution of the end-user IP to forward, factored out for unit tests.
///
/// The forwarded IP is honoured ONLY when `peer_ip` is inside a configured
/// trusted-proxy CIDR (the BFF's ingress, i.e. the edge proxy). In that case the
/// first `X-Forwarded-For` entry (the original client) is used, falling back to
/// `X-Real-IP`. For every other peer - including when `trusted_proxies` is
/// empty (dev), or when the peer is unknown - this returns `None`: the BFF
/// forwards NO IP rather than fabricating one, so the backend keeps attributing
/// the request to the BFF (never to a spoofed value).
pub fn resolve_forwarded_ip(
    peer_ip: Option<IpAddr>,
    forwarded_for: Option<&str>,
    real_ip: Option<&str>,
    trusted_proxies: &[ipnetwork::IpNetwork],
) -> Option<IpAddr> {
    let peer_is_trusted_proxy = match peer_ip {
        Some(peer) => trusted_proxies.iter().any(|net| net.contains(peer)),
        None => false,
    };

    if !peer_is_trusted_proxy {
        return None;
    }

    // X-Forwarded-For: the first entry is the original client.
    if let Some(first_ip) = forwarded_for.and_then(|s| s.split(',').next()) {
        if let Ok(ip) = first_ip.trim().parse() {
            return Some(ip);
        }
    }

    // X-Real-IP fallback (still only from a trusted proxy).
    real_ip.and_then(|s| s.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> ipnetwork::IpNetwork {
        s.parse().unwrap()
    }

    /// A request forwarded by a trusted proxy resolves to the external client in
    /// `X-Forwarded-For`, which the BFF forwards to the backend as the end-user
    /// IP.
    #[test]
    fn forwards_client_ip_when_peer_is_trusted_proxy() {
        let proxies = [net("10.0.0.0/8")];
        let resolved = resolve_forwarded_ip(
            Some(ip("10.1.2.3")),          // peer = proxy, internal IP
            Some("203.0.113.7, 10.1.2.3"), // XFF: real client first
            None,
            &proxies,
        );
        assert_eq!(resolved, Some(ip("203.0.113.7")));
    }

    /// `X-Real-IP` is the fallback when a trusted proxy sets it without XFF.
    #[test]
    fn falls_back_to_real_ip_from_trusted_proxy() {
        let proxies = [net("10.0.0.0/8")];
        let resolved =
            resolve_forwarded_ip(Some(ip("10.1.2.3")), None, Some("203.0.113.7"), &proxies);
        assert_eq!(resolved, Some(ip("203.0.113.7")));
    }

    /// A direct (untrusted) client forging `X-Forwarded-For` is not forwarded:
    /// the BFF fabricates nothing, so the backend attributes to the BFF.
    #[test]
    fn forwards_nothing_when_peer_is_untrusted() {
        let proxies = [net("10.0.0.0/8")];
        let resolved = resolve_forwarded_ip(
            Some(ip("198.51.100.9")), // peer is NOT a trusted proxy
            Some("203.0.113.7"),      // forged XFF
            None,
            &proxies,
        );
        assert_eq!(
            resolved, None,
            "spoofed XFF from an untrusted peer must not be forwarded"
        );
    }

    /// With no trusted proxies configured (dev default), forwarding headers are
    /// never honoured and nothing is forwarded - dev behaviour is unchanged.
    #[test]
    fn forwards_nothing_when_no_trusted_proxies_configured() {
        let resolved = resolve_forwarded_ip(Some(ip("203.0.113.7")), Some("1.2.3.4"), None, &[]);
        assert_eq!(resolved, None);
    }

    /// An unknown socket peer (no ConnectInfo) is never treated as trusted.
    #[test]
    fn forwards_nothing_when_peer_unknown() {
        let proxies = [net("10.0.0.0/8")];
        let resolved = resolve_forwarded_ip(None, Some("203.0.113.7"), None, &proxies);
        assert_eq!(resolved, None);
    }

    // ---- Middleware wiring: proves the resolved IP reaches `current()` inside
    // the handler (the task-local set by the middleware survives `next.run`).

    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    /// Handler that reports what `current()` sees, so the test can assert the
    /// task-local the middleware set is visible on the outbound-call code path.
    async fn probe() -> String {
        current()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "none".into())
    }

    fn app(trusted: Vec<ipnetwork::IpNetwork>) -> Router {
        Router::new()
            .route("/probe", get(probe))
            .layer(axum::middleware::from_fn_with_state(
                Arc::new(trusted),
                forward_client_ip,
            ))
    }

    async fn body_string(resp: axum::response::Response) -> String {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn middleware_exposes_client_ip_to_handler_for_trusted_peer() {
        let app = app(vec![net("10.0.0.0/8")]);
        let mut req = Request::builder()
            .uri("/probe")
            .header("X-Forwarded-For", "203.0.113.7, 10.1.2.3")
            .body(Body::empty())
            .unwrap();
        // Peer = proxy inside the trusted range.
        req.extensions_mut()
            .insert(ConnectInfo("10.1.2.3:5000".parse::<SocketAddr>().unwrap()));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(body_string(resp).await, "203.0.113.7");
    }

    #[tokio::test]
    async fn middleware_exposes_no_ip_to_handler_for_untrusted_peer() {
        let app = app(vec![net("10.0.0.0/8")]);
        let mut req = Request::builder()
            .uri("/probe")
            .header("X-Forwarded-For", "203.0.113.7") // forged
            .body(Body::empty())
            .unwrap();
        // Peer is NOT in the trusted range.
        req.extensions_mut().insert(ConnectInfo(
            "198.51.100.9:5000".parse::<SocketAddr>().unwrap(),
        ));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(body_string(resp).await, "none");
    }

    /// Outside any request scope (e.g. a background poll), `current()` must not
    /// panic and returns `None`.
    #[test]
    fn current_is_none_outside_request_scope() {
        assert_eq!(current(), None);
    }

    /// BUNYIP-409: the middleware captures the inbound browser User-Agent into
    /// the task-local so `current_ua()` can forward it on outbound API calls.
    #[tokio::test]
    async fn middleware_exposes_user_agent_to_handler() {
        async fn probe_ua() -> String {
            current_ua().unwrap_or_else(|| "none".into())
        }
        let app =
            Router::new()
                .route("/ua", get(probe_ua))
                .layer(axum::middleware::from_fn_with_state(
                    Arc::new(Vec::new()),
                    forward_client_ip,
                ));
        let mut req = Request::builder()
            .uri("/ua")
            .header(
                "User-Agent",
                "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
            )
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo("127.0.0.1:5000".parse::<SocketAddr>().unwrap()));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            body_string(resp).await,
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0"
        );
    }

    /// The UA task-local, like the IP, is absent outside a request scope.
    #[test]
    fn current_ua_is_none_outside_request_scope() {
        assert_eq!(current_ua(), None);
    }
}
