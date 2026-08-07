//! BUNYIP-311: forward the end-user's client IP from the BFF to bunyip-api.
//!
//! bunyip-web is an SSR BFF: the browser talks only to it (through Traefik),
//! and it calls bunyip-api server-to-server over the internal docker network.
//! Without help, bunyip-api sees the BFF process as the peer, so the end-user's
//! browser IP is lost for API-side logging, rate-limiting, and audit.
//!
//! This module closes that gap for the second hop of the trust chain
//! (Traefik -> bunyip-web -> bunyip-api):
//!
//! 1. A per-request middleware ([`forward_client_ip`]) resolves the end-user IP
//!    from the inbound request. It honours the inbound `X-Forwarded-For` /
//!    `X-Real-IP` (set by Traefik) ONLY when bunyip-web's own socket peer is a
//!    configured trusted proxy (`TRUSTED_PROXY_CIDR`, [`Config::trusted_proxies`]).
//!    For any other peer it resolves to `None` and forwards nothing, so a
//!    client hitting the BFF directly cannot spoof its IP into the API's logs.
//! 2. The resolved IP is stashed in a task-local for the duration of the
//!    request. Every outbound `/v1` call in [`crate::api`] reads it via
//!    [`current`] and, when present, sets `X-Forwarded-For` on the reqwest
//!    call. Routing the forward through the three `Api` send paths (JSON,
//!    streaming, multipart) covers every outbound call at one choke point
//!    rather than threading the IP through ~45 handler call sites.
//!
//! bunyip-api then treats bunyip-web as its own trusted proxy (bunyip-web's
//! address must be in bunyip-api's `TRUSTED_PROXY_CIDR`) and reads the
//! forwarded IP as the external client via its `extract_client_ip`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::config::Config;

tokio::task_local! {
    /// The end-user IP resolved for the in-flight request, or `None` when the
    /// inbound peer is not a trusted proxy (so nothing may be forwarded).
    static CLIENT_IP: Option<IpAddr>;

    /// BUNYIP-409: the end-user's browser `User-Agent` for the in-flight
    /// request. Forwarded to bunyip-api so its session rows record a real device
    /// (the server-to-server call would otherwise carry the BFF's HTTP-client UA
    /// or none, leaving sessions as "Unknown device"). Unlike the IP this is not
    /// gated on the trusted proxy: a spoofed UA only mislabels the spoofer's own
    /// session, so there is no cross-user surface to protect.
    static CLIENT_UA: Option<String>;
}

/// The end-user IP resolved for the current request, if any.
///
/// Returns `None` outside a request scope (e.g. the background health-recovery
/// poll) via `try_with`, so callers never panic on a missing task-local.
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
/// outbound API call the handler makes.
pub async fn forward_client_ip(
    State(cfg): State<Arc<Config>>,
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
    let resolved = resolve_forwarded_ip(peer, forwarded_for, real_ip, &cfg.trusted_proxies);

    // BUNYIP-409: capture the browser User-Agent to forward alongside the IP so
    // bunyip-api records the real device on the session row. Bounded to 512
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
/// trusted-proxy CIDR (bunyip-web's ingress, i.e. Traefik). In that case the
/// first `X-Forwarded-For` entry (the original client) is used, falling back to
/// `X-Real-IP`. For every other peer - including when `trusted_proxies` is
/// empty (dev), or when the peer is unknown - this returns `None`: the BFF
/// forwards NO IP rather than fabricating one, so bunyip-api keeps attributing
/// the request to bunyip-web (never to a spoofed value).
pub(crate) fn resolve_forwarded_ip(
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

    /// A request forwarded by a trusted proxy (Traefik) resolves to the
    /// external client in `X-Forwarded-For`, which the BFF forwards to
    /// bunyip-api as the end-user IP.
    #[test]
    fn forwards_client_ip_when_peer_is_trusted_proxy() {
        let proxies = [net("10.0.0.0/8")];
        let resolved = resolve_forwarded_ip(
            Some(ip("10.1.2.3")),          // peer = Traefik, internal IP
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
    /// the BFF fabricates nothing, so bunyip-api attributes to bunyip-web.
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

    fn cfg_with(trusted: Vec<ipnetwork::IpNetwork>) -> Arc<Config> {
        Arc::new(Config {
            bind_addr: "0.0.0.0:4400".into(),
            api_url: "http://localhost:4401".into(),
            api_public_origin: "http://localhost:4401".into(),
            oidc_issuer: "http://localhost:4401".into(),
            app_domain: String::new(),
            community_url: String::new(),
            trusted_proxies: trusted,
            theme_css: None,
            app_name: "Bunyip".into(),
            brand_description: String::new(),
            csp: crate::config::CspConfig::default(),
        })
    }

    /// Handler that reports what `current()` sees, so the test can assert the
    /// task-local the middleware set is visible on the outbound-call code path.
    async fn probe() -> String {
        current()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "none".into())
    }

    fn app(cfg: Arc<Config>) -> Router {
        Router::new()
            .route("/probe", get(probe))
            .layer(axum::middleware::from_fn_with_state(cfg, forward_client_ip))
    }

    async fn body_string(resp: axum::response::Response) -> String {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn middleware_exposes_client_ip_to_handler_for_trusted_peer() {
        let app = app(cfg_with(vec![net("10.0.0.0/8")]));
        let mut req = Request::builder()
            .uri("/probe")
            .header("X-Forwarded-For", "203.0.113.7, 10.1.2.3")
            .body(Body::empty())
            .unwrap();
        // Peer = Traefik inside the trusted range.
        req.extensions_mut()
            .insert(ConnectInfo("10.1.2.3:5000".parse::<SocketAddr>().unwrap()));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(body_string(resp).await, "203.0.113.7");
    }

    #[tokio::test]
    async fn middleware_exposes_no_ip_to_handler_for_untrusted_peer() {
        let app = app(cfg_with(vec![net("10.0.0.0/8")]));
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

    /// Outside any request scope (e.g. the background health poll), `current()`
    /// must not panic and returns `None`.
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
                    cfg_with(vec![]),
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
