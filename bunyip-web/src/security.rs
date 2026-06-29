//! Content-Security-Policy for bunyip-web responses (BUNYIP-232).
//!
//! The edge proxy already stamps the other security headers
//! (Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options,
//! Referrer-Policy, Permissions-Policy) onto bunyip-web responses, but it does
//! not set a Content-Security-Policy. This layer fills that gap from inside the
//! app so the policy ships with the binary and tracks the actual asset origins
//! the SSR pages load.
//!
//! The policy is deliberately scoped to what `views::layout` actually pulls in:
//!
//! - inline `<script>` blocks (theme flash/toggle, toast, the SSE subscriber)
//!   and `onclick=` handlers  -> `'unsafe-inline'` in `script-src`
//! - htmx from `unpkg.com`, the Font Awesome kit from `kit.fontawesome.com`
//!   -> host sources in `script-src`
//! - the Google Fonts stylesheet from `fonts.googleapis.com` plus Tailwind's
//!   inline `style=` usage -> `'unsafe-inline'` + host in `style-src`
//! - font files from `fonts.gstatic.com` and the Font Awesome kit CDN
//!   (`ka-f.fontawesome.com`) -> `font-src`
//! - the browser-facing bunyip-api origin the dashboard `EventSource` subscribes
//!   to (`/v1/events`), which is a distinct origin from bunyip-web even in dev
//!   (different port) -> added to `connect-src`
//! - HaveIBeenPwned k-anonymity API (`api.pwnedpasswords.com`) for the
//!   BUNYIP-240 live breach check on `/register` + `/reset-password`. The
//!   browser hashes the password with SHA-1 and sends only the first 5 hex
//!   chars; the full password never leaves the browser -> added to `connect-src`
//!
//! `frame-ancestors 'none'` (with the proxy's `X-Frame-Options: DENY`) blocks
//! framing; `form-action 'self'` keeps form posts on bunyip-web. SSO is driven by
//! top-level navigations (`Location` redirects), which CSP does not constrain, so
//! the OIDC hop to bunyip-api keeps working.
//!
//! Because `'unsafe-inline'` is honoured only when no nonce/hash source is
//! present, the inline scripts/styles above keep executing under this policy.

use axum::http::header::CONTENT_SECURITY_POLICY;
use axum::http::HeaderValue;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::config::Config;

/// Build the Content-Security-Policy header value for the given config.
///
/// `api_public_origin` is the browser-facing bunyip-api origin (the same value
/// the SSE subscriber connects to); it is whitelisted in `connect-src` so the
/// dashboard `EventSource` is not blocked.
fn policy(api_public_origin: &str) -> String {
    format!(
        "default-src 'self'; \
         base-uri 'self'; \
         object-src 'none'; \
         frame-ancestors 'none'; \
         form-action 'self'; \
         img-src 'self' data: https:; \
         font-src 'self' https://fonts.gstatic.com https://ka-f.fontawesome.com; \
         style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
         script-src 'self' 'unsafe-inline' https://unpkg.com https://kit.fontawesome.com; \
         connect-src 'self' {api_public_origin} https://ka-f.fontawesome.com https://api.pwnedpasswords.com"
    )
}

/// Tower layer that stamps the Content-Security-Policy onto every bunyip-web
/// response that does not already carry one.
///
/// `if_not_present` is intentional: the admin attachment route serves untrusted
/// uploads under a stricter `Content-Security-Policy: sandbox`
/// (`handlers::admin::with_attachment_hardening`), and this default policy must
/// not clobber that hardening.
pub fn csp_layer(cfg: &Config) -> SetResponseHeaderLayer<HeaderValue> {
    let value = HeaderValue::from_str(&policy(&cfg.api_public_origin))
        .expect("CSP policy is valid header value");
    SetResponseHeaderLayer::if_not_present(CONTENT_SECURITY_POLICY, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn test_config() -> Config {
        Config {
            bind_addr: "0.0.0.0:4400".into(),
            api_url: "http://localhost:4401".into(),
            api_public_origin: "https://api.example.com".into(),
            oidc_issuer: "http://localhost:4401".into(),
            app_domain: String::new(),
            show_business_pricing: false,
        }
    }

    #[test]
    fn policy_includes_required_directives() {
        let p = policy("https://api.example.com");
        // Self-by-default, framing locked down, and the inline assets the SSR
        // pages actually emit are allowed.
        assert!(p.contains("default-src 'self'"));
        assert!(p.contains("frame-ancestors 'none'"));
        assert!(p.contains("script-src 'self' 'unsafe-inline'"));
        assert!(p.contains("style-src 'self' 'unsafe-inline'"));
        // The browser-facing api origin is whitelisted for the SSE EventSource.
        assert!(p.contains("connect-src 'self' https://api.example.com"));
    }

    #[test]
    fn policy_connect_src_allows_hibp_for_breach_check() {
        // BUNYIP-240: the live password-breach check on /register +
        // /reset-password runs a fetch() to api.pwnedpasswords.com. Without
        // an explicit connect-src allowance the browser blocks the
        // request and the breach indicator stays stuck pending. Pin the
        // substring so a future tightening surfaces in CI before it ships.
        let p = policy("https://api.example.com");
        assert!(
            p.contains("https://api.pwnedpasswords.com"),
            "connect-src must allow the HIBP k-anonymity endpoint; got: {p}"
        );
    }

    /// AC: Content-Security-Policy is present on bunyip-web responses, asserted
    /// the same way the response would be served through the router layer.
    #[tokio::test]
    async fn csp_header_present_on_responses() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(csp_layer(&test_config()));

        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let csp = resp
            .headers()
            .get(CONTENT_SECURITY_POLICY)
            .expect("Content-Security-Policy header present");
        let csp = csp.to_str().unwrap();
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("connect-src 'self' https://api.example.com"));
    }

    /// `if_not_present` must not overwrite a handler-set CSP (e.g. the admin
    /// attachment `sandbox` policy).
    #[tokio::test]
    async fn csp_layer_does_not_clobber_existing_policy() {
        let app = Router::new()
            .route(
                "/attachment",
                get(|| async { ([(CONTENT_SECURITY_POLICY, "sandbox")], "file") }),
            )
            .layer(csp_layer(&test_config()));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/attachment")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let csp = resp.headers().get(CONTENT_SECURITY_POLICY).unwrap();
        assert_eq!(csp.to_str().unwrap(), "sandbox");
    }
}
