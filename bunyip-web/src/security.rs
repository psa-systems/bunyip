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
//! framing. `form-action` is the subtle one: per CSP3 it constrains the ENTIRE
//! redirect chain of a form submission, not just the form's action URL, and
//! Chromium + WebKit enforce that (Firefox only checks the action URL). Two
//! flows submit a form on bunyip-web and then redirect cross-origin, so both
//! redirect families must be whitelisted:
//!
//! - BUNYIP-235 (Stripe): `/membership/subscribe` posts to a same-origin handler
//!   that 302s to `https://checkout.stripe.com/...` (and the billing portal to
//!   `billing.stripe.com`), so both Stripe origins are in `form-action`.
//! - BUNYIP-249 (OIDC login): the `/login` and `/login/2fa` forms post to
//!   bunyip-web and 303 to the OIDC authorize endpoint at
//!   `{api_public_origin}/oauth2/authorize`, which redirects on to the requesting
//!   app's callback under `*.{app_domain}`. So `form-action` must also include
//!   the bunyip-api origin and the child-app wildcard. Without them Chrome/Safari
//!   users with 2FA are stuck on `/login/2fa` (the submit is refused before the
//!   redirect) while Firefox slips through. An earlier note here got this wrong
//!   by assuming the OIDC hop was an unconstrained top-level `Location` redirect;
//!   it is the redirect TARGET of a form POST, which `form-action` does constrain.
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
/// dashboard `EventSource` is not blocked, and in `form-action` so the OIDC
/// login redirect chain is not blocked. `app_domain` is the apex child apps live
/// under; its `*.` wildcard covers the OIDC callback origins in `form-action`.
fn policy(api_public_origin: &str, app_domain: &str) -> String {
    // BUNYIP-249: form-action is checked against the WHOLE submission redirect
    // chain (CSP3), so the OIDC login forms need the authorize origin and the
    // child-app callback wildcard, not just 'self' (see the module docs).
    // `https://*.{app_domain}` also covers `api_public_origin` when the api is on
    // the apex, but the api origin is listed explicitly so an off-apex api still
    // works; the wildcard is omitted in dev where `app_domain` is empty.
    let app_callbacks = if app_domain.is_empty() {
        String::new()
    } else {
        format!(" https://*.{app_domain}")
    };
    format!(
        "default-src 'self'; \
         base-uri 'self'; \
         object-src 'none'; \
         frame-ancestors 'none'; \
         form-action 'self' {api_public_origin}{app_callbacks} https://checkout.stripe.com https://billing.stripe.com; \
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
    let value = HeaderValue::from_str(&policy(&cfg.api_public_origin, &cfg.app_domain))
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
        let p = policy("https://api.example.com", "example.com");
        // Self-by-default, framing locked down, and the inline assets the SSR
        // pages actually emit are allowed.
        assert!(p.contains("default-src 'self'"));
        assert!(p.contains("frame-ancestors 'none'"));
        assert!(p.contains("script-src 'self' 'unsafe-inline'"));
        assert!(p.contains("style-src 'self' 'unsafe-inline'"));
        // The browser-facing api origin is whitelisted for the SSE EventSource.
        assert!(p.contains("connect-src 'self' https://api.example.com"));
        // BUNYIP-249: form-action must allow the OIDC login redirect chain (the
        // authorize origin + the child-app callback wildcard), or Chromium and
        // WebKit block 2FA login - form-action is checked on the redirect chain.
        assert!(p.contains(
            "form-action 'self' https://api.example.com https://*.example.com \
             https://checkout.stripe.com https://billing.stripe.com"
        ));
    }

    #[test]
    fn form_action_omits_child_app_wildcard_without_app_domain() {
        // In dev `app_domain` is empty (loopback IS the public origin), so no
        // `*.` child-app source is emitted - only the api origin is added.
        let p = policy("http://localhost:4401", "");
        assert!(p.contains(
            "form-action 'self' http://localhost:4401 https://checkout.stripe.com https://billing.stripe.com"
        ));
        assert!(
            !p.contains("*."),
            "no wildcard form-action source without app_domain; got: {p}"
        );
    }

    #[test]
    fn policy_connect_src_allows_hibp_for_breach_check() {
        // BUNYIP-240: the live password-breach check on /register +
        // /reset-password runs a fetch() to api.pwnedpasswords.com. Without
        // an explicit connect-src allowance the browser blocks the
        // request and the breach indicator stays stuck pending. Pin the
        // substring so a future tightening surfaces in CI before it ships.
        let p = policy("https://api.example.com", "example.com");
        assert!(
            p.contains("https://api.pwnedpasswords.com"),
            "connect-src must allow the HIBP k-anonymity endpoint; got: {p}"
        );
    }

    #[test]
    fn policy_form_action_allows_stripe_hosted_destinations() {
        // BUNYIP-235: `form-action` MUST include `checkout.stripe.com` and
        // `billing.stripe.com`. The /membership/subscribe form posts to a
        // same-origin handler that 302s to those Stripe-hosted destinations,
        // and per CSP3 the directive applies to redirect targets. Pinning the
        // substring here so a future tightening (dropping back to `'self'`)
        // surfaces in CI before it ships and breaks every Subscribe button.
        let p = policy("https://api.example.com", "example.com");
        assert!(
            p.contains("https://checkout.stripe.com https://billing.stripe.com"),
            "form-action must allow Stripe Checkout + billing portal redirects; got: {p}"
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
