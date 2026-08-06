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
//! - JavaScript: `script-src 'self'` and nothing else. BUNYIP-424 vendored htmx
//!   and the Font Awesome webfont build into `assets/` and moved every inline
//!   `<script>` body and `on*=` handler into `assets/js/*.js`, so no CDN host
//!   and no `'unsafe-inline'` is needed. The two CDNs that were allowlisted
//!   before (`unpkg.com`, `kit.fontawesome.com`) were a standing
//!   remote-code-execution grant: neither tag could carry SRI, and
//!   `'unsafe-inline'` meant CSP was no barrier to a reflected-XSS bug either.
//!   Keep it that way - server values reach the client as `data-*` attributes,
//!   never as executable JavaScript.
//! - the Google Fonts stylesheet from `fonts.googleapis.com` plus Tailwind's
//!   inline `style=` usage -> `'unsafe-inline'` + host in `style-src`. Styles
//!   are a much smaller exposure than scripts, so BUNYIP-424 deliberately left
//!   this host remote; self-hosting the two Google font families is a separate
//!   change.
//! - font files from `fonts.gstatic.com` (Font Awesome's are now same-origin)
//!   -> `font-src`
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
//! `'unsafe-inline'` is honoured only when no nonce/hash source is present, so
//! the inline `style=` / `<style>` usage above keeps working. `script-src` has
//! no such escape hatch any more: an inline `<script>` or `on*=` attribute added
//! to an SSR page will simply not run. `policy_script_src_is_self_only` and
//! `no_inline_script_or_event_handlers_in_views` (below) fail the build if
//! either half regresses.

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
         font-src 'self' https://fonts.gstatic.com; \
         style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
         script-src 'self'; \
         connect-src 'self' {api_public_origin} https://api.pwnedpasswords.com"
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
            community_url: String::new(),
            trusted_proxies: Vec::new(),
        }
    }

    #[test]
    fn policy_includes_required_directives() {
        let p = policy("https://api.example.com", "example.com");
        // Self-by-default, framing locked down, scripts first-party only, and
        // the inline styles the SSR pages actually emit still allowed.
        assert!(p.contains("default-src 'self'"));
        assert!(p.contains("frame-ancestors 'none'"));
        assert!(p.contains("script-src 'self';"));
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

    /// BUNYIP-424 guard: `script-src` is exactly `'self'`. Any third-party host
    /// or `'unsafe-inline'` creeping back into the directive is a regression to
    /// the pre-BUNYIP-424 policy, where a compromise at either CDN (or any
    /// reflected-XSS bug in an SSR page) executed on the session origin.
    #[test]
    fn policy_script_src_is_self_only() {
        let p = policy("https://api.example.com", "example.com");
        let script_src = p
            .split("; ")
            .find(|d| d.trim_start().starts_with("script-src"))
            .expect("script-src directive present");
        assert_eq!(
            script_src.trim(),
            "script-src 'self'",
            "script-src must stay first-party only; got: {script_src}"
        );
        for banned in [
            "'unsafe-inline'",
            "'unsafe-eval'",
            "https://unpkg.com",
            "https://kit.fontawesome.com",
            "https://ka-f.fontawesome.com",
        ] {
            assert!(
                !script_src.contains(banned),
                "script-src must not allow {banned}; got: {script_src}"
            );
        }
        // The Font Awesome kit CDN is fully gone: it was also in font-src and
        // connect-src to serve the kit's fonts and telemetry.
        assert!(
            !p.contains("fontawesome.com"),
            "no Font Awesome CDN source anywhere in the policy; got: {p}"
        );
        assert!(
            !p.contains("unpkg.com"),
            "no unpkg source anywhere in the policy; got: {p}"
        );
    }

    /// BUNYIP-424 guard: `script-src 'self'` only holds if the SSR pages stop
    /// emitting executable markup. Scan every view/handler source file for the
    /// two shapes the browser would refuse to run under this policy - an inline
    /// `<script>` body and an `on*=` event-handler attribute - plus any
    /// off-origin `<script src>`. Test modules are excluded (they carry hostile
    /// XSS fixtures on purpose); everything above the first `#[cfg(test)]` is
    /// production markup and must stay clean.
    #[test]
    fn no_inline_script_or_event_handlers_in_views() {
        // Event names only; the `on...=` needle is assembled below so this file
        // itself never contains the literal attribute it forbids.
        const HANDLER_EVENTS: &[&str] = &[
            "click",
            "submit",
            "change",
            "input",
            "load",
            "error",
            "keydown",
            "keyup",
            "keypress",
            "focus",
            "blur",
            "mousedown",
            "mouseup",
            "mouseover",
            "mouseenter",
            "mouseleave",
            "toggle",
        ];
        let handler_attrs: Vec<String> =
            HANDLER_EVENTS.iter().map(|e| format!(" on{e}=")).collect();

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sources = Vec::new();
        collect_rs(&root, &mut sources);
        assert!(
            sources.len() > 10,
            "expected to scan the whole src tree, found {} files",
            sources.len()
        );

        let mut offences = Vec::new();
        for path in &sources {
            let text = std::fs::read_to_string(path).expect("source file is readable");
            // Cut the test module: fixtures there deliberately contain hostile
            // `<script>` / `onerror=` strings that never reach a response.
            let prod = match text.find("#[cfg(test)]") {
                Some(i) => &text[..i],
                None => &text[..],
            };
            let rel = path
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap_or(path)
                .display()
                .to_string();
            for (n, line) in prod.lines().enumerate() {
                let no = n + 1;
                // Comments and doc comments discuss these shapes by name; only
                // code emits them.
                if line.trim_start().starts_with("//") {
                    continue;
                }
                for attr in &handler_attrs {
                    // The needle carries a leading space so a JS property
                    // assignment (`xhr.onload=`) is not mistaken for an HTML
                    // attribute.
                    if line.contains(attr.as_str()) {
                        let attr = attr.trim();
                        offences.push(format!("{rel}:{no}: inline event handler `{attr}`"));
                    }
                }
                if line.contains("<script") {
                    offences.push(format!("{rel}:{no}: raw `<script` markup in a string"));
                }
                if let Some(rest) = line.split_once("script {") {
                    if rest.1.trim() != "}" {
                        offences.push(format!("{rel}:{no}: inline `<script>` body"));
                    }
                }
                if line.contains("script src=\"http") {
                    offences.push(format!("{rel}:{no}: off-origin `<script src>`"));
                }
            }
        }
        assert!(
            offences.is_empty(),
            "script-src 'self' forbids inline/off-origin scripts; move the code into \
             bunyip-web/assets/js and wire it with data-* attributes:\n{}",
            offences.join("\n")
        );
    }

    fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("src directory is readable") {
            let path = entry.expect("readable dir entry").path();
            if path.is_dir() {
                collect_rs(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// BUNYIP-487 guard: the removals in this issue must stay removed. The
    /// hardcoded Business tier and its env flag are gone (tiers are defined on
    /// the admin Pricing tiers page), and so is every string that advertised
    /// organizations, which the product does not have. Each needle below was a
    /// real line in `content.rs` / `public.rs` / `config.rs`; reintroducing any
    /// of them fails the build rather than shipping a false claim again.
    #[test]
    fn removed_business_tier_and_org_copy_stay_removed() {
        const BANNED: &[&str] = &[
            // The dead Business tier and the env flag that gated it.
            "show_business_pricing",
            "BUNYIP_SHOW_BUSINESS_PRICING",
            // Copy that claimed orgs, memberships-per-org, or org switching.
            "members per org",
            "Unlimited members and orgs",
            "Org switching and role management",
            "For MSPs running multiple orgs",
            "subscriptions, and orgs",
            "org and membership directory",
            "Orgs and members",
            "switch between orgs without leaving",
            // The trial lengths that were hardcoded instead of read from
            // `tier_config.standard_trial_days`.
            "Start free for 14 days",
            "free for 14 days",
            "14-day trial",
        ];

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sources = Vec::new();
        collect_rs(&root, &mut sources);
        let mut offences = Vec::new();
        for path in &sources {
            let text = std::fs::read_to_string(path).expect("source file is readable");
            let rel = path
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap_or(path)
                .display()
                .to_string();
            for (n, line) in text.lines().enumerate() {
                // This test lists the needles by name; skip itself. Comments
                // elsewhere explain what was removed and why, which is the
                // point: only code and copy are scanned.
                if rel.ends_with("security.rs") || line.trim_start().starts_with("//") {
                    continue;
                }
                for needle in BANNED {
                    if line.contains(needle) {
                        offences.push(format!("{rel}:{}: {needle}", n + 1));
                    }
                }
            }
        }
        assert!(
            offences.is_empty(),
            "BUNYIP-487 removed these; they must not come back:\n{}",
            offences.join("\n")
        );
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
