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
//!   (and, at the time, the Font Awesome webfont build) into `assets/` and
//!   moved every inline
//!   `<script>` body and `on*=` handler into `assets/js/*.js`, so no CDN host
//!   and no `'unsafe-inline'` is needed. The two CDNs that were allowlisted
//!   before (`unpkg.com`, `kit.fontawesome.com`) were a standing
//!   remote-code-execution grant: neither tag could carry SRI, and
//!   `'unsafe-inline'` meant CSP was no barrier to a reflected-XSS bug either.
//!   Keep it that way - server values reach the client as `data-*` attributes,
//!   never as executable JavaScript.
//! - Tailwind's inline `style=` usage plus the skin's `:root` block ->
//!   `'unsafe-inline'` in `style-src`, and nothing else. BUNYIP-554 vendored
//!   Inter and JetBrains Mono under `assets/vendor/fonts/`, which is what let
//!   `https://fonts.googleapis.com` come out of `style-src` and
//!   `https://fonts.gstatic.com` out of `font-src`.
//! - font files -> `font-src 'self'`, all same-origin (BUNYIP-424 for Font
//!   Awesome, which BUNYIP-554 then deleted outright; BUNYIP-554 for the two
//!   text families)
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

use crate::config::{Config, CspConfig};

/// Build the Content-Security-Policy header value for the given config.
///
/// `api_public_origin` is the browser-facing bunyip-api origin (the same value
/// the SSE subscriber connects to); it is whitelisted in `connect-src` so the
/// dashboard `EventSource` is not blocked, and in `form-action` so the OIDC
/// login redirect chain is not blocked. `app_domain` is the apex child apps live
/// under; its `*.` wildcard covers the OIDC callback origins in `form-action`.
fn policy(api_public_origin: &str, app_domain: &str, csp: &CspConfig) -> String {
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
    // BUNYIP-503: a skin appends its own hosts to connect-src / form-action only.
    // script-src / default-src / frame-ancestors stay locked (BUNYIP-424).
    let form_extra = appended(&csp.form_action);
    let connect_extra = appended(&csp.connect_src);
    format!(
        "default-src 'self'; \
         base-uri 'self'; \
         object-src 'none'; \
         frame-ancestors 'none'; \
         form-action 'self' {api_public_origin}{app_callbacks} https://checkout.stripe.com https://billing.stripe.com{form_extra}; \
         img-src 'self' data: https:; \
         font-src 'self'; \
         style-src 'self' 'unsafe-inline'; \
         script-src 'self'; \
         connect-src 'self' {api_public_origin} https://api.pwnedpasswords.com{connect_extra}"
    )
}

/// BUNYIP-503: space-prefixed join of a skin's extra CSP hosts, or empty when
/// there are none, so the default policy stays byte-identical.
fn appended(hosts: &[String]) -> String {
    if hosts.is_empty() {
        String::new()
    } else {
        format!(" {}", hosts.join(" "))
    }
}

/// Tower layer that stamps the Content-Security-Policy onto every bunyip-web
/// response that does not already carry one.
///
/// `if_not_present` is intentional: the admin attachment route serves untrusted
/// uploads under a stricter `Content-Security-Policy: sandbox`
/// (`handlers::admin::with_attachment_hardening`), and this default policy must
/// not clobber that hardening.
pub fn csp_layer(cfg: &Config) -> SetResponseHeaderLayer<HeaderValue> {
    let value = HeaderValue::from_str(&policy(&cfg.api_public_origin, &cfg.app_domain, &cfg.csp))
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
            csp: crate::config::CspConfig::default(),
        }
    }

    #[test]
    fn policy_includes_required_directives() {
        let p = policy(
            "https://api.example.com",
            "example.com",
            &crate::config::CspConfig::default(),
        );
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
        let p = policy(
            "https://api.example.com",
            "example.com",
            &crate::config::CspConfig::default(),
        );
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

    /// BUNYIP-554 guard: both Google Fonts origins are gone from the policy.
    /// They were the only remote hosts left in `style-src` / `font-src`, and
    /// they cost two DNS lookups plus two TLS handshakes on the critical path
    /// of every first load. Inter and JetBrains Mono are vendored under
    /// `assets/vendor/fonts/`, so re-adding either grant means a `<link>` to
    /// Google came back with them.
    #[test]
    fn policy_grants_no_google_fonts_origin() {
        let p = policy(
            "https://api.example.com",
            "example.com",
            &crate::config::CspConfig::default(),
        );
        for banned in ["fonts.googleapis.com", "fonts.gstatic.com"] {
            assert!(
                !p.contains(banned),
                "the font families are self-hosted; {banned} must not be granted. got: {p}"
            );
        }
        assert!(p.contains("font-src 'self';"), "got: {p}");
        assert!(p.contains("style-src 'self' 'unsafe-inline';"), "got: {p}");
    }

    /// BUNYIP-554 guard: the render-blocking Google Fonts stylesheet and the
    /// three Font Awesome stylesheets are out of the shared document head, and
    /// the webfont build is deleted from the tree. A `<link>` to either is the
    /// regression this issue removed.
    #[test]
    fn document_head_pulls_no_remote_font_or_icon_stylesheet() {
        let html = crate::views::layout::document("Test", maud::html! {}).into_string();
        // The Font Awesome class needles are assembled at run time so this
        // file's own source does not answer the tree-wide grep that proves
        // those class prefixes are gone.
        for banned in [
            "fonts.googleapis.com".to_string(),
            "fonts.gstatic.com".to_string(),
            "fontawesome".to_string(),
            format!("fa-{}", "solid"),
            format!("fa-{}", "regular"),
            format!("fa-{}", "brands"),
        ] {
            assert!(
                !html.contains(&banned),
                "`{banned}` is back in the shared document head"
            );
        }
        assert!(
            !std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("assets/vendor/fontawesome-6.7.2")
                .exists(),
            "the Font Awesome webfont build is vendored again; views::ui::icon renders the set inline"
        );
        for font in [
            "assets/vendor/fonts/inter-v20-latin.woff2",
            "assets/vendor/fonts/jetbrains-mono-v24-latin.woff2",
        ] {
            assert!(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join(font)
                    .exists(),
                "{font} is missing; the CSP no longer allows the Google fallback"
            );
        }
    }

    // BUNYIP-503: a skin's extra hosts append to connect-src / form-action only,
    // never to the locked-down script-src (BUNYIP-424) or the other directives.
    #[test]
    fn policy_appends_skin_hosts_to_connect_and_form_only() {
        let csp = crate::config::CspConfig {
            connect_src: vec!["https://api.myskin.example".into()],
            form_action: vec!["https://pay.myskin.example".into()],
        };
        let p = policy("https://api.example.com", "example.com", &csp);
        let directive = |name: &str| {
            p.split("; ")
                .find(|d| d.trim_start().starts_with(name))
                .unwrap_or_else(|| panic!("{name} directive present"))
                .trim()
                .to_string()
        };
        assert!(
            directive("connect-src").ends_with("https://api.myskin.example"),
            "skin connect-src host appended; got: {}",
            directive("connect-src")
        );
        assert!(
            directive("form-action").ends_with("https://pay.myskin.example"),
            "skin form-action host appended; got: {}",
            directive("form-action")
        );
        // The lockdown directives never carry the skin hosts.
        assert_eq!(directive("script-src"), "script-src 'self'");
        assert!(!directive("default-src").contains("myskin"));
        assert!(!directive("img-src").contains("myskin"));
    }

    // BUNYIP-503: an empty CspConfig (no skin override) is byte-identical to the
    // pre-config policy, so the default deploy is unchanged.
    #[test]
    fn policy_default_csp_config_is_byte_identical() {
        let with_default = policy(
            "https://api.example.com",
            "example.com",
            &crate::config::CspConfig::default(),
        );
        assert!(with_default.ends_with(
            "connect-src 'self' https://api.example.com https://api.pwnedpasswords.com"
        ));
        assert!(with_default.contains(
            "form-action 'self' https://api.example.com https://*.example.com https://checkout.stripe.com https://billing.stripe.com;"
        ));
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

    /// BUNYIP-615 guard: an empty `catch` body drops the failure with no log,
    /// which the `Error Visibility` rule forbids. BUNYIP-596 removed the shape
    /// from `password.js` and BUNYIP-613 removed the last six from its siblings;
    /// this fails the build on a seventh. The scripts are listed from disk, so a
    /// new one is covered without editing this test.
    #[test]
    fn no_empty_catch_block_in_browser_scripts() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/js");
        let mut scripts: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
            .expect("assets/js is readable")
            .map(|entry| entry.expect("readable dir entry").path())
            .filter(|path| path.extension().is_some_and(|e| e == "js"))
            .collect();
        scripts.sort();
        assert!(
            scripts.len() > 5,
            "expected to scan every browser script, found {}",
            scripts.len()
        );

        let mut offences = Vec::new();
        for path in &scripts {
            let text = std::fs::read_to_string(path).expect("script is readable");
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            for (offset, _) in text.match_indices("catch") {
                // Word boundary, so an identifier ending in `catch` is not the
                // keyword. A leading `.` is kept: `.catch(...)` is a handler too.
                let preceded_by_ident = text[..offset]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '$');
                if preceded_by_ident {
                    continue;
                }
                if let Some(shape) = empty_catch_handler(&text[offset + "catch".len()..]) {
                    offences.push(format!("{name}: {shape} at byte offset {offset}"));
                }
            }
        }
        assert!(
            offences.is_empty(),
            "a swallowed failure is worse than the failure it hides; log the cause \
             (see the `report` helper in these scripts) instead of an empty catch:\n{}",
            offences.join("\n")
        );
    }

    /// Classify the text following a `catch` keyword: `Some(shape)` when the
    /// handler body is empty, covering `catch (e) {}`, bare `catch {}`, and the
    /// promise form `.catch(function (e) {})` / `.catch(() => {})`.
    fn empty_catch_handler(rest: &str) -> Option<&'static str> {
        let rest = rest.trim_start();
        let after_binding = match rest.strip_prefix('(') {
            Some(inner) => {
                let (arg, tail) = split_balanced_parens(inner)?;
                if arg.trim_end().ends_with("{}") {
                    return Some("empty `catch` callback");
                }
                tail
            }
            None => rest,
        };
        let inner = after_binding.trim_start().strip_prefix('{')?;
        inner
            .trim_start()
            .starts_with('}')
            .then_some("empty `catch` body")
    }

    /// Split the text after an opening `(` into its parenthesised content and
    /// the tail after the matching `)`. `None` when the parens never close.
    fn split_balanced_parens(s: &str) -> Option<(&str, &str)> {
        let mut depth = 1usize;
        for (i, c) in s.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some((&s[..i], &s[i + 1..]));
                    }
                }
                _ => {}
            }
        }
        None
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
    ///
    /// BUNYIP-493 decided how this list interacts with the organizations and
    /// teams flag, since the flag can now be switched on: the guard stays
    /// ABSOLUTE, not conditional on the flag. Every needle below is a specific
    /// claim (a membership cap, org switching, an MSP pitch) that the feature
    /// still will not make when it ships, so gating them on the flag would only
    /// let a false claim back in behind a switch. Copy the feature introduces is
    /// written fresh, under the flag from its first commit, and must not reuse
    /// these strings. If one is genuinely wanted back, it is deleted from this
    /// list in the same commit that adds the copy, with the reason, rather than
    /// worked around by splitting or reformatting the string.
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
        let p = policy(
            "http://localhost:4401",
            "",
            &crate::config::CspConfig::default(),
        );
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
        let p = policy(
            "https://api.example.com",
            "example.com",
            &crate::config::CspConfig::default(),
        );
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
        let p = policy(
            "https://api.example.com",
            "example.com",
            &crate::config::CspConfig::default(),
        );
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
