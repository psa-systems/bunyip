//! Shared web plumbing: app state and response builders that relay `Set-Cookie`.

use std::sync::Arc;

use axum::http::header::{HeaderValue, LOCATION, SET_COOKIE};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use maud::Markup;

use crate::api::calls;
use crate::api::types::{Application, DocumentedApp, PricingResponse, SetupStatus};
use crate::api::Api;
use crate::config::Config;
use crate::ttl_cache::TtlCache;

#[derive(Clone)]
pub struct AppState {
    pub api: Api,
    pub cfg: Arc<Config>,
    /// BUNYIP-518: short-TTL cache of the public `/v1/pricing` payload, so a
    /// public page render does not always produce an upstream call (which,
    /// per-render, tripped the rate-limit floor and 404'd `/pricing`).
    pub pricing_cache: Arc<TtlCache<PricingResponse>>,
    /// BUNYIP-555: the public chrome's application list, on the same terms.
    pub applications_cache: Arc<TtlCache<Vec<Application>>>,
    /// BUNYIP-555: the setup-status flags, which bunyip-api answers from process
    /// state without touching a table.
    pub setup_status_cache: Arc<TtlCache<SetupStatus>>,
    /// BUNYIP-635: the applications carrying documentation, read by every
    /// `/docs` render for the section menu. Same terms as the other near-static
    /// payloads: it changes only when an admin publishes a page or deactivates
    /// an application.
    pub documented_apps_cache: Arc<TtlCache<Vec<DocumentedApp>>>,
}

impl AppState {
    /// The public pricing payload for the chrome, coalesced per TTL. A cold
    /// failure falls back to the unpublished default, which hides the `/pricing`
    /// links rather than offering a dead one (BUNYIP-487/518).
    pub async fn pricing(&self) -> PricingResponse {
        self.pricing_cache
            .get_or_fetch(|| calls::pricing(&self.api))
            .await
            .unwrap_or_default()
    }

    /// The application list the PUBLIC chrome renders (footer links), coalesced
    /// per TTL.
    ///
    /// Deliberately fetched WITHOUT the visitor's cookie: `/v1/applications`
    /// lists the same active hosted applications for every caller and varies
    /// only in the per-user `is_accessible` bit, which the public chrome never
    /// reads. Fetching it anonymously is what makes ONE shared cache slot
    /// correct - a per-user payload in a process-wide cache would be served to
    /// the next visitor. The authenticated pages that DO read `is_accessible`
    /// (`/dashboard`, `/applications`) keep their own per-request, cookie-bearing
    /// fetch.
    pub async fn public_applications(&self) -> Vec<Application> {
        self.applications_cache
            .get_or_fetch(|| calls::applications(&self.api, None))
            .await
            .unwrap_or_default()
    }

    /// The applications with published documentation, coalesced per TTL
    /// (BUNYIP-635). `None` only when the cache has never read the list, which
    /// the `/docs` hub renders as "could not load" - never as "no application
    /// has documentation", and never as a menu of dead links.
    pub async fn documented_apps(&self) -> Option<Vec<DocumentedApp>> {
        self.documented_apps_cache
            .get_or_fetch(|| calls::documented_apps(&self.api))
            .await
    }

    /// The setup-status flags, coalesced per TTL. `None` only when the cache has
    /// never read them, so each caller applies its own documented fallback.
    pub async fn setup_status(&self) -> Option<SetupStatus> {
        self.setup_status_cache
            .get_or_fetch(|| crate::api::auth::setup_status(&self.api))
            .await
    }

    /// Whether the subscribe CTA is live. BUNYIP-515: an unreadable setup status
    /// defaults to "payment configured", so a working Stripe account is never
    /// hidden behind a disabled button, but it says so first.
    pub async fn stripe_enabled(&self) -> bool {
        match self.setup_status().await {
            Some(s) => s.stripe_enabled,
            None => {
                tracing::warn!(
                    endpoint = "/v1/auth/setup/status",
                    "assuming payment is configured; the subscribe CTA stays live"
                );
                true
            }
        }
    }
}

fn attach_cookies(resp: &mut Response, cookies: &[String]) {
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            resp.headers_mut().append(SET_COOKIE, v);
        }
    }
}

/// 200 HTML response.
pub fn html(markup: Markup) -> Response {
    Html(markup.into_string()).into_response()
}

/// HTML response with an explicit status (e.g. 404 for the not-found fallback,
/// BUNYIP-186 - the fallback page must carry a real 404, not a soft-404 200).
pub fn html_status(markup: Markup, status: StatusCode) -> Response {
    let mut resp = Html(markup.into_string()).into_response();
    *resp.status_mut() = status;
    resp
}

/// 200 HTML response that also relays refreshed cookies.
pub fn html_cookies(markup: Markup, cookies: &[String]) -> Response {
    let mut resp = Html(markup.into_string()).into_response();
    attach_cookies(&mut resp, cookies);
    resp
}

/// A bare status response that relays refreshed cookies (BUNYIP-473). For
/// fetch-driven endpoints that must not redirect (a redirect would reload and
/// scroll the page), the client only reads `response.ok`.
pub fn status_cookies(status: StatusCode, cookies: &[String]) -> Response {
    let mut resp = status.into_response();
    attach_cookies(&mut resp, cookies);
    resp
}

/// 303 redirect (so a POST -> GET after form submit).
pub fn redirect(path: &str) -> Response {
    let mut resp = StatusCode::SEE_OTHER.into_response();
    resp.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(path).unwrap_or(HeaderValue::from_static("/")),
    );
    resp
}

/// 303 redirect that relays cookies (login/logout).
pub fn redirect_cookies(path: &str, cookies: &[String]) -> Response {
    let mut resp = redirect(path);
    attach_cookies(&mut resp, cookies);
    resp
}

#[cfg(test)]
mod chrome_fetch_guards {
    /// The BFF sources that render chrome (public shell) or read the
    /// setup-status flags, scanned below. Comment lines are dropped before
    /// matching, so the prose in these files can still name the call sites.
    const SOURCES: &[(&str, &str)] = &[
        ("handlers/mod.rs", include_str!("handlers/mod.rs")),
        (
            "handlers/auth_pages.rs",
            include_str!("handlers/auth_pages.rs"),
        ),
        (
            "handlers/dashboard.rs",
            include_str!("handlers/dashboard.rs"),
        ),
        ("skin/content.rs", include_str!("skin/content.rs")),
        ("skin/public.rs", include_str!("skin/public.rs")),
    ];

    /// Lines of `src` that mention `needle`, ignoring comments and everything
    /// from the file's first test module on.
    fn hits<'a>(src: &'a str, needle: &str) -> Vec<&'a str> {
        src.split("#[cfg(test)]")
            .next()
            .expect("split yields a head")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .filter(|l| l.contains(needle))
            .collect()
    }

    /// BUNYIP-555: every read of the three near-static payloads goes through
    /// `AppState`'s TTL caches. A direct per-render fetch is what made normal
    /// browsing exhaust the rate-limit floor, and each one that came back had
    /// swallowed its error into an empty list or an unpublished payload.
    ///
    /// The one exception is deliberate and narrow: `/dashboard` and
    /// `/applications` read the per-user `is_accessible` bit, so they keep a
    /// cookie-bearing fetch that must NOT be shared across visitors.
    #[test]
    fn every_chrome_payload_read_goes_through_the_cache() {
        for (name, src) in SOURCES {
            for needle in [
                "auth_api::setup_status(",
                "api::auth::setup_status(",
                "calls::pricing(",
            ] {
                assert!(
                    hits(src, needle).is_empty(),
                    "{name} fetches {needle} directly; use the AppState TTL cache"
                );
            }
            if *name != "handlers/dashboard.rs" {
                assert!(
                    hits(src, "calls::applications(").is_empty(),
                    "{name} fetches the application list per render; use st.public_applications()"
                );
            }
        }
    }

    /// BUNYIP-555: the handlers that issue several independent upstream calls
    /// issue them concurrently. Serial awaits made a page cost the SUM of its
    /// fetch latencies; `join!` (never `try_join!`, which would collapse the
    /// per-fetch fallbacks into all-or-nothing) makes it the slowest one.
    #[test]
    fn post_guard_fetches_run_concurrently() {
        const FANOUT: &[(&str, &str, &str)] = &[
            (
                "handlers/mod.rs",
                include_str!("handlers/mod.rs"),
                "pub async fn public_ctx(",
            ),
            (
                "handlers/dashboard.rs",
                include_str!("handlers/dashboard.rs"),
                "pub async fn dashboard(",
            ),
            (
                "handlers/dashboard.rs",
                include_str!("handlers/dashboard.rs"),
                "pub async fn applications(",
            ),
            (
                "handlers/dashboard.rs",
                include_str!("handlers/dashboard.rs"),
                "pub async fn membership(",
            ),
            (
                "handlers/dashboard.rs",
                include_str!("handlers/dashboard.rs"),
                "pub async fn settings(",
            ),
        ];
        for (name, src, signature) in FANOUT {
            let start = src
                .find(signature)
                .unwrap_or_else(|| panic!("{name} no longer defines {signature}"));
            let body = &src[start + signature.len()..];
            let end = body.find("\npub async fn ").unwrap_or(body.len());
            let body = &body[..end];
            assert!(
                body.contains("tokio::join!"),
                "{name} {signature} awaits its independent fetches serially"
            );
            assert!(
                !body.contains("tokio::try_join!"),
                "{name} {signature} uses try_join!, which drops the per-fetch fallbacks"
            );
        }
    }
}
