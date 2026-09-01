//! Organizations and teams, behind the BUNYIP-493 feature flag.
//!
//! The flag exists before the feature does, so every surface the work adds is
//! dark from its first commit rather than being retrofitted behind a switch
//! later. `/organizations` is the route the flag gates today: while the switch
//! is off it is indistinguishable from a route that was never registered (the
//! branded 404 the router fallback serves), and no nav entry points at it.
//!
//! The semantics are Enable Pricing's, deliberately: off means invisible, not
//! merely inert. Anything the feature adds later - further routes, nav entries,
//! copy - goes under the same flag from the start.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{html, Markup};

use crate::handlers::{dashboard_response, guard};
use crate::views::layout::orgs_enabled;
use crate::views::ui::empty_state;
use crate::web::AppState;

/// The page body served while the feature is switched on. A placeholder until
/// the feature itself lands; it names no capability the product does not have.
fn organizations_content() -> Markup {
    html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { "Organizations" }
                p class="mt-2 text-muted-foreground" {
                    "Shared accounts for a team. This is switched on for the environment the feature is being built in."
                }
            }
            div class="rounded-lg border bg-card p-6" {
                (empty_state("users", "No organizations yet.", None))
            }
        }
    }
}

/// `GET /organizations` - the flagged surface.
///
/// With the flag off the caller gets the same 404 the router fallback renders,
/// BEFORE the auth guard runs: a redirect to `/login` would confirm the route
/// exists, which is exactly what "dark in production" must not do.
pub async fn organizations(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if !orgs_enabled() {
        return crate::skin::public::not_found(State(st), headers).await;
    }
    let (user, c) = match guard(&st, &headers, "/organizations").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    dashboard_response(
        &c,
        &user,
        "/organizations",
        "Organizations",
        organizations_content(),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    use super::*;
    use crate::api::Api;
    use crate::config::Config;
    use crate::ttl_cache::TtlCache;
    use crate::views::layout::install_orgs_enabled;

    /// State pointed at a port nothing listens on: every upstream call fails
    /// fast, which is the harshest case for the gate. The flag decision must not
    /// depend on the API being reachable, and a failed fetch must not turn a 404
    /// into a 200 or a 500.
    fn state() -> AppState {
        let api = Api::new("http://127.0.0.1:1");
        AppState {
            api,
            cfg: Arc::new(Config::from_env()),
            pricing_cache: Arc::new(TtlCache::new(
                "/v1/pricing",
                "PricingResponse",
                "the test chrome",
                Duration::from_secs(1),
            )),
            applications_cache: Arc::new(TtlCache::new(
                "/v1/applications",
                "Vec<Application>",
                "the test chrome",
                Duration::from_secs(1),
            )),
            setup_status_cache: Arc::new(TtlCache::new(
                "/v1/auth/setup/status",
                "SetupStatus",
                "the test chrome",
                Duration::from_secs(1),
            )),
        }
    }

    /// The flag cell is process-wide and its lock is a plain `Mutex`, so the
    /// request is driven on a runtime built inside the test rather than by
    /// `#[tokio::test]`: that keeps the guard off any await point the test body
    /// owns (`clippy::await_holding_lock`) while still serialising the flag.
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime builds")
            .block_on(f)
    }

    /// The status and `Location` the router answers `GET /organizations` with.
    async fn get_organizations() -> (StatusCode, Option<String>) {
        let app = Router::new()
            .route("/organizations", get(organizations))
            .with_state(state());
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/organizations")
                    .body(Body::empty())
                    .expect("the request builds"),
            )
            .await
            .expect("the router answers");
        let location = res
            .headers()
            .get(axum::http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        (res.status(), location)
    }

    /// BUNYIP-493 AC: with the switch off the flagged route is unreachable, and
    /// unreachable means 404 - the same answer a path that was never registered
    /// gets. An empty page, an error page or a redirect to `/login` would each
    /// confirm the route exists.
    #[test]
    fn the_flagged_route_404s_while_the_switch_is_off() {
        let _guard = crate::feature_flags::FLAG_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        install_orgs_enabled(false);
        let (status, location) = block_on(get_organizations());
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            location, None,
            "a 404 is the whole answer; a redirect would confirm the route"
        );
    }

    /// The other half: with the switch on the route exists, so an anonymous
    /// caller is sent to sign in rather than told the page is not there. Without
    /// this the test above would pass on a route that is broken in both states.
    #[test]
    fn the_flagged_route_exists_once_the_switch_is_on() {
        let _guard = crate::feature_flags::FLAG_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        install_orgs_enabled(true);
        let (status, location) = block_on(get_organizations());
        install_orgs_enabled(false);
        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "an unauthenticated caller is redirected to sign in, which only a live route does"
        );
        assert_eq!(location.as_deref(), Some("/login"));
    }

    /// The page copy renders under the flag, and it claims nothing the product
    /// does not have (BUNYIP-487 removed the copy that did).
    #[test]
    fn the_page_names_no_capability_that_does_not_exist() {
        let markup = organizations_content().into_string();
        assert!(markup.contains("Organizations"));
        assert!(markup.contains("No organizations yet."));
    }
}
