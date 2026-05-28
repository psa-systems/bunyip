use dioxus::prelude::*;

mod api;
mod components;
mod modules;
mod pages;
mod routes;
mod stores;

use components::feedback::FeedbackLauncher;
use components::toast::ToastViewport;
use routes::Route;
use stores::auth::{use_auth_provider, use_bfcache_invalidator};
use stores::config::OidcConfig;
use stores::toast::use_toast_provider;

const STYLES_CSS: Asset = asset!("/assets/styles.css");

fn main() {
    // The OIDC code-flow callback arrives at `/auth/callback?code=...
    // &state=...`. Dioxus's router calls `history.replaceState()` on
    // mount and would erase the query string before `AuthCallbackPage`
    // can read it. Snapshot once here so the page can still find the
    // values when it runs.
    modules::oidc::snapshot_initial_search();
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    // Fetch the same-origin `/config.json` once before any auth-dependent
    // UI mounts. `OidcConfig::from_env()` is synchronous and read all over
    // the tree, so the real app (providers + Router) only mounts once the
    // config is loaded. The static `index.html` splash stays visible until
    // then because `#main` has no children while this resource is pending.
    let config = use_resource(|| async { OidcConfig::load().await });

    rsx! {
        document::Stylesheet { href: STYLES_CSS }
        if config.read().is_some() {
            AppShell {}
        }
    }
}

#[component]
fn AppShell() -> Element {
    use_toast_provider();
    use_auth_provider();
    use_bfcache_invalidator();

    rsx! {
        Router::<Route> {}
        FeedbackLauncher {}
        ToastViewport {}
    }
}
