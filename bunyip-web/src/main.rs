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
use stores::auth::use_auth_provider;
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
    use_toast_provider();
    use_auth_provider();

    rsx! {
        document::Stylesheet { href: STYLES_CSS }
        Router::<Route> {}
        FeedbackLauncher {}
        ToastViewport {}
    }
}
