//! `/auth/callback` - OIDC code-flow callback page.
//!
//! Reads `?code=...&state=...` (snapshotted by `modules::oidc::
//! snapshot_initial_search()` in main.rs before the Router rewrote
//! the URL), verifies state against the `PendingFlow` in
//! sessionStorage, exchanges the code at `/oauth2/token`, persists
//! the tokens, refreshes the AuthContext, and routes to the
//! `return_to` the original `start_login()` recorded.

use dioxus::prelude::*;

use crate::components::layout::AuthShell;
use crate::modules::oidc;
use crate::routes::Route;
use crate::stores::auth::{refresh_auth, use_auth};
use crate::stores::config::OidcConfig;
use crate::stores::tokens::save_tokens;

#[derive(Clone, PartialEq)]
enum State {
    Working,
    Error(String),
}

#[component]
pub fn AuthCallbackPage() -> Element {
    let nav = navigator();
    let auth = use_auth();
    let mut state = use_signal(|| State::Working);

    use_future(move || async move {
        let cfg = OidcConfig::from_env();
        match oidc::complete_login(&cfg).await {
            Ok((tokens, return_to)) => {
                save_tokens(&tokens);
                refresh_auth(auth).await;
                if return_to.is_empty() || return_to == "/" {
                    nav.replace(Route::DashboardPage {});
                } else if return_to.starts_with('/') {
                    // Same-origin relative path. Use the browser to
                    // navigate so the URL bar reflects it; the Router
                    // re-matches on the next render.
                    if let Some(win) = web_sys::window() {
                        let _ = win.location().set_href(&return_to);
                    }
                } else {
                    // Absolute URL (rare; should only happen on the
                    // cross-app SSO bridge in phase 07).
                    if let Some(win) = web_sys::window() {
                        let _ = win.location().set_href(&return_to);
                    }
                }
            }
            Err(e) => state.set(State::Error(format!("{e}"))),
        }
    });

    rsx! {
        AuthShell {
            title: "Signing you in...",
            subtitle: "",
            match state() {
                State::Working => rsx! { p { class: "text-sm", "Completing sign-in..." } },
                State::Error(msg) => rsx! {
                    div { class: "space-y-3",
                        p { class: "text-sm text-red-700", "Sign-in failed: {msg}" }
                        Link { to: Route::LoginPage {}, class: "underline text-sm",
                            "Back to sign in"
                        }
                    }
                },
            }
        }
    }
}
