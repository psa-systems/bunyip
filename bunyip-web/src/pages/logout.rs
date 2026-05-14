//! `/logout` - canonical, cross-origin logout endpoint.
//!
//! Any first-party relying party (mokosh-clients today, future apps
//! tomorrow) redirects users here on logout. We do the teardown in
//! one place so the OP-session cookie + the hub's localStorage tokens
//! die together:
//!
//!   1. POST /v1/auth/logout. mokosh-server responds with Set-Cookie
//!      that clears the `.a8n.run`-scoped OP session cookie. The
//!      cross-origin fetch carries `credentials: include` via the
//!      `base_builder` helper, so the browser actually applies the
//!      Set-Cookie.
//!   2. Clear localStorage tokens + drop the auth signal to SignedOut.
//!   3. nav.replace to /login.
//!
//! Relying parties redirect to this page instead of clearing their
//! local tokens and going straight to /login, so the OP session does
//! not survive to silently sign them back in on the next visit.

use dioxus::prelude::*;
use wasm_bindgen::JsValue;

use crate::api;
use crate::routes::Route;
use crate::stores::auth::{self, use_auth};

/// Mirrors the sign-out flow into the browser's DevTools console so a
/// stuck logout is visible without rebuilding with extra tracing.
fn log(msg: &str) {
    web_sys::console::log_1(&JsValue::from_str(msg));
}

#[component]
pub fn LogoutPage() -> Element {
    let auth_sig = use_auth();
    let nav = navigator();

    use_future(move || async move {
        log("sign-out: entering /logout, posting /v1/auth/logout");
        // Best-effort server logout (clears the OP cookie). Ignored
        // on failure: we always tear down local state below.
        let _ = api::auth::logout().await;
        log("sign-out: clearing local tokens + auth signal");
        auth::sign_out(auth_sig);
        log("sign-out: redirecting to /login");
        nav.replace(Route::LoginPage {});
    });

    rsx! {
        div { class: "min-h-screen flex items-center justify-center text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
            "Signing you out..."
        }
    }
}
