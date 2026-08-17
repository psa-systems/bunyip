//! App-wide "is bunyip-api reachable" state for the BFF (BUNYIP-243).
//!
//! `bunyip-web` is the only thing the browser talks to; it makes
//! server-to-server calls to `bunyip-api` through [`crate::api::Api::send`].
//! When the API is unreachable those calls today degrade silently (empty
//! dashboards, phantom logouts, generic errors). This module gives the BFF a
//! single process-global "API reachable" flag so every rendered page can show
//! one clear "Service unavailable" banner instead.
//!
//! Detection is reactive and free: `Api::send` flips the flag to `false` on a
//! transport failure or a `5xx`, and back to `true` on any real response. A
//! `GlobalSignal`-style process flag (a plain `AtomicBool`) is the right
//! primitive here because the classification happens in `Api::send`, which is a
//! plain async fn outside any request/handler state, and the banner is rendered
//! from the shared `document()` shell which likewise has no handle to per-request
//! state. Recovery is an explicit poll that only runs while down (see
//! [`spawn_recovery_poll`]), so there is zero added traffic while healthy.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use maud::{html, Markup};

/// Process-global "bunyip-api reachable" flag. `true` (reachable) on boot.
static API_REACHABLE: AtomicBool = AtomicBool::new(true);

/// Whether bunyip-api is currently considered reachable.
pub fn is_reachable() -> bool {
    API_REACHABLE.load(Ordering::Relaxed)
}

fn set_reachable(reachable: bool) {
    API_REACHABLE.store(reachable, Ordering::Relaxed);
}

/// Classify a completed API response. Any response at all - even a `4xx` -
/// proves the API is reachable and clears the down state. A `5xx` is treated as
/// "down" per BUNYIP-243 (the server is up but failing, surfaced like an
/// outage). A `4xx` (auth, validation) is NOT "down" and keeps its normal
/// per-handler treatment.
pub fn note_status(status: u16) {
    set_reachable(!(500..600).contains(&status));
}

/// Classify a transport-level failure (connection refused, DNS, timeout: the
/// `reqwest` send error mapped to `ApiError::network` / `status: 0`) as the API
/// being unreachable. This is also the opaque failure the browser console
/// renders as a CORS error on the direct SSE hop even though no CORS
/// misconfiguration exists; on the BFF hop it is simply the API being down.
pub fn note_transport_error() {
    set_reachable(false);
}

/// Full-width "service unavailable" banner, rendered at the top of every page
/// from the shared `document()` shell. Renders nothing while the API is
/// reachable, so healthy pages are unaffected; when down it shows on every
/// page (including `/login`), so an outage that would otherwise look like a
/// phantom logout is clearly communicated. Auto-dismisses on recovery because
/// the next render reads the flag back as reachable.
pub fn banner() -> Markup {
    if is_reachable() {
        return html! {};
    }
    html! {
        div role="status" aria-live="polite"
            class="w-full bg-destructive text-destructive-foreground" {
            div class="container flex items-center justify-center gap-2 py-2 text-sm text-center" {
                span class="font-medium" { "Service unavailable. Reconnecting…" }
            }
        }
    }
}

/// Spawn the background recovery poll. While the API is marked unreachable, this
/// hits bunyip-api `GET /health` (liveness, no auth/DB) on an interval and
/// clears the down state on the first success. While healthy it does nothing
/// (no network), so there is no added traffic in the normal case. Call once at
/// startup with the BFF's configured `api_url`.
pub fn spawn_recovery_poll(api_url: String) {
    let health_url = format!("{}/health", api_url.trim_end_matches('/'));
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            // No network while healthy; detection is reactive in `Api::send`.
            if is_reachable() {
                continue;
            }
            if let Ok(resp) = client.get(&health_url).send().await {
                if resp.status().is_success() {
                    set_reachable(true);
                }
            }
        }
    });
}
