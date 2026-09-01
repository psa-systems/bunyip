//! The feature switches the BFF reads from bunyip-api (BUNYIP-493).
//!
//! Today that is one flag: organizations and teams. It is an admin switch
//! persisted on `tier_config`, published on the public feature-flags probe
//! (`GET /v1/auth/setup/status`), and installed into the process-wide cell the
//! nav and the flagged routes read (`views::layout::orgs_enabled`). A free
//! function builds the nav list with no access to `AppState`, which is why the
//! value lives in a cell rather than being threaded through every caller - the
//! same reason the Community flag does.
//!
//! Loaded once before the listener binds and re-read on an interval, the same
//! shape `branding` uses, so an admin flipping the switch does not need a
//! restart. A fetch that fails never turns the feature ON: the startup path
//! leaves it dark and logs at `error`, and a later failure keeps the last good
//! value and logs at `warn`.

use std::time::Duration;

use crate::api::{auth as auth_api, Api, ApiError};
use crate::views::layout::install_orgs_enabled;

/// The flag cell is process-wide, so a test that flips it has to be the only
/// one reading it. Every test that installs a value takes this lock first and
/// restores the value it found.
#[cfg(test)]
pub(crate) static FLAG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// How often the BFF re-reads the flags. An admin change is live within one
/// interval; that is documented in the admin help text rather than worked
/// around.
pub const FLAGS_REFRESH_SECS: u64 = 60;

/// Cap on the startup read. Short: an unreachable API must not hold the listener
/// closed, it must serve with the feature dark and keep retrying.
pub const FLAGS_STARTUP_TIMEOUT_SECS: u64 = 5;

/// Read the flags and install them. `true` when a reading was published.
///
/// BUNYIP-555's rule (chrome payloads are read through `AppState`'s TTL caches,
/// never per render) is untouched: this is a startup and interval read of the
/// process-wide flag cell, not a per-request fetch, and no handler calls it.
async fn refresh(api: &Api, startup: bool) -> bool {
    match auth_api::setup_status(api).await {
        Ok(s) => {
            install_orgs_enabled(s.orgs_enabled);
            true
        }
        Err(e) => {
            report(&e, startup);
            false
        }
    }
}

fn report(e: &ApiError, startup: bool) {
    if startup {
        tracing::error!(
            endpoint = "/v1/auth/setup/status",
            status = e.status,
            code = %e.code,
            error = %e.message,
            request_id = ?e.request_id,
            "feature-flag read failed at startup; organizations and teams stay off (their nav \
             entry is hidden and /organizations 404s) until a refresh succeeds"
        );
    } else {
        tracing::warn!(
            endpoint = "/v1/auth/setup/status",
            status = e.status,
            code = %e.code,
            error = %e.message,
            request_id = ?e.request_id,
            "feature-flag refresh failed; keeping the last read values"
        );
    }
}

/// One bounded read before the listener binds, so the first render already has
/// the flags.
pub async fn load_at_startup(api: &Api) {
    let timed_out = || ApiError {
        status: 0,
        code: "TIMEOUT".into(),
        message: format!(
            "the startup feature-flag read did not answer within {FLAGS_STARTUP_TIMEOUT_SECS}s"
        ),
        retry_after: None,
        request_id: None,
    };
    match tokio::time::timeout(
        Duration::from_secs(FLAGS_STARTUP_TIMEOUT_SECS),
        refresh(api, true),
    )
    .await
    {
        Ok(_) => {}
        Err(_) => report(&timed_out(), true),
    }
}

/// Background refresh, so flipping the admin switch reaches the nav and the
/// routes without a restart.
pub fn spawn_refresh(api: Api) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(FLAGS_REFRESH_SECS)).await;
            refresh(&api, false).await;
        }
    });
}
