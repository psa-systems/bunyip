//! Admin-managed product branding for the BFF (BUNYIP-561).
//!
//! The product name, tagline, meta description and Open Graph image are a
//! database record edited on the admin panel, served by bunyip-api at
//! `GET /v1/branding`. Nothing here substitutes a compiled-in literal: an empty
//! field means the corresponding markup is omitted, which is what keeps product
//! copy out of the binary.
//!
//! `views::layout::document()` is a free function called from every page and
//! has no access to `AppState`, so the values live in a process-global cache
//! (the same shape `SSE_API_ORIGIN` and the theme override already use) rather
//! than being threaded through every handler signature. It is loaded once at
//! startup before the listener binds and refreshed on an interval, so an admin
//! edit is visible within [`BRANDING_REFRESH_SECS`].

use std::future::Future;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use serde_json::Value;

use crate::api::types::Branding;
use crate::api::{ok_data, parse, Api, ApiError};

/// How often the BFF re-reads `/v1/branding`. An admin edit is visible within
/// one interval; that is documented rather than worked around.
pub const BRANDING_REFRESH_SECS: u64 = 60;

/// Cap on the startup fetch. Short: an unreachable API must not hold the
/// listener closed, it must serve unbranded and keep retrying.
pub const BRANDING_STARTUP_TIMEOUT_SECS: u64 = 5;

/// What a refresh decided to serve, so the failure paths are assertable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrandingSource {
    /// A fetch succeeded and was stored.
    Fetched,
    /// A fetch failed; the last values the cache read are kept.
    StaleOnError,
    /// A fetch failed and the cache has never read anything, so the page
    /// renders unbranded (no name substituted, every optional tag omitted).
    UnbrandedOnError,
}

/// Last-good branding. `None` until the first successful fetch, which renders
/// as fully unbranded chrome rather than as bunyip's old literals.
pub struct BrandingCache {
    slot: RwLock<Option<Arc<Branding>>>,
}

/// The unbranded value every reader shares before anything has been loaded.
fn unbranded() -> Arc<Branding> {
    static UNBRANDED: OnceLock<Arc<Branding>> = OnceLock::new();
    Arc::clone(UNBRANDED.get_or_init(|| Arc::new(Branding::default())))
}

impl BrandingCache {
    pub const fn new() -> Self {
        Self {
            slot: RwLock::new(None),
        }
    }

    /// The current values, or the unbranded default when nothing has loaded.
    pub fn get(&self) -> Arc<Branding> {
        // A poisoned lock means a writer panicked; the data is structurally
        // intact, so recover through the poison rather than taking the process
        // down over a branding string.
        match self.slot.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(b) => Arc::clone(b),
            None => unbranded(),
        }
    }

    /// Publish values directly (startup path and tests).
    pub fn install(&self, branding: Branding) {
        *self.slot.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(branding));
    }

    /// Fetch and publish, keeping the last good values on failure.
    ///
    /// A failure is never silent and never substitutes copy: the first one
    /// (startup, nothing cached) logs at `error` because the deployment then
    /// serves unbranded chrome; a later one logs at `warn` because the last
    /// good values still stand, the way `TtlCache` serves `StaleOnError` rather
    /// than flipping to a default.
    pub async fn refresh<F, Fut>(&self, fetch: F) -> BrandingSource
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Branding, ApiError>>,
    {
        match fetch().await {
            Ok(fresh) => {
                self.install(fresh);
                BrandingSource::Fetched
            }
            Err(e) => {
                let had_value = self
                    .slot
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .is_some();
                if had_value {
                    tracing::warn!(
                        endpoint = "/v1/branding",
                        status = e.status,
                        code = %e.code,
                        error = %e.message,
                        request_id = ?e.request_id,
                        "branding refresh failed; keeping the last loaded values"
                    );
                    BrandingSource::StaleOnError
                } else {
                    tracing::error!(
                        endpoint = "/v1/branding",
                        status = e.status,
                        code = %e.code,
                        error = %e.message,
                        request_id = ?e.request_id,
                        "branding fetch failed and nothing is cached; serving unbranded chrome \
                         (no product name, tagline, description or Open Graph card) until a \
                         refresh succeeds"
                    );
                    BrandingSource::UnbrandedOnError
                }
            }
        }
    }
}

impl Default for BrandingCache {
    fn default() -> Self {
        Self::new()
    }
}

/// The process-wide cache `views::layout` renders from.
static BRANDING: BrandingCache = BrandingCache::new();

/// The branding every page renders. Unbranded until the first fetch lands.
pub fn current() -> Arc<Branding> {
    BRANDING.get()
}

/// Publish branding into the process-wide cache. Called by the startup fetch
/// and the refresh task; also the seam the layout tests render through.
pub fn install(branding: Branding) {
    BRANDING.install(branding);
}

/// `GET /v1/branding` - public, unauthenticated, enveloped like every other
/// endpoint except `/v1/pricing`.
pub async fn fetch(api: &Api) -> Result<Branding, ApiError> {
    parse(api.get("/branding", None).await?)
}

/// One blocking fetch before the listener binds, so the very first page render
/// already carries the brand. A timeout is a failure like any other: it is
/// logged and the process serves unbranded while the refresh task retries.
pub async fn load_at_startup(api: &Api) {
    let fetch_with_timeout = || async {
        match tokio::time::timeout(
            Duration::from_secs(BRANDING_STARTUP_TIMEOUT_SECS),
            fetch(api),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(ApiError {
                status: 0,
                code: "TIMEOUT".into(),
                message: format!(
                    "the startup branding fetch did not answer within {BRANDING_STARTUP_TIMEOUT_SECS}s"
                ),
                retry_after: None,
                request_id: None,
            }),
        }
    };
    BRANDING.refresh(fetch_with_timeout).await;
}

/// Background refresh, so an admin edit reaches the pages without a redeploy.
pub fn spawn_refresh(api: Api) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(BRANDING_REFRESH_SECS)).await;
            BRANDING.refresh(|| fetch(&api)).await;
        }
    });
}

/// `GET /v1/admin/branding` - the saved record behind the admin form. The
/// response carries `updated_at` / `updated_by` too; the form does not render
/// them, and serde ignores what it does not read.
pub async fn admin_get(api: &Api, cookie: Option<&str>) -> Result<Branding, ApiError> {
    parse(api.get("/admin/branding", cookie).await?)
}

/// `PUT /v1/admin/branding`. A rejected save arrives as a 4xx whose per-field
/// message the form renders verbatim (BUNYIP-506: a 5xx would be collapsed into
/// the generic line, and the admin would never learn which field was wrong).
pub async fn admin_update(api: &Api, cookie: Option<&str>, body: Value) -> Result<(), ApiError> {
    let r = api.put("/admin/branding", cookie, Some(body)).await?;
    ok_data(&r).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn branded() -> Branding {
        Branding {
            brand_name: "Acme".into(),
            tagline: "Surfaces what matters.".into(),
            meta_description: "Acme does things.".into(),
            og_image_url: "https://acme.test/card.png".into(),
        }
    }

    fn unreachable() -> ApiError {
        ApiError {
            status: 0,
            code: "NETWORK_ERROR".into(),
            message: "connection refused".into(),
            retry_after: None,
            request_id: None,
        }
    }

    /// The startup path with the API down: nothing is cached, so the pages
    /// render unbranded. Critically, NOT bunyip's old literals - a fetch
    /// failure must not resurrect compiled-in copy.
    #[tokio::test]
    async fn a_cold_failure_serves_unbranded_rather_than_a_compiled_in_name() {
        let cache = BrandingCache::new();
        let source = cache.refresh(|| async { Err(unreachable()) }).await;
        assert_eq!(source, BrandingSource::UnbrandedOnError);
        assert_eq!(*cache.get(), Branding::default());
    }

    /// The refresh path: a transient failure keeps the last good values instead
    /// of blanking the product name on every page.
    #[tokio::test]
    async fn a_failed_refresh_keeps_the_last_good_values() {
        let cache = BrandingCache::new();
        assert_eq!(
            cache.refresh(|| async { Ok(branded()) }).await,
            BrandingSource::Fetched
        );

        let source = cache.refresh(|| async { Err(unreachable()) }).await;
        assert_eq!(source, BrandingSource::StaleOnError);
        assert_eq!(cache.get().brand_name, "Acme");
        assert_eq!(cache.get().og_image_url, "https://acme.test/card.png");
    }

    /// A later success replaces the stale values.
    #[tokio::test]
    async fn a_recovered_fetch_replaces_the_stale_values() {
        let cache = BrandingCache::new();
        cache.install(branded());
        cache
            .refresh(|| async {
                Ok(Branding {
                    brand_name: "Acme Renamed".into(),
                    ..Branding::default()
                })
            })
            .await;
        assert_eq!(cache.get().brand_name, "Acme Renamed");
        assert_eq!(
            cache.get().tagline,
            "",
            "a cleared tagline clears here too: empty means omit, not keep"
        );
    }
}
