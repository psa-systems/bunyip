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

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use crate::api::types::Branding;
use crate::api::{ok_data, parse, Api, ApiError};
use crate::web::AppState;

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

/// BUNYIP-560: upload one brand asset (`mark`, `favicon` or `mascot`). The
/// bytes are relayed as a multipart file part; bunyip-api sniffs the real type
/// from content, so the declared `mime` is advisory, and it derives the whole
/// favicon set from the favicon slot's source.
pub async fn admin_upload_asset(
    api: &Api,
    cookie: Option<&str>,
    slot: &str,
    filename: &str,
    mime: &str,
    bytes: Vec<u8>,
) -> Result<(), ApiError> {
    let part = reqwest::multipart::Part::bytes(bytes)
        .file_name(filename.to_string())
        .mime_str(mime)
        .map_err(|e| ApiError {
            status: 0,
            code: "NETWORK_ERROR".into(),
            message: format!("invalid brand asset mime: {e}"),
            retry_after: None,
            request_id: None,
        })?;
    let form = reqwest::multipart::Form::new().part("asset", part);
    let r = api
        .post_form(&format!("/admin/branding/assets/{slot}"), cookie, form)
        .await?;
    ok_data(&r).map(|_| ())
}

/// BUNYIP-560: clear one brand asset slot. Idempotent.
pub async fn admin_clear_asset(
    api: &Api,
    cookie: Option<&str>,
    slot: &str,
) -> Result<(), ApiError> {
    let r = api
        .delete(&format!("/admin/branding/assets/{slot}"), cookie, None)
        .await?;
    ok_data(&r).map(|_| ())
}

/// BUNYIP-560: stream one brand asset's bytes for the `/brand/{kind}` BFF
/// proxy, so the browser loads every brand image from bunyip-web's own origin
/// (the same shape the avatar proxy uses). No cookie is forwarded: these are
/// site chrome, identical for every visitor and for none.
pub async fn fetch_asset(api: &Api, kind: &str) -> Result<reqwest::Response, ApiError> {
    api.get_stream(&format!("/branding/assets/{kind}"), None)
        .await
}

/// BUNYIP-560: every asset key the BFF will relay.
///
/// The path segment is interpolated into the upstream URL, and a percent-encoded
/// `../` in it would otherwise walk out of `/v1/branding/assets/` and address
/// another endpoint entirely, so the parameter is matched against this fixed
/// list before any request is made. It mirrors `is_servable_asset_kind` in
/// bunyip-domain; bunyip-web is a standalone binary and shares no crate with it.
pub const BRAND_ASSET_KINDS: &[&str] = &[
    "mark",
    "mascot",
    "favicon-ico",
    "favicon-16",
    "favicon-32",
    "favicon-48",
    "favicon-192",
    "favicon-512",
    "apple-touch-icon",
];

/// GET /brand/{kind} - same-origin proxy of one brand image, so the favicon
/// links, the nav mark and the hero mascot all load from bunyip-web's own
/// origin rather than needing the api origin in the CSP.
///
/// Unauthenticated, like the upstream endpoint. Any non-2xx is a 404 rather
/// than a redirect, so a missing image never navigates an `<img>` to an HTML
/// page.
pub async fn brand_asset(State(st): State<AppState>, Path(kind): Path<String>) -> Response {
    if !BRAND_ASSET_KINDS.contains(&kind.as_str()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match fetch_asset(&st.api, &kind).await {
        Ok(resp) if resp.status().is_success() => {
            let content_type = relayed_content_type(&resp, "application/octet-stream");
            // Public and a day long; every reference carries the record's
            // version as `?v=`, so a re-upload is a new URL rather than a day of
            // the old logo.
            image_response(
                &kind,
                content_type,
                BRAND_ASSET_CACHE_CONTROL,
                Body::from_stream(resp.bytes_stream()),
            )
        }
        // A 404 upstream (the slot is unset) and an unreachable api are the same
        // thing to an `<img>`, but not to the operator: only the second is a
        // fault, and it is already logged with its cause by `Api::send`.
        Ok(resp) => {
            tracing::debug!(kind, status = resp.status().as_u16(), "brand asset missing");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            tracing::warn!(
                kind,
                status = e.status,
                error = %e.message,
                "could not relay a brand asset; the page renders without it"
            );
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

/// The committed favicon the root probe falls back to. Relative to the working
/// directory, exactly like the `ServeDir` that answers `/assets`.
const COMMITTED_FAVICON: &str = "assets/favicon.ico";

/// Brand images are relayed with a day-long lifetime; the `?v=` in every
/// reference is what makes a re-upload visible immediately.
const BRAND_ASSET_CACHE_CONTROL: &str = "public, max-age=86400";

/// The upstream `Content-Type`, or `fallback` when the header is absent or not
/// text. An absent optional header is not a failure; a wrong one would be, and
/// the api always sets the stored MIME.
fn relayed_content_type(resp: &reqwest::Response, fallback: &str) -> String {
    resp.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(fallback)
        .to_string()
}

/// Build one image response. A builder failure is logged with its cause rather
/// than collapsing into a bare 404: every input here is server-controlled, so a
/// failure is a defect in this file and there would otherwise be no trace of it.
fn image_response(kind: &str, content_type: String, cache: &str, body: Body) -> Response {
    match Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, cache)
        .body(body)
    {
        Ok(response) => response,
        Err(e) => {
            tracing::error!(kind, error = %e, "could not build the brand asset response");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

/// GET /favicon.ico - the root probe browsers issue regardless of the
/// `<link rel="icon">` tags in `<head>`.
///
/// BUNYIP-560: it follows the branding record like every other icon. It cannot
/// carry a `?v=` (the URL is fixed by the browser, not by the markup), so it is
/// cacheable for a day rather than `immutable`; with the slot unset, or the api
/// unreachable, it serves the committed file.
pub async fn favicon_ico(State(st): State<AppState>) -> Response {
    if !current().favicon_version.is_empty() {
        // Never silent: the record says an icon IS set, so failing to relay it
        // means every browser tab shows the build's icon instead of the
        // deployment's, and the cause is the only way to tell why.
        match fetch_asset(&st.api, "favicon-ico").await {
            Ok(resp) if resp.status().is_success() => {
                let content_type = relayed_content_type(&resp, "image/x-icon");
                return image_response(
                    "favicon-ico",
                    content_type,
                    BRAND_ASSET_CACHE_CONTROL,
                    Body::from_stream(resp.bytes_stream()),
                );
            }
            Ok(resp) => tracing::warn!(
                status = resp.status().as_u16(),
                "the uploaded favicon.ico is unavailable; serving the committed one"
            ),
            Err(e) => tracing::warn!(
                status = e.status,
                error = %e.message,
                "could not relay the uploaded favicon.ico; serving the committed one"
            ),
        }
    }
    match tokio::fs::read(COMMITTED_FAVICON).await {
        Ok(bytes) => image_response(
            "favicon-ico",
            "image/x-icon".to_string(),
            BRAND_ASSET_CACHE_CONTROL,
            Body::from(bytes),
        ),
        Err(e) => {
            tracing::error!(path = COMMITTED_FAVICON, error = %e, "the committed favicon is unreadable");
            StatusCode::NOT_FOUND.into_response()
        }
    }
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
            ..Branding::default()
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
