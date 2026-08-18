//! Public branding endpoint (BUNYIP-561).
//!
//! `GET /v1/branding` serves the four resolved values bunyip-web renders into
//! the document head and its copy. Unauthenticated (it is what every visitor
//! already sees in the page) and deliberately NOT in
//! `rate_limit_floor::EXEMPT_PATHS`: bunyip-web fetches it once per refresh
//! interval per process, nowhere near the per-IP floor.

use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse};
use sqlx::PgPool;

use crate::errors::AppError;
use crate::models::{is_servable_asset_kind, BrandingCache};
use crate::repositories::BrandingRepository;
use crate::responses::{get_request_id, success};

/// `GET /v1/branding`
pub async fn public_branding(
    req: HttpRequest,
    branding: web::Data<Arc<BrandingCache>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    Ok(success(branding.get().as_ref().clone(), request_id))
}

/// `GET /v1/branding/assets/{kind}` (BUNYIP-560).
///
/// Streams a stored brand image with its stored MIME type. Unauthenticated: a
/// favicon, a logo and a hero illustration are what every anonymous visitor
/// already sees in the page. 404 when the slot is unset, so a caller that asks
/// for an asset the record does not have gets a missing image rather than an
/// HTML error page in an `<img>`.
///
/// `kind` is matched against a fixed allow-list before any query runs, so the
/// path parameter can never name an arbitrary row.
///
/// Deliberately NOT in `rate_limit_floor::EXEMPT_PATHS`, unlike `/v1/pricing`:
/// this one reads a table on every call, so the per-IP floor is exactly the
/// control that should apply. The BFF relays it with a day-long
/// `Cache-Control`, so a visitor spends a handful of requests per browser per
/// day, and a throttled one loses an icon rather than a page.
pub async fn public_branding_asset(
    pool: web::Data<PgPool>,
    kind: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let kind = kind.into_inner();
    if !is_servable_asset_kind(&kind) {
        return Err(AppError::not_found("Brand asset"));
    }
    let (mime, data) = BrandingRepository::get_asset(&pool, &kind)
        .await?
        .ok_or_else(|| AppError::not_found("Brand asset"))?;

    Ok(HttpResponse::Ok()
        .content_type(mime)
        .insert_header(("Content-Disposition", "inline"))
        // Public (it is site chrome, identical for every visitor) and cacheable
        // for a day; every reference carries the record's version as `?v=`, so a
        // re-upload produces a new URL rather than waiting the day out.
        .insert_header(("Cache-Control", "public, max-age=86400"))
        .body(data))
}
