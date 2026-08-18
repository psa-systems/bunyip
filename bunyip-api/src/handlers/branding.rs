//! Public branding endpoint (BUNYIP-561).
//!
//! `GET /v1/branding` serves the four resolved values bunyip-web renders into
//! the document head and its copy. Unauthenticated (it is what every visitor
//! already sees in the page) and deliberately NOT in
//! `rate_limit_floor::EXEMPT_PATHS`: bunyip-web fetches it once per refresh
//! interval per process, nowhere near the per-IP floor.

use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse};

use crate::errors::AppError;
use crate::models::BrandingCache;
use crate::responses::{get_request_id, success};

/// `GET /v1/branding`
pub async fn public_branding(
    req: HttpRequest,
    branding: web::Data<Arc<BrandingCache>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    Ok(success(branding.get().as_ref().clone(), request_id))
}
