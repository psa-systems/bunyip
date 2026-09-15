//! BUNYIP-692: HTTP handlers for the org-tier catalogue.
//!
//! Public: `GET /v1/pricing/orgs` returns the visible catalogue, or `[]`
//! when `orgs_enabled` is off. Admin: CRUD + reorder at
//! `/v1/admin/pricing/orgs`. Per-org: `PUT` / `DELETE /v1/organization/tier`
//! for the owner to pick / clear.
//!
//! Every handler resolves the `orgs_enabled` flag ONCE from the process-
//! wide `Arc<RwLock<TierConfig>>` and passes the boolean into the service.

use actix_web::{web, HttpRequest, HttpResponse};
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use bunyip_domain::errors::AppError;
use bunyip_domain::middleware::{AdminUser, AuthenticatedUser};
use bunyip_domain::models::{
    CreateOrgPricingTierRequest, ReorderOrgPricingTiersRequest, SetOrganizationTierRequest,
    UpdateOrgPricingTierRequest,
};
use bunyip_domain::services::OrgPricingService;

use crate::config::TierConfig;
use crate::responses::{created, get_request_id, success};

fn orgs_enabled(tier_config: &Arc<RwLock<TierConfig>>) -> bool {
    tier_config
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .orgs_enabled
}

pub async fn public_list(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let tiers = OrgPricingService::public_list(pool.get_ref(), flag).await?;
    Ok(success(tiers, request_id))
}

pub async fn admin_list(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let tiers = OrgPricingService::admin_list(pool.get_ref(), flag).await?;
    Ok(success(tiers, request_id))
}

pub async fn admin_create(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    body: web::Json<CreateOrgPricingTierRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let tier = OrgPricingService::admin_create(pool.get_ref(), flag, body.into_inner()).await?;
    Ok(created(tier, request_id))
}

pub async fn admin_update(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateOrgPricingTierRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let tier =
        OrgPricingService::admin_update(pool.get_ref(), flag, path.into_inner(), body.into_inner())
            .await?;
    Ok(success(tier, request_id))
}

pub async fn admin_delete(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    OrgPricingService::admin_delete(pool.get_ref(), flag, path.into_inner()).await?;
    Ok(success(serde_json::json!({ "deleted": true }), request_id))
}

pub async fn admin_reorder(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    body: web::Json<ReorderOrgPricingTiersRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    OrgPricingService::admin_reorder(pool.get_ref(), flag, body.into_inner()).await?;
    Ok(success(
        serde_json::json!({ "reordered": true }),
        request_id,
    ))
}

/// `PUT /v1/organization/tier` - the owner picks a tier.
pub async fn set_organization_tier(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    body: web::Json<SetOrganizationTierRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    OrgPricingService::set_organization_tier(pool.get_ref(), flag, user.0.sub, body.org_tier_id)
        .await?;
    Ok(success(
        serde_json::json!({ "org_tier_id": body.org_tier_id }),
        request_id,
    ))
}

/// `DELETE /v1/organization/tier` - the owner clears their tier.
pub async fn clear_organization_tier(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    OrgPricingService::clear_organization_tier(pool.get_ref(), flag, user.0.sub).await?;
    Ok(success(serde_json::json!({ "cleared": true }), request_id))
}
