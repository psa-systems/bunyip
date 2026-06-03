//! Admin per-product entitlement management (BUNYIP-39).
//!
//! Lets an admin mark a product as restricted, grant/revoke a member's access
//! to a restricted product, and manage the Stripe price -> product mapping that
//! the subscription webhook uses to auto-grant. All mutations are audited.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::models::entitlement::entitlement_source;
use crate::models::{AuditAction, CreateAuditLog};
use crate::repositories::{ApplicationRepository, AuditLogRepository, EntitlementRepository};
use crate::responses::{get_request_id, success, success_no_data};

#[derive(Debug, Deserialize)]
pub struct EntitlementSlugRequest {
    /// Product slug to grant or revoke.
    pub slug: String,
}

#[derive(Debug, Deserialize)]
pub struct SetRestrictedRequest {
    pub requires_entitlement: bool,
}

#[derive(Debug, Deserialize)]
pub struct PriceMappingRequest {
    pub stripe_price_id: String,
}

/// Resolve a product slug to its id, 404 if unknown.
async fn resolve_app_id(pool: &PgPool, slug: &str) -> Result<Uuid, AppError> {
    let app = ApplicationRepository::find_by_slug(pool, slug)
        .await?
        .ok_or_else(|| AppError::not_found("Application"))?;
    Ok(app.id)
}

/// GET /v1/admin/users/{user_id}/entitlements
pub async fn list_user_entitlements(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();
    let rows = EntitlementRepository::list_for_user(pool.get_ref(), user_id).await?;
    Ok(success(rows, request_id))
}

/// POST /v1/admin/users/{user_id}/entitlements
/// Body: { "slug": "product-slug" }
pub async fn grant_entitlement(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<Uuid>,
    body: web::Json<EntitlementSlugRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();
    let app_id = resolve_app_id(pool.get_ref(), &body.slug).await?;

    EntitlementRepository::grant(
        pool.get_ref(),
        user_id,
        app_id,
        Some(admin.0.sub),
        entitlement_source::ADMIN,
    )
    .await?;

    let log = CreateAuditLog::new(AuditAction::AdminEntitlementGranted)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("user", user_id)
        .with_metadata(serde_json::json!({ "slug": body.slug, "application_id": app_id }));
    AuditLogRepository::create(pool.get_ref(), log).await?;

    Ok(success_no_data(request_id))
}

/// POST /v1/admin/users/{user_id}/entitlements/revoke
/// Body: { "slug": "product-slug" }
pub async fn revoke_entitlement(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<Uuid>,
    body: web::Json<EntitlementSlugRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();
    let app_id = resolve_app_id(pool.get_ref(), &body.slug).await?;

    let revoked = EntitlementRepository::revoke(pool.get_ref(), user_id, app_id).await?;

    // Only audit a real revocation (the call is idempotent).
    if revoked {
        let log = CreateAuditLog::new(AuditAction::AdminEntitlementRevoked)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("user", user_id)
            .with_metadata(serde_json::json!({ "slug": body.slug, "application_id": app_id }));
        AuditLogRepository::create(pool.get_ref(), log).await?;
    }

    Ok(success_no_data(request_id))
}

/// PUT /v1/admin/applications/{slug}/restricted
/// Body: { "requires_entitlement": true }
pub async fn set_application_restricted(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<String>,
    body: web::Json<SetRestrictedRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let slug = path.into_inner();
    let app = ApplicationRepository::find_by_slug(pool.get_ref(), &slug)
        .await?
        .ok_or_else(|| AppError::not_found("Application"))?;

    ApplicationRepository::set_requires_entitlement(
        pool.get_ref(),
        app.id,
        body.requires_entitlement,
    )
    .await?;

    // Preserve current access (BUNYIP-39): flipping an open product to
    // restricted grants it to every member who can access it right now, so
    // nobody loses access to a product they could use moments ago. (The
    // migration only backfilled members who existed at deploy time; this covers
    // everyone current at flip time.)
    let mut backfilled = 0u64;
    if body.requires_entitlement && !app.requires_entitlement {
        backfilled =
            EntitlementRepository::backfill_for_application(pool.get_ref(), app.id).await?;
    }

    let log = CreateAuditLog::new(AuditAction::AdminApplicationRestrictionChanged)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("application", app.id)
        .with_metadata(serde_json::json!({
            "slug": slug,
            "requires_entitlement": body.requires_entitlement,
            "backfilled_members": backfilled,
        }));
    AuditLogRepository::create(pool.get_ref(), log).await?;

    Ok(success_no_data(request_id))
}

/// POST /v1/admin/applications/{slug}/stripe-prices
/// Body: { "stripe_price_id": "price_..." }
pub async fn add_price_mapping(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<String>,
    body: web::Json<PriceMappingRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let slug = path.into_inner();
    let app_id = resolve_app_id(pool.get_ref(), &slug).await?;

    EntitlementRepository::add_price_mapping(pool.get_ref(), &body.stripe_price_id, app_id).await?;

    let log = CreateAuditLog::new(AuditAction::AdminStripePriceMappingChanged)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("application", app_id)
        .with_metadata(serde_json::json!({
            "slug": slug,
            "stripe_price_mapping_added": body.stripe_price_id,
        }));
    AuditLogRepository::create(pool.get_ref(), log).await?;

    Ok(success_no_data(request_id))
}

/// DELETE /v1/admin/applications/{slug}/stripe-prices
/// Body: { "stripe_price_id": "price_..." }
pub async fn remove_price_mapping(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<String>,
    body: web::Json<PriceMappingRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let slug = path.into_inner();
    let app_id = resolve_app_id(pool.get_ref(), &slug).await?;

    EntitlementRepository::remove_price_mapping(pool.get_ref(), &body.stripe_price_id, app_id)
        .await?;

    let log = CreateAuditLog::new(AuditAction::AdminStripePriceMappingChanged)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("application", app_id)
        .with_metadata(serde_json::json!({
            "slug": slug,
            "stripe_price_mapping_removed": body.stripe_price_id,
        }));
    AuditLogRepository::create(pool.get_ref(), log).await?;

    Ok(success_no_data(request_id))
}
