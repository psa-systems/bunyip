//! Application handlers
//!
//! This module contains HTTP handlers for application endpoints.

use actix_web::{web, HttpRequest, HttpResponse};
use sqlx::PgPool;

use crate::errors::AppError;
use crate::middleware::OptionalUser;
use crate::models::ApplicationResponse;
use crate::repositories::{
    ApplicationGroupRepository, ApplicationRepository, EntitlementRepository,
};
use crate::responses::{get_request_id, success};

/// GET /v1/application-groups
/// List application groups (display metadata) so the web layer can render
/// applications grouped under their group heading. Public: groups carry no
/// sensitive data, and membership/entitlement gating stays on the apps.
pub async fn list_application_groups(
    req: HttpRequest,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let groups = ApplicationGroupRepository::list(&pool).await?;
    Ok(success(serde_json::json!({ "groups": groups }), request_id))
}

/// GET /v1/applications
/// List active HOSTED applications (hub launch tiles). Catalog-only
/// distribution products are excluded; they surface via /v1/downloads and
/// the OCI registry instead.
pub async fn list_applications(
    req: HttpRequest,
    user: OptionalUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let has_access = user
        .0
        .as_ref()
        .map(|claims| claims.has_member_access())
        .unwrap_or(false);

    let apps = ApplicationRepository::list_active_hosted(&pool).await?;

    let apps_response: Vec<ApplicationResponse> = apps
        .into_iter()
        .map(|app| ApplicationResponse::from_application(app, has_access))
        .collect();

    Ok(success(
        serde_json::json!({ "applications": apps_response }),
        request_id,
    ))
}

/// GET /v1/applications/{slug}
/// Get a specific application by slug
pub async fn get_application(
    req: HttpRequest,
    user: OptionalUser,
    path: web::Path<String>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let slug = path.into_inner();

    let has_access = user
        .0
        .as_ref()
        .map(|claims| claims.has_member_access())
        .unwrap_or(false);

    let app = ApplicationRepository::find_active_by_slug(&pool, &slug)
        .await?
        .ok_or(AppError::not_found("Application"))?;

    // A restricted product (BUNYIP-39) must not leak its existence/metadata to
    // a caller who is not entitled. Treat it as not found for anyone who is not
    // an admin or actively entitled (anonymous callers included). Open products
    // are unaffected (is_allowed short-circuits).
    let (user_id, is_admin) = user
        .0
        .as_ref()
        .map(|claims| (claims.sub, claims.role == "admin"))
        .unwrap_or((uuid::Uuid::nil(), false));
    if !EntitlementRepository::is_allowed(&pool, user_id, is_admin, &app).await? {
        return Err(AppError::not_found("Application"));
    }

    let app_response = ApplicationResponse::from_application(app, has_access);

    Ok(success(app_response, request_id))
}
