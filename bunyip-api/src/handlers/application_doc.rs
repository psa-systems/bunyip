//! Per-application documentation handlers (BUNYIP-388).
//!
//! Public reads are open: docs are public content, readable for any ACTIVE
//! application regardless of whether the app requires an entitlement to download
//! or launch. Admin writes (AdminUser) power the docs manager and are
//! audit-logged.

use actix_web::{web, HttpRequest, HttpResponse};
use sqlx::PgPool;

use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::models::{AuditAction, CreateApplicationDoc, CreateAuditLog, UpdateApplicationDoc};
use crate::repositories::{ApplicationDocRepository, ApplicationRepository, AuditLogRepository};
use crate::responses::{get_request_id, success};

/// 404 unless `slug` names an ACTIVE application. Docs are public content
/// (BUNYIP-388): readable for any active app regardless of whether the app
/// itself requires an entitlement to download or launch, so a user can read how
/// to use or pull a product before (or without) having access to it. Only the
/// app being active gates visibility here - not membership or entitlement.
async fn require_active_app(pool: &PgPool, slug: &str) -> Result<(), AppError> {
    ApplicationRepository::find_active_by_slug(pool, slug)
        .await?
        .ok_or(AppError::not_found("Application"))?;
    Ok(())
}

/// Public: `GET /v1/applications/{slug}/docs` - the app's doc-page index
/// (metadata only, ordered). Empty list when the app has no docs.
pub async fn list_app_docs(
    req: HttpRequest,
    path: web::Path<String>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let app_slug = path.into_inner();
    require_active_app(&pool, &app_slug).await?;
    let docs = ApplicationDocRepository::list_by_app_slug(&pool, &app_slug).await?;
    Ok(success(docs, request_id))
}

/// Public: `GET /v1/application-docs` - every ACTIVE application that has at
/// least one documentation page (BUNYIP-635). The `/docs` hub lists these
/// alongside its own static pages; it cannot use `/v1/applications`, which
/// filters `is_hosted = TRUE` and so returns none of the documented apps.
pub async fn list_documented_apps(
    req: HttpRequest,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let apps = ApplicationDocRepository::list_documented_apps(&pool).await?;
    Ok(success(apps, request_id))
}

/// Public: `GET /v1/applications/{slug}/docs/{doc_slug}` - one doc page.
pub async fn get_app_doc(
    req: HttpRequest,
    path: web::Path<(String, String)>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let (app_slug, doc_slug) = path.into_inner();
    require_active_app(&pool, &app_slug).await?;
    let doc = ApplicationDocRepository::get_by_app_and_slug(&pool, &app_slug, &doc_slug)
        .await?
        .ok_or(AppError::not_found("Documentation page"))?;
    Ok(success(doc, request_id))
}

/// Admin: `GET /v1/admin/applications/{app_id}/docs` - all pages for an app
/// (full rows, for the manager UI).
pub async fn list_app_docs_admin(
    req: HttpRequest,
    _admin: AdminUser,
    path: web::Path<uuid::Uuid>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let app_id = path.into_inner();
    let docs = ApplicationDocRepository::list_by_app_id(&pool, app_id).await?;
    Ok(success(docs, request_id))
}

/// Admin: `POST /v1/admin/applications/{app_id}/docs` - create a page.
pub async fn create_app_doc(
    req: HttpRequest,
    admin: AdminUser,
    path: web::Path<uuid::Uuid>,
    body: web::Json<CreateApplicationDoc>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let app_id = path.into_inner();
    let doc = ApplicationDocRepository::create(&pool, app_id, &body.into_inner()).await?;
    let audit = CreateAuditLog::new(AuditAction::ApplicationDocCreated)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("application_doc", doc.id)
        .with_metadata(serde_json::json!({
            "application_id": app_id,
            "slug": doc.slug,
            "title": doc.title,
        }));
    AuditLogRepository::create(&pool, audit).await?;
    Ok(success(doc, request_id))
}

/// Admin: `PUT /v1/admin/application-docs/{doc_id}` - patch a page.
pub async fn update_app_doc(
    req: HttpRequest,
    admin: AdminUser,
    path: web::Path<uuid::Uuid>,
    body: web::Json<UpdateApplicationDoc>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let doc_id = path.into_inner();
    let doc = ApplicationDocRepository::update(&pool, doc_id, &body.into_inner()).await?;
    let audit = CreateAuditLog::new(AuditAction::ApplicationDocUpdated)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("application_doc", doc.id)
        .with_metadata(serde_json::json!({
            "application_id": doc.application_id,
            "slug": doc.slug,
            "title": doc.title,
        }));
    AuditLogRepository::create(&pool, audit).await?;
    Ok(success(doc, request_id))
}

/// Admin: `DELETE /v1/admin/application-docs/{doc_id}` - remove a page.
pub async fn delete_app_doc(
    req: HttpRequest,
    admin: AdminUser,
    path: web::Path<uuid::Uuid>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let doc_id = path.into_inner();
    let removed = ApplicationDocRepository::delete(&pool, doc_id).await?;
    if !removed {
        return Err(AppError::not_found("Documentation page"));
    }
    let audit = CreateAuditLog::new(AuditAction::ApplicationDocDeleted)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("application_doc", doc_id);
    AuditLogRepository::create(&pool, audit).await?;
    Ok(success(serde_json::json!({ "deleted": true }), request_id))
}
