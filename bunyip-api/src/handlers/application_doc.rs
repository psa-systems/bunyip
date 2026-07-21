//! Per-application documentation handlers (BUNYIP-388).
//!
//! Public reads (no auth) power the `/apps/{slug}/docs` pages rendered by
//! bunyip-web; admin writes (AdminUser) power the admin docs manager.

use actix_web::{web, HttpRequest, HttpResponse};
use sqlx::PgPool;

use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::models::{CreateApplicationDoc, UpdateApplicationDoc};
use crate::repositories::ApplicationDocRepository;
use crate::responses::{get_request_id, success};

/// Public: `GET /v1/applications/{slug}/docs` - the app's doc-page index
/// (metadata only, ordered). Empty list when the app has no docs.
pub async fn list_app_docs(
    req: HttpRequest,
    path: web::Path<String>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let app_slug = path.into_inner();
    let docs = ApplicationDocRepository::list_by_app_slug(&pool, &app_slug).await?;
    Ok(success(docs, request_id))
}

/// Public: `GET /v1/applications/{slug}/docs/{doc_slug}` - one doc page.
pub async fn get_app_doc(
    req: HttpRequest,
    path: web::Path<(String, String)>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let (app_slug, doc_slug) = path.into_inner();
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
    _admin: AdminUser,
    path: web::Path<uuid::Uuid>,
    body: web::Json<CreateApplicationDoc>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let app_id = path.into_inner();
    let doc = ApplicationDocRepository::create(&pool, app_id, &body.into_inner()).await?;
    Ok(success(doc, request_id))
}

/// Admin: `PUT /v1/admin/application-docs/{doc_id}` - patch a page.
pub async fn update_app_doc(
    req: HttpRequest,
    _admin: AdminUser,
    path: web::Path<uuid::Uuid>,
    body: web::Json<UpdateApplicationDoc>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let doc_id = path.into_inner();
    let doc = ApplicationDocRepository::update(&pool, doc_id, &body.into_inner()).await?;
    Ok(success(doc, request_id))
}

/// Admin: `DELETE /v1/admin/application-docs/{doc_id}` - remove a page.
pub async fn delete_app_doc(
    req: HttpRequest,
    _admin: AdminUser,
    path: web::Path<uuid::Uuid>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let doc_id = path.into_inner();
    let removed = ApplicationDocRepository::delete(&pool, doc_id).await?;
    if !removed {
        return Err(AppError::not_found("Documentation page"));
    }
    Ok(success(serde_json::json!({ "deleted": true }), request_id))
}
