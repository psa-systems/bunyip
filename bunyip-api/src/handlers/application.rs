//! Application handlers
//!
//! This module contains HTTP handlers for application endpoints.

use actix_web::{web, HttpRequest, HttpResponse};
use sqlx::PgPool;

use crate::errors::AppError;
use crate::middleware::OptionalUser;
use crate::models::ApplicationResponse;
use crate::repositories::ApplicationRepository;
use crate::responses::{get_request_id, success};

/// GET /v1/applications
/// List all active applications
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

    let apps = ApplicationRepository::list_active(&pool).await?;

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

    let app_response = ApplicationResponse::from_application(app, has_access);

    Ok(success(app_response, request_id))
}
