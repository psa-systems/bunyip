//! Admin surface for the shared mailer suppression list (BUNYIP-762).
//!
//! `mailer_suppressions` (BUNYIP-603) had a write path (the bounce/complaint
//! webhook) and a read path used only internally by the send guard, but no
//! way for an operator to see or remove a suppressed address. This is the
//! missing list/delete half: an admin can page through who is suppressed and
//! why, and lift a suppression so that address can be mailed again.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use sqlx::PgPool;

use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::models::{AuditAction, CreateAuditLog};
use crate::repositories::{AuditLogRepository, MailerSuppressionRepository};
use crate::responses::{get_request_id, paginated, success_no_data};

#[derive(Debug, Deserialize)]
pub struct ListMailerSuppressionsQuery {
    pub page: Option<i32>,
    pub per_page: Option<i32>,
}

/// GET /v1/admin/mailer-suppressions
///
/// Lists suppressed addresses, newest first. AdminUser-guarded.
pub async fn list_mailer_suppressions(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    query: web::Query<ListMailerSuppressionsQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) as i64 * per_page as i64;

    let total = MailerSuppressionRepository::count(pool.get_ref()).await?;
    let items = MailerSuppressionRepository::list(pool.get_ref(), per_page as i64, offset).await?;

    Ok(paginated(items, total, page, per_page, request_id))
}

/// DELETE /v1/admin/mailer-suppressions/{address}
///
/// Removes `address` from the suppression list, so it can be mailed again.
/// Returns 404 when the address was not suppressed. AdminUser-guarded and
/// audited, since lifting a suppression resumes sending to a recipient the
/// suite previously stopped mailing.
pub async fn delete_mailer_suppression(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let address = path.into_inner();

    let deleted = MailerSuppressionRepository::delete(pool.get_ref(), &address).await?;
    if !deleted {
        return Err(AppError::not_found("Suppressed address"));
    }

    let log = CreateAuditLog::new(AuditAction::AdminMailerSuppressionDeleted)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_metadata(serde_json::json!({ "address": address }));
    AuditLogRepository::create(pool.get_ref(), log).await?;

    Ok(success_no_data(request_id))
}
