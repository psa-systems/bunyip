//! Admin API for per-RP user-tenant assignments (BUNYIP-61).
//!
//! Each row in `oauth_client_user_tenants` answers "does USER X have
//! TENANT Y on RP Z?". These endpoints let an admin (or a one-off
//! seed script via the admin API) wire up those rows. The OIDC
//! `/authorize` handler (BUNYIP-62) is the consumer; without these
//! rows existing first, gating /authorize on the table would deny
//! every user on every gated client.
//!
//! All routes are admin-gated. List is read-only; assign / unassign
//! mutate and write an audit-log row each.

use actix_web::{web, HttpRequest, HttpResponse};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::models::{AuditAction, CreateAuditLog, CreateUserTenantAssignment};
use crate::repositories::{AuditLogRepository, OAuthClientUserTenantRepository};
use crate::responses::{get_request_id, success, success_no_data};

/// GET /v1/admin/oauth-clients/{client_id}/user-tenants
///
/// List every (user, tenant) assignment for the given OAuth client.
/// Returns oldest-first. No pagination - the realistic order of
/// magnitude here is tens to low hundreds per client; if a deployment
/// outgrows that, add `?after=<uuid>&limit=N` later without breaking
/// callers because the body shape is a flat array.
pub async fn list_client_assignments(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let client_id = path.into_inner();
    let rows = OAuthClientUserTenantRepository::list_for_client(pool.get_ref(), client_id).await?;
    Ok(success(rows, request_id))
}

/// POST /v1/admin/oauth-clients/{client_id}/user-tenants
/// Body: { "user_id": "<uuid>", "tenant_id": "<uuid>", "role": "<str>" }
///
/// Idempotent (the underlying repo uses ON CONFLICT DO UPDATE), so
/// retrying a seed script that previously crashed mid-batch will not
/// 500. An audit log row is written for every successful call; the
/// upsert "no-op repaint" path still produces one (admin operations
/// should be traceable even when the data did not move).
pub async fn assign_user_tenant(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<Uuid>,
    body: web::Json<CreateUserTenantAssignment>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let client_id = path.into_inner();
    let row = OAuthClientUserTenantRepository::assign(
        pool.get_ref(),
        client_id,
        &body,
        Some(admin.0.sub),
    )
    .await?;

    AuditLogRepository::create(
        pool.get_ref(),
        CreateAuditLog::new(AuditAction::OauthUserTenantAssigned)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("oauth_client", client_id)
            .with_metadata(serde_json::json!({
                "user_id": body.user_id,
                "tenant_id": body.tenant_id,
                "role": body.role,
                "assignment_id": row.id,
            })),
    )
    .await?;

    Ok(success(row, request_id))
}

/// DELETE /v1/admin/oauth-clients/{client_id}/user-tenants/{assignment_id}
///
/// Hard-delete the assignment. Idempotent: deleting an already-deleted
/// row returns 204, matching the repository semantic. The audit log
/// row carries the assignment_id even on a no-op so security review
/// can reconstruct "who deleted what when."
pub async fn unassign_user_tenant(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<(Uuid, Uuid)>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let (client_id, assignment_id) = path.into_inner();
    OAuthClientUserTenantRepository::unassign(pool.get_ref(), assignment_id).await?;

    AuditLogRepository::create(
        pool.get_ref(),
        CreateAuditLog::new(AuditAction::OauthUserTenantUnassigned)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("oauth_client", client_id)
            .with_metadata(serde_json::json!({
                "assignment_id": assignment_id,
            })),
    )
    .await?;

    Ok(success_no_data(request_id))
}
