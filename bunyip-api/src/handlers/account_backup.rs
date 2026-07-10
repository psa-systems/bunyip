//! BUNYIP-353: account-level backup and restore endpoints.
//!
//! `GET /v1/account/backup` builds and downloads a single account bundle;
//! `POST /v1/account/restore` re-applies an uploaded bundle. Both are gated to
//! account admins ([`AdminUser`]) and audited (metadata logs `user_id`, never
//! PII - BUNYIP-265). The bundle captures the acting admin's own account
//! (profile + entitlements) plus a per-app section for each entitled app,
//! produced through the pluggable adapters wired into [`BackupService`].

use actix_web::{web, HttpRequest, HttpResponse};

use crate::middleware::AdminUser;
use crate::models::{AuditAction, CreateAuditLog};
use crate::repositories::AuditLogRepository;
use crate::responses::{get_request_id, success};
use crate::services::{AccountBackup, BackupService, PgAccountBackupStore, RestoreReport};
use crate::AppError;
use sqlx::PgPool;
use uuid::Uuid;

/// The single default app tenant every account JIT-lands in today (matches
/// mokosh-server's `OIDC_DEFAULT_TENANT_ID`). Kept explicit so a per-app
/// adapter can scope its call once multi-tenant ships.
const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);

/// `GET /v1/account/backup` - build and download the account bundle.
pub async fn download_backup(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    backup_service: web::Data<BackupService>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let store = PgAccountBackupStore::new(pool.get_ref().clone());
    let backup = backup_service
        .create_backup(&store, admin.0.sub, DEFAULT_TENANT_ID, chrono::Utc::now())
        .await?;

    let body = serde_json::to_vec_pretty(&backup)
        .map_err(|e| AppError::internal(format!("serialize account backup: {e}")))?;
    let filename = format!(
        "account-backup-{}.json",
        backup.created_at.format("%Y%m%d-%H%M%S")
    );

    let audit = CreateAuditLog::new(AuditAction::AccountBackupCreated)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("user", admin.0.sub)
        .with_metadata(serde_json::json!({
            "user_id": admin.0.sub,
            "app_sections": backup.apps.len(),
        }));
    AuditLogRepository::create(&pool, audit).await?;

    Ok(HttpResponse::Ok()
        .content_type("application/json; charset=utf-8")
        .insert_header((
            "Content-Disposition",
            format!("attachment; filename=\"{filename}\""),
        ))
        .insert_header(("x-request-id", request_id))
        .body(body))
}

/// `POST /v1/account/restore` - re-apply an uploaded account bundle to the
/// acting admin's own account.
pub async fn restore_backup(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    backup_service: web::Data<BackupService>,
    body: web::Json<AccountBackup>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let store = PgAccountBackupStore::new(pool.get_ref().clone());
    let report: RestoreReport = backup_service
        .restore_backup(
            &store,
            admin.0.sub,
            DEFAULT_TENANT_ID,
            admin.0.sub,
            body.into_inner(),
        )
        .await?;

    let audit = CreateAuditLog::new(AuditAction::AccountRestored)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("user", admin.0.sub)
        .with_metadata(serde_json::json!({
            "user_id": admin.0.sub,
            "entitlements_granted": report.entitlements_granted.len(),
            "apps": report.apps.iter().map(|a| &a.slug).collect::<Vec<_>>(),
        }));
    AuditLogRepository::create(&pool, audit).await?;

    Ok(success(report, request_id))
}
