//! Admin IP auto-ban management (BUNYIP-319).
//!
//! Read the currently-active IP auto-bans and lift one ahead of its natural
//! expiry. The in-memory `AutoBanService` map is the source of truth for
//! enforcement, so both operations go through the service (never the `ip_bans`
//! table directly): `list_bans` merges the persisted rows with the live map,
//! and `unban` clears the map, strikes, and the persisted row in one call so
//! the lift is effective on the next request. Lifting is audited.

use std::net::IpAddr;

use actix_web::{web, HttpRequest, HttpResponse};

use crate::errors::AppError;
use crate::middleware::{AdminUser, AutoBanService};
use crate::models::{AuditAction, CreateAuditLog};
use crate::repositories::AuditLogRepository;
use crate::responses::{get_request_id, success, success_no_data};
use sqlx::PgPool;

/// GET /v1/admin/ip-bans
///
/// Lists every currently-active IP auto-ban (IP, reason, strikes, banned_at,
/// expires_at). AdminUser-guarded.
pub async fn list_ip_bans(
    req: HttpRequest,
    _admin: AdminUser,
    auto_ban: web::Data<AutoBanService>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let bans = auto_ban.list_bans().await?;
    Ok(success(bans, request_id))
}

/// DELETE /v1/admin/ip-bans/{ip}
///
/// Lifts the auto-ban for `{ip}` via [`AutoBanService::unban`], effective on the
/// next request. Returns 404 when the IP was not banned. Records an
/// [`AuditAction::AdminIpBanLifted`] with the acting admin and target IP.
/// AdminUser-guarded.
pub async fn unban_ip(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    auto_ban: web::Data<AutoBanService>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let raw = path.into_inner();
    let ip: IpAddr = raw
        .parse()
        .map_err(|_| AppError::bad_request(format!("'{raw}' is not a valid IP address")))?;

    // Source of truth is the in-memory ban map, cleared inside `unban`.
    let lifted = auto_ban.unban(&ip).await?;
    if !lifted {
        return Err(AppError::not_found("IP ban"));
    }

    let log = CreateAuditLog::new(AuditAction::AdminIpBanLifted)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_metadata(serde_json::json!({ "ip": ip.to_string() }));
    AuditLogRepository::create(pool.get_ref(), log).await?;

    Ok(success_no_data(request_id))
}
