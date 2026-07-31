//! Admin IP auto-ban management (BUNYIP-319).
//!
//! Read the currently-active IP auto-bans and lift one ahead of its natural
//! expiry. The in-memory `AutoBanService` map is the source of truth for
//! enforcement, so both operations go through the service (never the `ip_bans`
//! table directly): `list_bans` merges the persisted rows with the live map,
//! and `unban` clears the map, strikes, and the persisted row in one call so
//! the lift is effective on the next request. Lifting is audited.
//!
//! BUNYIP-413 adds the missing create half: a super admin can ban an address by
//! hand through the same service, so the ban lands in the map (effective on the
//! next request) and in the `ip_bans` table (surviving a restart).

use std::net::IpAddr;

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::errors::AppError;
use crate::middleware::{AdminUser, AutoBanService, SuperAdminUser};
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

/// Request body for `POST /v1/admin/ip-bans` (BUNYIP-413).
#[derive(Debug, Deserialize)]
pub struct CreateIpBanRequest {
    pub ip: String,
    pub reason: String,
    /// How long the ban lasts. Absent = [`DEFAULT_BAN_SECONDS`].
    #[serde(default)]
    pub duration_secs: Option<i64>,
}

/// Default manual-ban duration: 24 hours, long enough to be useful without
/// stranding a mistyped address forever (it is liftable at any time anyway).
const DEFAULT_BAN_SECONDS: i64 = 86_400;
/// Bounds on a manual ban: a minute at the low end (anything shorter expires
/// before the operator can see it took), a year at the high end.
const MIN_BAN_SECONDS: i64 = 60;
const MAX_BAN_SECONDS: i64 = 31_536_000;
/// `ip_bans.reason` is VARCHAR(255).
const MAX_REASON_LEN: usize = 255;

/// Validate a manual-ban request into the `(ip, reason, duration)` the service
/// takes. Pure and unit-tested: an unparseable address, an empty reason, an
/// over-long reason and an out-of-range duration are all rejected before any
/// state is touched.
fn validate_ban_request(
    raw_ip: &str,
    raw_reason: &str,
    duration_secs: Option<i64>,
) -> Result<(IpAddr, String, i64), AppError> {
    let ip: IpAddr = raw_ip
        .trim()
        .parse()
        .map_err(|_| AppError::bad_request(format!("'{raw_ip}' is not a valid IP address")))?;

    let reason = raw_reason.trim();
    if reason.is_empty() {
        return Err(AppError::bad_request("reason is required"));
    }
    if reason.chars().count() > MAX_REASON_LEN {
        return Err(AppError::bad_request(format!(
            "reason must be at most {MAX_REASON_LEN} characters"
        )));
    }

    let duration = duration_secs.unwrap_or(DEFAULT_BAN_SECONDS);
    if !(MIN_BAN_SECONDS..=MAX_BAN_SECONDS).contains(&duration) {
        return Err(AppError::bad_request(format!(
            "duration_secs must be between {MIN_BAN_SECONDS} and {MAX_BAN_SECONDS}"
        )));
    }

    Ok((ip, reason.to_string(), duration))
}

/// POST /v1/admin/ip-bans
///
/// Ban an IP by hand (BUNYIP-413), the counterpart to the existing lift. Goes
/// through [`AutoBanService::ban`] so the in-memory map the request path checks
/// is updated first and the ban is effective on the next request, with the
/// `ip_bans` row persisted so it survives a restart. Re-banning an
/// already-banned IP replaces its reason and expiry. SuperAdminUser-guarded
/// (a careless ban can lock the platform out) and audited.
pub async fn create_ip_ban(
    req: HttpRequest,
    admin: SuperAdminUser,
    pool: web::Data<PgPool>,
    auto_ban: web::Data<AutoBanService>,
    body: web::Json<CreateIpBanRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let (ip, reason, duration) = validate_ban_request(&body.ip, &body.reason, body.duration_secs)?;

    let expires_at = auto_ban.ban(&ip, &reason, duration).await?;

    let log = CreateAuditLog::new(AuditAction::AdminIpBanCreated)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_metadata(serde_json::json!({
            "ip": ip.to_string(),
            "reason": reason,
            "expires_at": expires_at,
        }));
    AuditLogRepository::create(pool.get_ref(), log).await?;

    Ok(success(
        serde_json::json!({ "ip": ip.to_string(), "expires_at": expires_at }),
        request_id,
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// BUNYIP-413: a manual ban request is normalised (trimmed IP + reason) and
    /// defaults its duration; every malformed field is refused before the
    /// service (and the ban map) is touched.
    #[test]
    fn ban_request_validation() {
        let (ip, reason, duration) =
            validate_ban_request(" 203.0.113.7 ", "  scraping  ", None).unwrap();
        assert_eq!(ip.to_string(), "203.0.113.7");
        assert_eq!(reason, "scraping");
        assert_eq!(duration, DEFAULT_BAN_SECONDS);

        // IPv6 is a first-class input, not just a path-escaping concern.
        let (ip, _, duration) = validate_ban_request("2001:db8::1", "abuse", Some(3600)).unwrap();
        assert_eq!(ip.to_string(), "2001:db8::1");
        assert_eq!(duration, 3600);

        assert!(validate_ban_request("not-an-ip", "abuse", None).is_err());
        assert!(validate_ban_request("203.0.113.7", "   ", None).is_err());
        assert!(
            validate_ban_request("203.0.113.7", &"x".repeat(MAX_REASON_LEN + 1), None).is_err()
        );
        assert!(validate_ban_request("203.0.113.7", "abuse", Some(MIN_BAN_SECONDS - 1)).is_err());
        assert!(validate_ban_request("203.0.113.7", "abuse", Some(MAX_BAN_SECONDS + 1)).is_err());
    }
}
