//! Admin rate-limit visibility (BUNYIP-315).
//!
//! A read-only view of who is *currently* throttled. Rate-limit state lives in
//! two places and this handler unifies them:
//!
//! 1. The `rate_limits` table (`login`, `registration`, the OCI/OAuth presets,
//!    the per-account 2FA failure counter, ...). Each row's `key` is opaque and
//!    its meaning depends on `action`, so we interpret it per the action's
//!    [`KeySubject`] and resolve it to a user (id + email) when it is email- or
//!    user-id-keyed, exposing the IP instead when it is IP-keyed.
//! 2. The email-verify / email-change resend limiters (BUNYIP-313), which count
//!    rows in `email_verification_tokens` / `email_change_requests` rather than
//!    the `rate_limits` table. Users at or over the shared resend threshold are
//!    synthesized into entries under the pseudo-actions `email_verification` /
//!    `email_change`.
//!
//! Cap and window always come from the [`RateLimitConfig`] presets (or the
//! shared resend constants), never re-hardcoded here, and `retry_after` is
//! computed from `window_start`, never stored. Read-only, no mutation.

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::middleware::{AdminUser, SuperAdminUser};
use crate::models::{AuditAction, CreateAuditLog, KeySubject, RateLimit, RateLimitConfig};
use crate::repositories::{
    AuditLogRepository, EmailResendLimiterRow, RateLimitConfigRepository, RateLimitConfigRow,
    RateLimitRepository, TokenRepository, UserRepository,
};
use crate::responses::{get_request_id, paginated, success, success_no_data};
use crate::services::auth::{resend_retry_after_secs, RESEND_LIMIT_MAX, RESEND_LIMIT_WINDOW_SECS};

/// One currently-active throttle, resolved to a user where possible.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RateLimitEntry {
    /// The action being throttled (a `RateLimitConfig` action, or one of the
    /// `email_verification` / `email_change` pseudo-actions).
    pub action: String,
    /// The raw `rate_limits.key` (or the user id for the token limiters).
    pub key: String,
    /// Resolved user id, when the key maps to one.
    pub user_id: Option<Uuid>,
    /// Resolved user email, when the key maps to one.
    pub user_email: Option<String>,
    /// Source IP, for IP-keyed actions (mutually exclusive with the user).
    pub ip: Option<String>,
    /// Current request count in the window.
    pub count: i64,
    /// Configured cap for this action (from the presets / resend constants).
    pub max_requests: i32,
    /// Start of the current window.
    pub window_start: DateTime<Utc>,
    /// Seconds until the window elapses and the throttle clears (computed).
    pub retry_after: u64,
}

/// Build the entry for a `rate_limits` table row that has already been
/// confirmed active (its `retry_after` computed) and whose `subject` has been
/// resolved to `user` where possible. Pure so it is unit-testable without a DB:
/// IP-keyed rows expose the IP and never a user; every other subject exposes
/// the resolved user (or nothing, when the key pointed at no live user).
fn build_table_entry(
    row: &RateLimit,
    cfg: &RateLimitConfig,
    subject: &KeySubject,
    user: Option<(Uuid, String)>,
    retry_after: u64,
) -> RateLimitEntry {
    let (user_id, user_email, ip) = match subject {
        KeySubject::Ip(ip) => (None, None, Some(ip.clone())),
        // A client-id key names a calling app, not a person (BUNYIP-602): there
        // is no user and no IP to expose, and the raw key is already on the
        // entry.
        KeySubject::ClientId(_) => (None, None, None),
        KeySubject::Email(_) | KeySubject::UserId(_) | KeySubject::Unknown(_) => match user {
            Some((id, email)) => (Some(id), Some(email), None),
            None => (None, None, None),
        },
    };

    RateLimitEntry {
        action: row.action.clone(),
        key: row.key.clone(),
        user_id,
        user_email,
        ip,
        count: row.count as i64,
        max_requests: cfg.max_requests,
        window_start: row.window_start,
        retry_after,
    }
}

/// Synthesize an entry for an email-resend limiter (BUNYIP-315). These limiters
/// live outside the `rate_limits` table, so the user is always known and the
/// cap/window come from the shared resend constants; `retry_after` is computed
/// from the oldest in-window request the same way the enforcement path does.
/// Pure and unit-testable.
fn synthesize_resend_entry(
    action: &str,
    row: &EmailResendLimiterRow,
    now: DateTime<Utc>,
) -> RateLimitEntry {
    RateLimitEntry {
        action: action.to_string(),
        key: row.user_id.to_string(),
        user_id: Some(row.user_id),
        user_email: Some(row.email.clone()),
        ip: None,
        count: row.count,
        max_requests: RESEND_LIMIT_MAX as i32,
        window_start: row.oldest,
        retry_after: resend_retry_after_secs(row.oldest, now),
    }
}

/// Query parameters for listing active rate limits.
#[derive(Debug, Deserialize)]
pub struct ListRateLimitsQuery {
    pub page: Option<i32>,
    pub per_page: Option<i32>,
}

/// GET /v1/admin/rate-limits
///
/// List every currently-active throttle across the `rate_limits` table and the
/// email-verify / email-change resend limiters, each resolved to a user where
/// possible. AdminUser-guarded, read-only, paginated.
pub async fn list_rate_limits(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    query: web::Query<ListRateLimitsQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let now = Utc::now();

    let mut entries: Vec<RateLimitEntry> = Vec::new();

    // 1. `rate_limits` table rows whose window is still open and whose count is
    //    at or over the cap. Cap/window come from the action's EFFECTIVE config
    //    (preset + env, with any persisted override applied - BUNYIP-413), so
    //    this view judges active-ness by the same numbers the enforcement path
    //    does. A row whose action has no preset is skipped (we cannot judge it).
    //    The overrides are read once here rather than per row.
    let overrides = RateLimitConfigRepository::list(pool.get_ref()).await?;
    for row in RateLimitRepository::list_active(pool.get_ref()).await? {
        let Some(cfg) = RateLimitConfig::by_action(&row.action).map(|cfg| {
            match overrides.iter().find(|o| o.action == cfg.action) {
                Some(o) => cfg.with_overrides(Some(o.max_requests), Some(o.window_seconds)),
                None => cfg,
            }
        }) else {
            continue;
        };
        let Some(retry_after) = row.active_retry_after(&cfg, now) else {
            continue;
        };

        let subject = cfg.subject(&row.key);
        let user = match &subject {
            KeySubject::Email(email) => UserRepository::find_by_email(pool.get_ref(), email)
                .await?
                .map(|u| (u.id, u.email)),
            KeySubject::UserId(id) => UserRepository::find_by_id(pool.get_ref(), *id)
                .await?
                .map(|u| (u.id, u.email)),
            KeySubject::Ip(_) | KeySubject::ClientId(_) | KeySubject::Unknown(_) => None,
        };

        entries.push(build_table_entry(&row, &cfg, &subject, user, retry_after));
    }

    // 2. Email-resend limiters (BUNYIP-313): users at or over the shared
    //    threshold within the rolling window, surfaced as pseudo-actions.
    let since = now - Duration::seconds(RESEND_LIMIT_WINDOW_SECS);
    for row in
        TokenRepository::list_email_verification_over_limit(pool.get_ref(), since, RESEND_LIMIT_MAX)
            .await?
    {
        entries.push(synthesize_resend_entry("email_verification", &row, now));
    }
    for row in
        TokenRepository::list_email_change_over_limit(pool.get_ref(), since, RESEND_LIMIT_MAX)
            .await?
    {
        entries.push(synthesize_resend_entry("email_change", &row, now));
    }

    // Paginate the unified list in memory (the active set is small and drawn
    // from several sources, so there is no single query to page). Each source
    // is ordered deterministically, so the page boundary is stable.
    let total = entries.len() as i64;
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);
    let start = ((page - 1) * per_page) as usize;
    let page_items: Vec<RateLimitEntry> = entries
        .into_iter()
        .skip(start)
        .take(per_page as usize)
        .collect();

    Ok(paginated(page_items, total, page, per_page, request_id))
}

/// Request body for `POST /v1/admin/rate-limits/reset` (BUNYIP-316). `action`
/// and `key` are exactly the identifiers `list_rate_limits` returns for the
/// throttle to clear.
#[derive(Debug, Deserialize)]
pub struct ResetRateLimitRequest {
    pub action: String,
    pub key: String,
}

/// POST /v1/admin/rate-limits/reset
///
/// Clear one currently-active throttle so the affected user can act again
/// immediately (BUNYIP-316). Dispatched on `action`:
///
/// * the `email_verification` / `email_change` pseudo-actions are backed by row
///   counts, not the `rate_limits` table, so `key` is the user id and the reset
///   deletes that user's in-window token / request rows, dropping the count
///   below the shared resend threshold so a subsequent request succeeds;
/// * every other action is a `rate_limits` table row cleared via
///   [`RateLimitRepository::reset`]. The action must be a known preset.
///
/// AdminUser-guarded. Records an [`AuditAction::AdminRateLimitReset`] carrying
/// the acting admin, the reset action + key, and the resolved target user where
/// the key maps to one. Returns 204.
pub async fn reset_rate_limit(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    body: web::Json<ResetRateLimitRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let action = body.action.trim();
    let key = body.key.trim();

    if action.is_empty() || key.is_empty() {
        return Err(AppError::bad_request("action and key are required"));
    }

    // Clear the throttle and resolve the target user (for the audit record)
    // where the key maps to one.
    let target = apply_rate_limit_reset(pool.get_ref(), action, key).await?;
    let (target_user_id, target_email) = match target {
        Some((id, email)) => (Some(id), Some(email)),
        None => (None, None),
    };

    let mut log = CreateAuditLog::new(AuditAction::AdminRateLimitReset)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_metadata(serde_json::json!({
            "action": action,
            "key": key,
            "target_user_id": target_user_id,
            "target_email": target_email,
        }));
    if let Some(uid) = target_user_id {
        log = log.with_resource("user", uid);
    }
    AuditLogRepository::create(pool.get_ref(), log).await?;

    Ok(success_no_data(request_id))
}

/// Clear a single active throttle identified by `(action, key)` and return the
/// resolved target user `(id, email)` when the key maps to one (BUNYIP-316).
/// Holds the whole dispatch (pseudo-action vs `rate_limits` table row) so the
/// HTTP handler stays a thin audit wrapper and the reset behaviour is
/// integration-testable against a real pool without constructing a request.
async fn apply_rate_limit_reset(
    pool: &PgPool,
    action: &str,
    key: &str,
) -> Result<Option<(Uuid, String)>, AppError> {
    match action {
        "email_verification" | "email_change" => {
            // The list surfaces these pseudo-actions with the user id as `key`.
            let user_id = Uuid::parse_str(key).map_err(|_| {
                AppError::bad_request(format!("key must be a user id for the '{action}' limiter"))
            })?;
            let user = UserRepository::find_by_id(pool, user_id)
                .await?
                .ok_or(AppError::not_found("User"))?;

            let since = Utc::now() - Duration::seconds(RESEND_LIMIT_WINDOW_SECS);
            if action == "email_verification" {
                TokenRepository::delete_recent_email_verification_tokens(pool, user_id, since)
                    .await?;
            } else {
                TokenRepository::delete_recent_email_change_requests(pool, user_id, since).await?;
            }

            Ok(Some((user.id, user.email)))
        }
        _ => {
            // A `rate_limits` table action. Require a known preset so a typo'd
            // action that no reset would ever match is a clean 400, not a
            // silent no-op.
            let cfg = RateLimitConfig::by_action(action).ok_or_else(|| {
                AppError::bad_request(format!("unknown rate-limit action '{action}'"))
            })?;

            // Resolve the user for the audit record where the key maps to one.
            let target = match cfg.subject(key) {
                KeySubject::Email(email) => UserRepository::find_by_email(pool, &email)
                    .await?
                    .map(|u| (u.id, u.email)),
                KeySubject::UserId(id) => UserRepository::find_by_id(pool, id)
                    .await?
                    .map(|u| (u.id, u.email)),
                KeySubject::Ip(_) | KeySubject::ClientId(_) | KeySubject::Unknown(_) => None,
            };

            RateLimitRepository::reset(pool, key, action).await?;

            Ok(target)
        }
    }
}

// ===========================================================================
// Rate-limit CONFIGURATION management (BUNYIP-413)
//
// The screens above manage live throttles; this section manages the caps and
// windows themselves. Reading is AdminUser-guarded like the rest of the admin
// surface; every mutation is SuperAdminUser-guarded, because a mis-set cap can
// lock the whole platform out.
// ===========================================================================

/// The cap/window in force for one action, plus its bootstrap default so the
/// UI can show what an override is departing from and offer a revert.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RateLimitConfigEntry {
    pub action: String,
    /// Effective cap: the persisted override when present, else the default.
    pub max_requests: i32,
    /// Effective window, same precedence.
    pub window_seconds: i64,
    /// Bootstrap default cap (compile-time const with env vars applied).
    pub default_max_requests: i32,
    /// Bootstrap default window.
    pub default_window_seconds: i64,
    /// True when a persisted `rate_limit_configs` row is overriding the default.
    pub overridden: bool,
    /// When the override was last written (absent when not overridden).
    pub updated_at: Option<DateTime<Utc>>,
    /// Super admin who last wrote the override.
    pub updated_by: Option<Uuid>,
}

/// Build the entry for one action from its bootstrap default and the persisted
/// override, if any. Pure so the precedence is unit-testable without a DB.
fn build_config_entry(
    default_cfg: &RateLimitConfig,
    row: Option<&RateLimitConfigRow>,
) -> RateLimitConfigEntry {
    RateLimitConfigEntry {
        action: default_cfg.action.to_string(),
        max_requests: row.map_or(default_cfg.max_requests, |r| r.max_requests),
        window_seconds: row.map_or(default_cfg.window_seconds, |r| r.window_seconds),
        default_max_requests: default_cfg.max_requests,
        default_window_seconds: default_cfg.window_seconds,
        overridden: row.is_some(),
        updated_at: row.map(|r| r.updated_at),
        updated_by: row.and_then(|r| r.updated_by),
    }
}

/// Bounds on an admin-set rate limit. A cap of zero would refuse every request
/// for the action (including logins), and an unbounded window would keep a
/// throttle alive effectively forever, so both are rejected up front.
const MAX_REQUESTS_LIMIT: i32 = 1_000_000;
const WINDOW_SECONDS_LIMIT: i64 = 604_800; // 7 days

/// GET /v1/admin/rate-limit-configs
///
/// The configured cap/window for every known rate-limit action, marking which
/// ones a persisted override is in force for. AdminUser-guarded (read-only;
/// mutation is super-admin only).
pub async fn list_rate_limit_configs(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let rows = RateLimitConfigRepository::list(pool.get_ref()).await?;

    let entries: Vec<RateLimitConfigEntry> = RateLimitConfig::ALL
        .iter()
        .map(|cfg| {
            let default_cfg = cfg.with_deployment_defaults();
            let row = rows.iter().find(|r| r.action == default_cfg.action);
            build_config_entry(&default_cfg, row)
        })
        .collect();

    Ok(success(entries, request_id))
}

/// Request body for `PUT /v1/admin/rate-limit-configs/{action}`.
#[derive(Debug, Deserialize)]
pub struct UpsertRateLimitConfigRequest {
    pub max_requests: i32,
    pub window_seconds: i64,
}

/// Validate an admin-supplied cap/window pair. Pure and unit-tested.
fn validate_limits(max_requests: i32, window_seconds: i64) -> Result<(), AppError> {
    if !(1..=MAX_REQUESTS_LIMIT).contains(&max_requests) {
        return Err(AppError::bad_request(format!(
            "max_requests must be between 1 and {MAX_REQUESTS_LIMIT}"
        )));
    }
    if !(1..=WINDOW_SECONDS_LIMIT).contains(&window_seconds) {
        return Err(AppError::bad_request(format!(
            "window_seconds must be between 1 and {WINDOW_SECONDS_LIMIT}"
        )));
    }
    Ok(())
}

/// PUT /v1/admin/rate-limit-configs/{action}
///
/// Create or update the persisted override for `action`, which takes effect at
/// every enforcement site on the next request. The action must be a known
/// preset: an override for an action no call site enforces would be stored but
/// inert, so it is rejected. SuperAdminUser-guarded and audited.
pub async fn upsert_rate_limit_config(
    req: HttpRequest,
    admin: SuperAdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<String>,
    body: web::Json<UpsertRateLimitConfigRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let action = path.into_inner();
    let default_cfg = RateLimitConfig::by_action(&action)
        .ok_or_else(|| AppError::bad_request(format!("unknown rate-limit action '{action}'")))?;
    validate_limits(body.max_requests, body.window_seconds)?;

    let row = RateLimitConfigRepository::upsert(
        pool.get_ref(),
        default_cfg.action,
        body.max_requests,
        body.window_seconds,
        Some(admin.0.sub),
    )
    .await?;

    let log = CreateAuditLog::new(AuditAction::AdminRateLimitConfigUpdated)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_metadata(serde_json::json!({
            "action": row.action,
            "max_requests": row.max_requests,
            "window_seconds": row.window_seconds,
        }));
    AuditLogRepository::create(pool.get_ref(), log).await?;

    Ok(success(
        build_config_entry(&default_cfg, Some(&row)),
        request_id,
    ))
}

/// DELETE /v1/admin/rate-limit-configs/{action}
///
/// Drop the persisted override for `action`, reverting it to the bootstrap
/// default (const + env). 404s when no override was in force.
/// SuperAdminUser-guarded and audited.
pub async fn delete_rate_limit_config(
    req: HttpRequest,
    admin: SuperAdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let action = path.into_inner();
    let default_cfg = RateLimitConfig::by_action(&action)
        .ok_or_else(|| AppError::bad_request(format!("unknown rate-limit action '{action}'")))?;

    if !RateLimitConfigRepository::delete(pool.get_ref(), default_cfg.action).await? {
        return Err(AppError::not_found("Rate limit override"));
    }

    let log = CreateAuditLog::new(AuditAction::AdminRateLimitConfigDeleted)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_metadata(serde_json::json!({ "action": default_cfg.action }));
    AuditLogRepository::create(pool.get_ref(), log).await?;

    Ok(success_no_data(request_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::KeyKind;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    fn row(action: &str, key: &str, count: i32, window_start: DateTime<Utc>) -> RateLimit {
        RateLimit {
            id: Uuid::nil(),
            key: key.to_string(),
            action: action.to_string(),
            count,
            window_start,
        }
    }

    #[test]
    fn table_entry_email_keyed_exposes_resolved_user() {
        let cfg = RateLimitConfig::LOGIN;
        let r = row("login", "user@example.com", 6, ts(1000));
        let subject = cfg.subject(&r.key);
        assert_eq!(subject, KeySubject::Email("user@example.com".to_string()));

        let id = Uuid::from_u128(7);
        let entry = build_table_entry(
            &r,
            &cfg,
            &subject,
            Some((id, "user@example.com".to_string())),
            40,
        );
        assert_eq!(entry.user_id, Some(id));
        assert_eq!(entry.user_email.as_deref(), Some("user@example.com"));
        assert_eq!(entry.ip, None);
        assert_eq!(entry.max_requests, cfg.max_requests);
        assert_eq!(entry.count, 6);
        assert_eq!(entry.retry_after, 40);
    }

    #[test]
    fn table_entry_ip_keyed_exposes_ip_never_user() {
        let cfg = RateLimitConfig::REGISTRATION;
        let r = row("registration", "203.0.113.9", 3, ts(1000));
        let subject = cfg.subject(&r.key);
        assert_eq!(subject, KeySubject::Ip("203.0.113.9".to_string()));

        // Even if a user were (wrongly) passed, an IP-keyed row must not leak one.
        let entry = build_table_entry(
            &r,
            &cfg,
            &subject,
            Some((Uuid::from_u128(1), "x@y.z".to_string())),
            120,
        );
        assert_eq!(entry.user_id, None);
        assert_eq!(entry.user_email, None);
        assert_eq!(entry.ip.as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn table_entry_two_factor_prefix_resolves_user() {
        let cfg = RateLimitConfig::TWO_FACTOR_VERIFY_FAILURES;
        assert_eq!(cfg.key_kind, KeyKind::TwoFactorUserId);
        let id = Uuid::from_u128(0xabc);
        let key = format!("{}{id}", crate::models::TWO_FACTOR_KEY_PREFIX);
        let r = row("two_factor_verify_failures", &key, 5, ts(1000));
        let subject = cfg.subject(&r.key);
        assert_eq!(subject, KeySubject::UserId(id));

        let entry = build_table_entry(&r, &cfg, &subject, Some((id, "a@b.c".to_string())), 900);
        assert_eq!(entry.user_id, Some(id));
        assert_eq!(entry.ip, None);
    }

    /// BUNYIP-413: with no persisted row the entry reports the bootstrap
    /// default and is not marked overridden; with one, the override wins and
    /// the default is still carried so the UI can offer a revert.
    #[test]
    fn config_entry_reports_default_then_override() {
        let cfg = RateLimitConfig::LOGIN;

        let plain = build_config_entry(&cfg, None);
        assert_eq!(plain.max_requests, cfg.max_requests);
        assert_eq!(plain.window_seconds, cfg.window_seconds);
        assert!(!plain.overridden);
        assert_eq!(plain.updated_at, None);

        let admin_id = Uuid::from_u128(9);
        let row = RateLimitConfigRow {
            action: "login".to_string(),
            max_requests: 25,
            window_seconds: 300,
            updated_at: ts(1_000),
            updated_by: Some(admin_id),
        };
        let overridden = build_config_entry(&cfg, Some(&row));
        assert_eq!(overridden.max_requests, 25);
        assert_eq!(overridden.window_seconds, 300);
        assert_eq!(overridden.default_max_requests, cfg.max_requests);
        assert_eq!(overridden.default_window_seconds, cfg.window_seconds);
        assert!(overridden.overridden);
        assert_eq!(overridden.updated_by, Some(admin_id));
    }

    /// A cap of zero (which would refuse every login) and an out-of-range
    /// window are rejected before anything is persisted.
    #[test]
    fn limits_validation_rejects_out_of_range() {
        assert!(validate_limits(1, 1).is_ok());
        assert!(validate_limits(MAX_REQUESTS_LIMIT, WINDOW_SECONDS_LIMIT).is_ok());
        assert!(validate_limits(0, 60).is_err());
        assert!(validate_limits(-1, 60).is_err());
        assert!(validate_limits(MAX_REQUESTS_LIMIT + 1, 60).is_err());
        assert!(validate_limits(5, 0).is_err());
        assert!(validate_limits(5, WINDOW_SECONDS_LIMIT + 1).is_err());
    }

    #[test]
    fn synthesize_email_verification_entry() {
        let now = ts(1_000_000);
        let oldest = now - Duration::seconds(600);
        let user_id = Uuid::from_u128(42);
        let limiter = EmailResendLimiterRow {
            user_id,
            email: "throttled@example.com".to_string(),
            count: 3,
            oldest,
        };
        let entry = synthesize_resend_entry("email_verification", &limiter, now);
        assert_eq!(entry.action, "email_verification");
        assert_eq!(entry.user_id, Some(user_id));
        assert_eq!(entry.user_email.as_deref(), Some("throttled@example.com"));
        assert_eq!(entry.ip, None);
        assert_eq!(entry.count, 3);
        assert_eq!(entry.max_requests, RESEND_LIMIT_MAX as i32);
        // retry_after = oldest + window - now = 3600 - 600 = 3000.
        assert_eq!(entry.retry_after, 3000);
        assert_eq!(entry.key, user_id.to_string());
    }
}

/// DB-backed integration tests for the BUNYIP-316 reset path. They exercise the
/// real `apply_rate_limit_reset` dispatch against Postgres and skip silently
/// when `DATABASE_URL` is unset (the same pattern the other admin handler tests
/// use), so `just test` stays green without a database.
#[cfg(test)]
mod db_tests {
    use super::*;

    async fn maybe_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        PgPool::connect(&url).await.ok()
    }

    async fn insert_user(pool: &PgPool, email: &str) -> Uuid {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO users (email, password_hash, role, email_verified)
            VALUES ($1, 'x', 'subscriber', false)
            RETURNING id
            "#,
        )
        .bind(email)
        .fetch_one(pool)
        .await
        .unwrap();
        row.0
    }

    async fn delete_user(pool: &PgPool, user_id: Uuid) {
        // email_verification_tokens / email_change_requests cascade on user delete.
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await
            .unwrap();
    }

    /// A `rate_limits`-backed throttle (login, email-keyed) is cleared by the
    /// reset so the key is no longer over the cap, and the resolved target user
    /// is returned for the audit record.
    #[actix_rt::test]
    async fn reset_clears_rate_limits_table_throttle() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let email = format!("rl-reset-{}@example.com", Uuid::new_v4());
        let user_id = insert_user(&pool, &email).await;

        let cfg = RateLimitConfig::LOGIN; // cap 5 / 60s, email-keyed.

        // Drive the counter over the cap so the key is throttled.
        for _ in 0..(cfg.max_requests + 1) {
            RateLimitRepository::check_and_increment(&pool, &email, &cfg)
                .await
                .unwrap();
        }
        let (_, exceeded) = RateLimitRepository::check(&pool, &email, &cfg)
            .await
            .unwrap();
        assert!(exceeded, "user should be throttled before reset");

        // Reset via the real handler dispatch.
        let target = apply_rate_limit_reset(&pool, "login", &email)
            .await
            .unwrap();
        assert_eq!(target, Some((user_id, email.clone())));

        // The throttle is gone: the row was deleted, so the count is back to 0.
        let (count, exceeded) = RateLimitRepository::check(&pool, &email, &cfg)
            .await
            .unwrap();
        assert_eq!(count, 0);
        assert!(!exceeded, "user should be un-throttled after reset");

        delete_user(&pool, user_id).await;
    }

    /// The `email_verification` pseudo-action is cleared by dropping the user's
    /// in-window verification tokens, taking the resend count below the shared
    /// threshold so a subsequent request would succeed.
    #[actix_rt::test]
    async fn reset_clears_email_verification_limiter() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let email = format!("ev-reset-{}@example.com", Uuid::new_v4());
        let user_id = insert_user(&pool, &email).await;

        // Insert RESEND_LIMIT_MAX in-window verification tokens so the user is
        // at the resend threshold (the enforcement gate is `count >= MAX`).
        for i in 0..RESEND_LIMIT_MAX {
            sqlx::query(
                r#"
                INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
                VALUES ($1, $2, NOW() + INTERVAL '1 day')
                "#,
            )
            .bind(user_id)
            .bind(format!("hash-{user_id}-{i}"))
            .execute(&pool)
            .await
            .unwrap();
        }

        let since = Utc::now() - Duration::seconds(RESEND_LIMIT_WINDOW_SECS);
        let before = TokenRepository::count_recent_email_verification_tokens(&pool, user_id, since)
            .await
            .unwrap();
        assert!(
            before >= RESEND_LIMIT_MAX,
            "user should be at/over the resend threshold before reset"
        );

        // Reset via the real handler dispatch (key is the user id).
        let target = apply_rate_limit_reset(&pool, "email_verification", &user_id.to_string())
            .await
            .unwrap();
        assert_eq!(target, Some((user_id, email.clone())));

        // In-window rows are gone, so the count is below the threshold: a
        // subsequent resend passes the `count >= MAX` gate.
        let after = TokenRepository::count_recent_email_verification_tokens(&pool, user_id, since)
            .await
            .unwrap();
        assert_eq!(after, 0);
        assert!(
            after < RESEND_LIMIT_MAX,
            "user should be un-throttled after reset"
        );

        delete_user(&pool, user_id).await;
    }

    /// BUNYIP-413: a created rate-limit override persists and is what the
    /// enforcement path then applies. The default login cap is 5/60s; after
    /// storing a 2-request override the third request in the window trips,
    /// and deleting the override restores the default.
    #[actix_rt::test]
    async fn created_rate_limit_config_persists_and_is_enforced() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let cfg = RateLimitConfig::LOGIN;
        let key = format!("rl-config-{}@example.com", Uuid::new_v4());

        // Clean slate: no override for this action.
        RateLimitConfigRepository::delete(&pool, cfg.action)
            .await
            .unwrap();
        assert_eq!(
            RateLimitConfigRepository::effective(&pool, &cfg)
                .await
                .unwrap(),
            cfg.with_deployment_defaults(),
            "with no override the bootstrap default (const + env) applies"
        );

        // Create the override, exactly as the handler does.
        let row = RateLimitConfigRepository::upsert(&pool, cfg.action, 2, 120, None)
            .await
            .unwrap();
        assert_eq!((row.max_requests, row.window_seconds), (2, 120));

        // It is persisted, readable back, and is what the enforcement path uses.
        let stored = RateLimitConfigRepository::get(&pool, cfg.action)
            .await
            .unwrap()
            .expect("override persisted");
        assert_eq!((stored.max_requests, stored.window_seconds), (2, 120));
        let effective = RateLimitConfigRepository::effective(&pool, &cfg)
            .await
            .unwrap();
        assert_eq!((effective.max_requests, effective.window_seconds), (2, 120));

        // Enforcement honours the override: 2 allowed, the 3rd trips.
        for i in 1..=2 {
            RateLimitRepository::check_rate_limit(&pool, &key, &cfg)
                .await
                .unwrap_or_else(|e| panic!("request {i} should be under the override cap: {e}"));
        }
        assert!(
            RateLimitRepository::check_rate_limit(&pool, &key, &cfg)
                .await
                .is_err(),
            "the 3rd request must trip the 2-request override"
        );

        // Deleting the override reverts to the bootstrap default.
        assert!(RateLimitConfigRepository::delete(&pool, cfg.action)
            .await
            .unwrap());
        assert_eq!(
            RateLimitConfigRepository::effective(&pool, &cfg)
                .await
                .unwrap()
                .max_requests,
            cfg.max_requests
        );
        assert!(
            !RateLimitConfigRepository::delete(&pool, cfg.action)
                .await
                .unwrap(),
            "a second delete reports that nothing was overridden"
        );

        RateLimitRepository::reset(&pool, &key, cfg.action)
            .await
            .unwrap();
    }

    /// BUNYIP-413: the super-admin gate is a property of the account, so only
    /// the flagged admin passes it. Exercises the same predicate the
    /// `SuperAdminUser` extractor applies, against real rows.
    #[actix_rt::test]
    async fn only_the_flagged_admin_passes_the_super_admin_gate() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        use crate::middleware::super_admin_allowed;

        let plain_admin =
            insert_user(&pool, &format!("rl-admin-{}@example.com", Uuid::new_v4())).await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = $1")
            .bind(plain_admin)
            .execute(&pool)
            .await
            .unwrap();
        let super_admin =
            insert_user(&pool, &format!("rl-super-{}@example.com", Uuid::new_v4())).await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = $1")
            .bind(super_admin)
            .execute(&pool)
            .await
            .unwrap();
        UserRepository::set_super_admin(&pool, super_admin, true)
            .await
            .unwrap();

        let load = |id: Uuid| {
            let pool = pool.clone();
            async move {
                let u = UserRepository::find_by_id(&pool, id)
                    .await
                    .unwrap()
                    .unwrap();
                (u.role, u.is_super_admin)
            }
        };

        let (role, flag) = load(plain_admin).await;
        assert!(
            !super_admin_allowed(&role, flag),
            "an ordinary admin must be refused"
        );
        let (role, flag) = load(super_admin).await;
        assert!(super_admin_allowed(&role, flag), "the super admin passes");

        delete_user(&pool, plain_admin).await;
        delete_user(&pool, super_admin).await;
    }

    /// An unknown action and a non-uuid key for a pseudo-action are rejected
    /// before any state is touched.
    #[actix_rt::test]
    async fn reset_rejects_bad_input() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        assert!(apply_rate_limit_reset(&pool, "not_a_real_action", "k")
            .await
            .is_err());
        assert!(
            apply_rate_limit_reset(&pool, "email_verification", "not-a-uuid")
                .await
                .is_err()
        );
    }
}
