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
use crate::middleware::AdminUser;
use crate::models::{KeySubject, RateLimit, RateLimitConfig};
use crate::repositories::{
    EmailResendLimiterRow, RateLimitRepository, TokenRepository, UserRepository,
};
use crate::responses::{get_request_id, paginated};
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
    //    at or over the cap. Cap/window come from the action's preset; a row
    //    whose action has no preset is skipped (we cannot judge it active).
    for row in RateLimitRepository::list_active(pool.get_ref()).await? {
        let Some(cfg) = RateLimitConfig::by_action(&row.action) else {
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
            KeySubject::Ip(_) | KeySubject::Unknown(_) => None,
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
