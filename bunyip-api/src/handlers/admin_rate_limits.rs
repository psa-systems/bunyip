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
use crate::models::{AuditAction, CreateAuditLog, KeySubject, RateLimit, RateLimitConfig};
use crate::repositories::{
    AuditLogRepository, EmailResendLimiterRow, RateLimitRepository, TokenRepository, UserRepository,
};
use crate::responses::{get_request_id, paginated, success_no_data};
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
                KeySubject::Ip(_) | KeySubject::Unknown(_) => None,
            };

            RateLimitRepository::reset(pool, key, action).await?;

            Ok(target)
        }
    }
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
