//! Rate limit repository

use chrono::{Duration, Utc};
use sqlx::PgPool;

use crate::errors::AppError;
use crate::models::{RateLimit, RateLimitConfig};
use crate::repositories::RateLimitConfigRepository;

pub struct RateLimitRepository;

impl RateLimitRepository {
    /// Candidate rows for the admin "currently rate-limited" view (BUNYIP-315):
    /// every `rate_limits` row whose window could still be open, i.e. started
    /// within the longest window currently in force. The caller decides which of
    /// these are *actually* active by re-checking each row against its action's
    /// effective config (`RateLimit::active_retry_after`), so the cap/window
    /// stay sourced from `RateLimitConfig` and are never re-encoded in SQL.
    /// Newest window first.
    pub async fn list_active(pool: &PgPool) -> Result<Vec<RateLimit>, AppError> {
        let horizon = Utc::now() - Duration::seconds(Self::max_window_seconds(pool).await?);
        let rows = sqlx::query_as::<_, RateLimit>(
            r#"
            SELECT id, key, action, count, window_start
            FROM rate_limits
            WHERE window_start > $1
            ORDER BY window_start DESC
            "#,
        )
        .bind(horizon)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// The longest window in force across every known action, with env and
    /// persisted overrides applied (BUNYIP-413). The retention horizon for the
    /// `rate_limits` table: a row older than this cannot belong to an open
    /// window. Previously a hard-coded hour, which a super-admin-configured
    /// longer window would have silently invalidated.
    pub async fn max_window_seconds(pool: &PgPool) -> Result<i64, AppError> {
        let overrides = RateLimitConfigRepository::list(pool).await?;
        let longest = RateLimitConfig::ALL
            .iter()
            .map(|cfg| {
                let effective = cfg.with_env_defaults();
                overrides
                    .iter()
                    .find(|row| row.action == effective.action)
                    .map(|row| row.window_seconds)
                    .unwrap_or(effective.window_seconds)
            })
            .max()
            .unwrap_or(3600);
        Ok(longest)
    }

    /// BUNYIP-264: convenience wrapper combining `check_and_increment`
    /// with `get_retry_after` so any handler can call a single function
    /// to enforce a rate limit. Returns `Ok(())` when under the cap and
    /// `Err(AppError::RateLimited)` with an accurate `retry_after`
    /// when over. Mirrors the bunyip-api private `check_rate_limit` that
    /// every auth handler uses; lifted here so bunyip-oidc handlers can
    /// share it without crossing the dependency direction.
    pub async fn check_rate_limit(
        pool: &PgPool,
        key: &str,
        config: &RateLimitConfig,
    ) -> Result<(), AppError> {
        let (_count, exceeded) = Self::check_and_increment(pool, key, config).await?;
        if exceeded {
            let retry_after = Self::get_retry_after(pool, key, config).await?;
            return Err(AppError::RateLimited { retry_after });
        }
        Ok(())
    }

    /// Check if rate limit is exceeded and increment counter
    /// Returns the current count and whether the limit is exceeded
    ///
    /// BUNYIP-413: `config` is the caller's bootstrap preset; the cap/window
    /// actually enforced are resolved here, so a persisted override applies at
    /// every enforcement site without touching any of them.
    pub async fn check_and_increment(
        pool: &PgPool,
        key: &str,
        config: &RateLimitConfig,
    ) -> Result<(i32, bool), AppError> {
        let config = &RateLimitConfigRepository::effective(pool, config).await?;
        let window_start = Utc::now() - Duration::seconds(config.window_seconds);

        // Try to insert or update the rate limit entry
        let result = sqlx::query_as::<_, (i32,)>(
            r#"
            INSERT INTO rate_limits (key, action, count, window_start)
            VALUES ($1, $2, 1, NOW())
            ON CONFLICT (key, action)
            DO UPDATE SET
                count = CASE
                    WHEN rate_limits.window_start < $3 THEN 1
                    ELSE rate_limits.count + 1
                END,
                window_start = CASE
                    WHEN rate_limits.window_start < $3 THEN NOW()
                    ELSE rate_limits.window_start
                END
            RETURNING count
            "#,
        )
        .bind(key)
        .bind(config.action)
        .bind(window_start)
        .fetch_one(pool)
        .await?;

        let count = result.0;
        let exceeded = count > config.max_requests;

        Ok((count, exceeded))
    }

    /// Check rate limit without incrementing. Resolves the effective config the
    /// same way [`check_and_increment`](Self::check_and_increment) does.
    pub async fn check(
        pool: &PgPool,
        key: &str,
        config: &RateLimitConfig,
    ) -> Result<(i32, bool), AppError> {
        let config = &RateLimitConfigRepository::effective(pool, config).await?;
        let window_start = Utc::now() - Duration::seconds(config.window_seconds);

        let result = sqlx::query_as::<_, (i32,)>(
            r#"
            SELECT COALESCE(
                (SELECT count FROM rate_limits
                 WHERE key = $1 AND action = $2 AND window_start >= $3),
                0
            )
            "#,
        )
        .bind(key)
        .bind(config.action)
        .bind(window_start)
        .fetch_one(pool)
        .await?;

        let count = result.0;
        let exceeded = count > config.max_requests;

        Ok((count, exceeded))
    }

    /// Reset rate limit for a specific key and action
    pub async fn reset(pool: &PgPool, key: &str, action: &str) -> Result<(), AppError> {
        sqlx::query(
            r#"
            DELETE FROM rate_limits WHERE key = $1 AND action = $2
            "#,
        )
        .bind(key)
        .bind(action)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Cleanup expired rate limit entries: anything older than the longest
    /// window currently in force, so a super-admin-configured long window is
    /// never swept out from under an open throttle (BUNYIP-413).
    pub async fn cleanup_expired(pool: &PgPool) -> Result<u64, AppError> {
        let horizon = Utc::now() - Duration::seconds(Self::max_window_seconds(pool).await?);
        let result = sqlx::query(
            r#"
            DELETE FROM rate_limits
            WHERE window_start < $1
            "#,
        )
        .bind(horizon)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get time until rate limit resets. Resolves the effective window the same
    /// way the enforcement path does, so the `retry_after` a client is told
    /// matches the window actually in force.
    pub async fn get_retry_after(
        pool: &PgPool,
        key: &str,
        config: &RateLimitConfig,
    ) -> Result<u64, AppError> {
        let config = &RateLimitConfigRepository::effective(pool, config).await?;
        let result = sqlx::query_as::<_, (chrono::DateTime<Utc>,)>(
            r#"
            SELECT window_start FROM rate_limits
            WHERE key = $1 AND action = $2
            "#,
        )
        .bind(key)
        .bind(config.action)
        .fetch_optional(pool)
        .await?;

        match result {
            Some((window_start,)) => {
                let reset_at = window_start + Duration::seconds(config.window_seconds);
                let retry_after = (reset_at - Utc::now()).num_seconds();
                Ok(retry_after.max(0) as u64)
            }
            None => Ok(0),
        }
    }
}
