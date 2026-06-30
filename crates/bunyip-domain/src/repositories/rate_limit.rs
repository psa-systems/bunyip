//! Rate limit repository

use chrono::{Duration, Utc};
use sqlx::PgPool;

use crate::errors::AppError;
use crate::models::RateLimitConfig;

pub struct RateLimitRepository;

impl RateLimitRepository {
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
    pub async fn check_and_increment(
        pool: &PgPool,
        key: &str,
        config: &RateLimitConfig,
    ) -> Result<(i32, bool), AppError> {
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

    /// Check rate limit without incrementing
    pub async fn check(
        pool: &PgPool,
        key: &str,
        config: &RateLimitConfig,
    ) -> Result<(i32, bool), AppError> {
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

    /// Cleanup expired rate limit entries
    pub async fn cleanup_expired(pool: &PgPool) -> Result<u64, AppError> {
        // Delete entries older than 1 hour (longer than any window)
        let result = sqlx::query(
            r#"
            DELETE FROM rate_limits
            WHERE window_start < NOW() - INTERVAL '1 hour'
            "#,
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get time until rate limit resets
    pub async fn get_retry_after(
        pool: &PgPool,
        key: &str,
        config: &RateLimitConfig,
    ) -> Result<u64, AppError> {
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
