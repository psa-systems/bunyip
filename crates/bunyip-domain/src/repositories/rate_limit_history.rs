//! Durable record of past rate-limit breaches.
//!
//! A row lands here each time `RateLimitRepository::check_and_increment`
//! transitions a key from under-cap to over-cap. The `rate_limits` row that
//! drives enforcement is overwritten on the next window reset, so the
//! fired-at and expires-at carried on that row disappear with it; this table
//! keeps them readable for the admin page.
//!
//! Retention: 24 hours, swept by the background task in `bunyip-api/main.rs`.
//! Older rows are not useful for the "has a rate limit fired recently"
//! question the admin page answers.

use chrono::{DateTime, Duration, Utc};
use sqlx::{types::Uuid, FromRow, PgPool};

use crate::errors::AppError;
use crate::models::RateLimitConfig;

/// One recorded throttle event. Columns mirror the schema in migration
/// `20261008000010_rate_limit_history.sql`.
#[derive(Debug, Clone, FromRow)]
pub struct RateLimitHistory {
    pub id: Uuid,
    pub action: String,
    pub key: String,
    pub fired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Read/write path for `rate_limit_history`.
///
/// Writes are best-effort: the admin page's history is a secondary record of
/// enforcement, so a dropped INSERT must never block the 429 the operator is
/// actually trying to serve. Callers log the error and move on.
pub struct RateLimitHistoryRepository;

impl RateLimitHistoryRepository {
    /// Record a throttle event. Called from `check_and_increment` the first
    /// time a key crosses the cap in a window, so one row per event.
    ///
    /// `expires_at` is `fired_at + window_seconds`, which is when the next
    /// successful request from the same key would reset the enforcement
    /// row's `window_start`. Carrying it on the history row means the admin
    /// page can show "fired 11:03, released 11:18" without a second query.
    pub async fn record(
        pool: &PgPool,
        action: &str,
        key: &str,
        config: &RateLimitConfig,
        window_start: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let expires_at = window_start + Duration::seconds(config.window_seconds);
        sqlx::query(
            r#"
            INSERT INTO rate_limit_history (action, key, fired_at, expires_at)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(action)
        .bind(key)
        .bind(window_start)
        .bind(expires_at)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// List throttle events in `[since, now]`, newest first, capped at
    /// `limit`. The admin page's past-throttles section reads through this.
    pub async fn list(
        pool: &PgPool,
        since: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<RateLimitHistory>, AppError> {
        let rows = sqlx::query_as::<_, RateLimitHistory>(
            r#"
            SELECT id, action, key, fired_at, expires_at
            FROM rate_limit_history
            WHERE fired_at >= $1
            ORDER BY fired_at DESC
            LIMIT $2
            "#,
        )
        .bind(since)
        .bind(limit)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Delete rows older than `retention_seconds`. Returns the number of
    /// rows deleted, matching `RateLimitRepository::cleanup_expired`.
    pub async fn sweep(pool: &PgPool, retention_seconds: i64) -> Result<u64, AppError> {
        let horizon = Utc::now() - Duration::seconds(retention_seconds);
        let result = sqlx::query("DELETE FROM rate_limit_history WHERE fired_at < $1")
            .bind(horizon)
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }
}
