//! Persisted rate-limit configuration (BUNYIP-413).
//!
//! One optional `rate_limit_configs` row per known [`RateLimitConfig`] action.
//! Absent means "use the bootstrap default" (the compile-time const with any
//! `RATE_LIMIT_{ACTION}_*` env var applied); present overrides the cap and
//! window for that action everywhere it is enforced. The enforcement path
//! resolves the effective config through [`RateLimitConfigRepository::effective`],
//! so a change lands on the next request with no restart.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::RateLimitConfig;

/// A persisted per-action override row.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct RateLimitConfigRow {
    pub action: String,
    pub max_requests: i32,
    pub window_seconds: i64,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

pub struct RateLimitConfigRepository;

impl RateLimitConfigRepository {
    /// Every persisted override, action-ordered.
    pub async fn list(pool: &PgPool) -> Result<Vec<RateLimitConfigRow>, AppError> {
        let rows = sqlx::query_as::<_, RateLimitConfigRow>(
            r#"
            SELECT action, max_requests, window_seconds, updated_at, updated_by
            FROM rate_limit_configs
            ORDER BY action
            "#,
        )
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// The persisted override for `action`, if any.
    pub async fn get(pool: &PgPool, action: &str) -> Result<Option<RateLimitConfigRow>, AppError> {
        let row = sqlx::query_as::<_, RateLimitConfigRow>(
            r#"
            SELECT action, max_requests, window_seconds, updated_at, updated_by
            FROM rate_limit_configs
            WHERE action = $1
            "#,
        )
        .bind(action)
        .fetch_optional(pool)
        .await?;
        Ok(row)
    }

    /// Create or update the override for `action`. `updated_by` is the acting
    /// super admin. Returns the stored row.
    pub async fn upsert(
        pool: &PgPool,
        action: &str,
        max_requests: i32,
        window_seconds: i64,
        updated_by: Option<Uuid>,
    ) -> Result<RateLimitConfigRow, AppError> {
        let row = sqlx::query_as::<_, RateLimitConfigRow>(
            r#"
            INSERT INTO rate_limit_configs (action, max_requests, window_seconds, updated_by)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (action) DO UPDATE
                SET max_requests = EXCLUDED.max_requests,
                    window_seconds = EXCLUDED.window_seconds,
                    updated_at = NOW(),
                    updated_by = EXCLUDED.updated_by
            RETURNING action, max_requests, window_seconds, updated_at, updated_by
            "#,
        )
        .bind(action)
        .bind(max_requests)
        .bind(window_seconds)
        .bind(updated_by)
        .fetch_one(pool)
        .await?;
        Ok(row)
    }

    /// Drop the override for `action`, reverting it to the bootstrap default.
    /// Returns true when a row was actually removed.
    pub async fn delete(pool: &PgPool, action: &str) -> Result<bool, AppError> {
        let result = sqlx::query("DELETE FROM rate_limit_configs WHERE action = $1")
            .bind(action)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// The config actually enforced for `base`: the bootstrap default (const +
    /// env) with the persisted row's cap/window applied when one exists. Every
    /// enforcement entry point resolves through here, so an override takes
    /// effect at every call site for that action.
    pub async fn effective(
        pool: &PgPool,
        base: &RateLimitConfig,
    ) -> Result<RateLimitConfig, AppError> {
        let base = base.with_env_defaults();
        match Self::get(pool, base.action).await? {
            Some(row) => Ok(base.with_overrides(Some(row.max_requests), Some(row.window_seconds))),
            None => Ok(base),
        }
    }
}
