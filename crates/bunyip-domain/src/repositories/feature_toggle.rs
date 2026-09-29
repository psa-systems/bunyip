//! `feature_toggles` rows (BUNYIP-840). The registry itself is
//! [`crate::feature_toggles::Feature`]; this module only reads and writes the
//! stored states.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::errors::AppError;
use crate::feature_toggles::FeatureToggles;

/// One stored toggle. `key` may name a feature this build no longer knows.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct FeatureToggleRow {
    pub key: String,
    pub enabled: bool,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

pub struct FeatureToggleRepository;

impl FeatureToggleRepository {
    pub async fn get_all(pool: &PgPool) -> Result<Vec<FeatureToggleRow>, AppError> {
        Ok(sqlx::query_as::<_, FeatureToggleRow>(
            "SELECT key, enabled, updated_at, updated_by FROM feature_toggles ORDER BY key",
        )
        .fetch_all(pool)
        .await?)
    }

    /// Read every row and resolve it against the registry.
    pub async fn load(pool: &PgPool) -> Result<FeatureToggles, AppError> {
        let rows = Self::get_all(pool).await?;
        Ok(FeatureToggles::from_rows(
            rows.iter().map(|r| (r.key.as_str(), r.enabled)),
        ))
    }

    /// Upsert one toggle. Takes an executor so the caller can pair it with its
    /// audit row in one transaction.
    pub async fn set<'e, E>(
        exec: E,
        key: &str,
        enabled: bool,
        updated_by: Option<Uuid>,
    ) -> Result<FeatureToggleRow, AppError>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        Ok(sqlx::query_as::<_, FeatureToggleRow>(
            "INSERT INTO feature_toggles (key, enabled, updated_at, updated_by) \
             VALUES ($1, $2, NOW(), $3) \
             ON CONFLICT (key) DO UPDATE SET enabled = EXCLUDED.enabled, \
             updated_at = NOW(), updated_by = EXCLUDED.updated_by \
             RETURNING key, enabled, updated_at, updated_by",
        )
        .bind(key)
        .bind(enabled)
        .bind(updated_by)
        .fetch_one(exec)
        .await?)
    }
}
