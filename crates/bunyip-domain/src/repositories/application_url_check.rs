//! Repository for the application URL health check history (BUNYIP-1089).

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::application_url_check::{ApplicationUrlCheck, CreateApplicationUrlCheck};

pub struct ApplicationUrlCheckRepository;

impl ApplicationUrlCheckRepository {
    pub async fn create(
        pool: &PgPool,
        data: &CreateApplicationUrlCheck,
    ) -> Result<ApplicationUrlCheck, AppError> {
        let row = sqlx::query_as::<_, ApplicationUrlCheck>(
            "INSERT INTO application_url_checks \
                 (application_id, status, http_status, latency_ms, error_detail) \
             VALUES ($1, $2, $3, $4, $5) RETURNING *",
        )
        .bind(data.application_id)
        .bind(data.status)
        .bind(data.http_status)
        .bind(data.latency_ms)
        .bind(data.error_detail.as_deref())
        .fetch_one(pool)
        .await?;
        Ok(row)
    }

    /// Delete rows older than `cutoff`. Returns the number evicted.
    pub async fn evict_before(pool: &PgPool, cutoff: DateTime<Utc>) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM application_url_checks WHERE checked_at < $1")
            .bind(cutoff)
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// The most recent check per application id, as a map. Used by the admin
    /// list to render the Last-check column in one query rather than N.
    pub async fn latest_per_application(
        pool: &PgPool,
        ids: &[Uuid],
    ) -> Result<Vec<ApplicationUrlCheck>, AppError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        // DISTINCT ON picks the newest row per application id in one pass.
        let rows = sqlx::query_as::<_, ApplicationUrlCheck>(
            "SELECT DISTINCT ON (application_id) * FROM application_url_checks \
             WHERE application_id = ANY($1) \
             ORDER BY application_id, checked_at DESC",
        )
        .bind(ids)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }
}
