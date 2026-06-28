//! Per-user per-day download counter.
//!
//! Implements the dunite-download [`DownloadCounter`](dunite_download::store::DownloadCounter)
//! trait (dunite-core's `UsageCounter`) against Bunyip's Postgres schema, so the
//! generic [`DownloadLimiter`](dunite_download::services::DownloadLimiter) can
//! enforce daily caps without depending on the schema.

use async_trait::async_trait;
use chrono::NaiveDate;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;

/// Postgres-backed per-user daily download counter.
#[derive(Clone)]
pub struct DownloadDailyCountRepository {
    pool: PgPool,
}

impl DownloadDailyCountRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Increments the count for `(user_id, day)` by 1 and returns the new value.
    pub async fn increment(&self, user_id: Uuid, day: NaiveDate) -> Result<i32, AppError> {
        let (count,): (i32,) = sqlx::query_as(
            r#"
            INSERT INTO download_daily_counts (user_id, day, count)
            VALUES ($1, $2, 1)
            ON CONFLICT (user_id, day)
            DO UPDATE SET count = download_daily_counts.count + 1
            RETURNING count
            "#,
        )
        .bind(user_id)
        .bind(day)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    /// Decrement on failed download (counted optimistically, roll back on failure).
    pub async fn decrement(&self, user_id: Uuid, day: NaiveDate) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE download_daily_counts
            SET count = GREATEST(count - 1, 0)
            WHERE user_id = $1 AND day = $2
            "#,
        )
        .bind(user_id)
        .bind(day)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// Wire the Postgres repository to the engine's counter trait.
#[async_trait]
impl dunite_download::store::DownloadCounter for DownloadDailyCountRepository {
    async fn increment(&self, user_id: Uuid, day: NaiveDate) -> Result<i32, AppError> {
        DownloadDailyCountRepository::increment(self, user_id, day).await
    }

    async fn decrement(&self, user_id: Uuid, day: NaiveDate) -> Result<(), AppError> {
        DownloadDailyCountRepository::decrement(self, user_id, day).await
    }
}
