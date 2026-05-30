//! Per-user per-day download counter.

use chrono::NaiveDate;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;

pub struct DownloadDailyCountRepository;

impl DownloadDailyCountRepository {
    /// Increments the count for `(user_id, day)` by 1 and returns the new value.
    pub async fn increment(pool: &PgPool, user_id: Uuid, day: NaiveDate) -> Result<i32, AppError> {
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
        .fetch_one(pool)
        .await?;
        Ok(count)
    }

    /// Decrement on failed download (counted optimistically, roll back on failure).
    pub async fn decrement(pool: &PgPool, user_id: Uuid, day: NaiveDate) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE download_daily_counts
            SET count = GREATEST(count - 1, 0)
            WHERE user_id = $1 AND day = $2
            "#,
        )
        .bind(user_id)
        .bind(day)
        .execute(pool)
        .await?;
        Ok(())
    }
}
