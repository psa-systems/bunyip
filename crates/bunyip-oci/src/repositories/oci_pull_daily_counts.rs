//! DB access for the `oci_pull_daily_counts` table.
//!
//! Implements the dunite-oci [`PullCounter`](dunite_oci::store::PullCounter)
//! trait against Bunyip's Postgres schema, so the generic
//! [`OciLimiter`](dunite_oci::services::OciLimiter) can enforce per-user daily
//! pull caps without depending on the schema.

use async_trait::async_trait;
use chrono::NaiveDate;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;

/// Postgres-backed per-user daily pull counter.
#[derive(Clone)]
pub struct OciPullDailyCountRepository {
    pool: PgPool,
}

impl OciPullDailyCountRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Atomically increment today's count for a user. Returns the new count.
    pub async fn increment(&self, user_id: Uuid, day_utc: NaiveDate) -> Result<i32, AppError> {
        let (count,): (i32,) = sqlx::query_as(
            "INSERT INTO oci_pull_daily_counts (user_id, day_utc, count)
             VALUES ($1, $2, 1)
             ON CONFLICT (user_id, day_utc) DO UPDATE
                 SET count = oci_pull_daily_counts.count + 1
             RETURNING count",
        )
        .bind(user_id)
        .bind(day_utc)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    /// Decrement today's count by 1 (best-effort rollback). Never goes below 0.
    pub async fn decrement(&self, user_id: Uuid, day_utc: NaiveDate) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE oci_pull_daily_counts SET count = GREATEST(count - 1, 0)
             WHERE user_id = $1 AND day_utc = $2",
        )
        .bind(user_id)
        .bind(day_utc)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn current(&self, user_id: Uuid, day_utc: NaiveDate) -> Result<i32, AppError> {
        let row: Option<(i32,)> = sqlx::query_as(
            "SELECT count FROM oci_pull_daily_counts WHERE user_id = $1 AND day_utc = $2",
        )
        .bind(user_id)
        .bind(day_utc)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(c,)| c).unwrap_or(0))
    }
}

/// Wire the Postgres repository to the engine's counter trait.
///
/// `PullCounter` is dunite-core's generic `UsageCounter` (re-exported by
/// dunite-oci), so only `increment` / `decrement` are part of the trait;
/// `current` stays as an inherent method for tests and diagnostics.
#[async_trait]
impl dunite_oci::store::PullCounter for OciPullDailyCountRepository {
    async fn increment(&self, user_id: Uuid, day: NaiveDate) -> Result<i32, AppError> {
        OciPullDailyCountRepository::increment(self, user_id, day).await
    }

    async fn decrement(&self, user_id: Uuid, day: NaiveDate) -> Result<(), AppError> {
        OciPullDailyCountRepository::decrement(self, user_id, day).await
    }
}

#[cfg(test)]
mod tests {
    //! DB-backed. Skipped when DATABASE_URL is unset.
    use super::*;
    use chrono::Utc;

    async fn maybe_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        PgPool::connect(&url).await.ok()
    }

    #[actix_rt::test]
    async fn increment_creates_and_bumps() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = OciPullDailyCountRepository::new(pool.clone());

        // Insert a test user with only required columns; let DB defaults fill the rest.
        let user_id = Uuid::new_v4();
        let email = format!("oci-count-test-{}@example.com", user_id);
        let res = sqlx::query(
            "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, 'placeholder')",
        )
        .bind(user_id)
        .bind(&email)
        .execute(&pool)
        .await;
        if res.is_err() {
            // Schema requires more fields — skip this test rather than guessing.
            return;
        }

        let today = Utc::now().date_naive();

        // Clean leftover from previous runs.
        sqlx::query("DELETE FROM oci_pull_daily_counts WHERE user_id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .ok();

        assert_eq!(repo.increment(user_id, today).await.unwrap(), 1);
        assert_eq!(repo.increment(user_id, today).await.unwrap(), 2);
        assert_eq!(repo.current(user_id, today).await.unwrap(), 2);

        repo.decrement(user_id, today).await.unwrap();
        assert_eq!(repo.current(user_id, today).await.unwrap(), 1);

        // Decrement twice more — hitting GREATEST floor.
        repo.decrement(user_id, today).await.unwrap();
        repo.decrement(user_id, today).await.unwrap();
        assert_eq!(repo.current(user_id, today).await.unwrap(), 0);

        // Cleanup
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .ok();
    }
}
