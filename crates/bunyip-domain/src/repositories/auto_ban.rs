//! Auto-ban configuration repository (singleton, id=1) — BUNYIP-351

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::auto_ban::AutoBanConfigRow;

pub struct AutoBanConfigRepository;

impl AutoBanConfigRepository {
    pub async fn get(pool: &PgPool) -> Result<AutoBanConfigRow, AppError> {
        let row =
            sqlx::query_as::<_, AutoBanConfigRow>("SELECT * FROM auto_ban_config WHERE id = 1")
                .fetch_one(pool)
                .await?;
        Ok(row)
    }

    /// Updates only the fields that are `Some`. `None` leaves the existing DB
    /// value unchanged (COALESCE), matching the tier/stripe config pattern.
    pub async fn update(
        pool: &PgPool,
        enabled: Option<bool>,
        threshold: Option<i64>,
        window_secs: Option<i64>,
        ban_duration_secs: Option<i64>,
        updated_by: Uuid,
    ) -> Result<AutoBanConfigRow, AppError> {
        let row = sqlx::query_as::<_, AutoBanConfigRow>(
            r#"
            UPDATE auto_ban_config
            SET
                enabled           = COALESCE($1, enabled),
                threshold         = COALESCE($2, threshold),
                window_secs       = COALESCE($3, window_secs),
                ban_duration_secs = COALESCE($4, ban_duration_secs),
                updated_at        = NOW(),
                updated_by        = $5
            WHERE id = 1
            RETURNING *
            "#,
        )
        .bind(enabled)
        .bind(threshold)
        .bind(window_secs)
        .bind(ban_duration_secs)
        .bind(updated_by)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }
}
