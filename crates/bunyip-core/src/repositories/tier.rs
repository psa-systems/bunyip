//! Tier configuration repository (singleton, id=1)

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::tier::TierConfigRow;

pub struct TierConfigRepository;

impl TierConfigRepository {
    pub async fn get(pool: &PgPool) -> Result<TierConfigRow, AppError> {
        let row = sqlx::query_as::<_, TierConfigRow>("SELECT * FROM tier_config WHERE id = 1")
            .fetch_one(pool)
            .await?;
        Ok(row)
    }

    /// Updates only the fields that are `Some`. `None` leaves the existing DB value unchanged.
    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        pool: &PgPool,
        lifetime_slots: Option<i64>,
        early_adopter_slots: Option<i64>,
        early_adopter_trial_days: Option<i64>,
        standard_trial_days: Option<i64>,
        free_price_id: Option<String>,
        early_adopter_price_id: Option<String>,
        standard_price_id: Option<String>,
        lifetime_product_id: Option<String>,
        early_adopter_product_id: Option<String>,
        standard_product_id: Option<String>,
        updated_by: Uuid,
    ) -> Result<TierConfigRow, AppError> {
        let row = sqlx::query_as::<_, TierConfigRow>(
            r#"
            UPDATE tier_config
            SET
                lifetime_slots           = COALESCE($1,  lifetime_slots),
                early_adopter_slots      = COALESCE($2,  early_adopter_slots),
                early_adopter_trial_days = COALESCE($3,  early_adopter_trial_days),
                standard_trial_days      = COALESCE($4,  standard_trial_days),
                free_price_id            = COALESCE($5,  free_price_id),
                early_adopter_price_id   = COALESCE($6,  early_adopter_price_id),
                standard_price_id        = COALESCE($7,  standard_price_id),
                lifetime_product_id      = COALESCE($8,  lifetime_product_id),
                early_adopter_product_id = COALESCE($9,  early_adopter_product_id),
                standard_product_id      = COALESCE($10, standard_product_id),
                updated_at               = NOW(),
                updated_by               = $11
            WHERE id = 1
            RETURNING *
            "#,
        )
        .bind(lifetime_slots)
        .bind(early_adopter_slots)
        .bind(early_adopter_trial_days)
        .bind(standard_trial_days)
        .bind(free_price_id)
        .bind(early_adopter_price_id)
        .bind(standard_price_id)
        .bind(lifetime_product_id)
        .bind(early_adopter_product_id)
        .bind(standard_product_id)
        .bind(updated_by)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }
}
