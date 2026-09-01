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
    ///
    /// BUNYIP-527: the six Stripe id columns are three-state. `None` (omitted)
    /// keeps the stored value; `Some("")` (an explicit empty string) CLEARS the
    /// column to NULL; `Some(id)` sets it. This is what lets the catalog "(none)"
    /// selection actually unmap a tier, distinct from a slots/trial-only save that
    /// simply omits the price columns. The numeric slots/trials and the
    /// `pricing_enabled` / `orgs_enabled` switches stay plain `COALESCE`
    /// (keep-on-None).
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
        pricing_enabled: Option<bool>,
        lifetime_visible: Option<bool>,
        early_adopter_visible: Option<bool>,
        standard_visible: Option<bool>,
        orgs_enabled: Option<bool>,
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
                free_price_id            = CASE WHEN $5  IS NULL THEN free_price_id            WHEN $5  = '' THEN NULL ELSE $5  END,
                early_adopter_price_id   = CASE WHEN $6  IS NULL THEN early_adopter_price_id   WHEN $6  = '' THEN NULL ELSE $6  END,
                standard_price_id        = CASE WHEN $7  IS NULL THEN standard_price_id        WHEN $7  = '' THEN NULL ELSE $7  END,
                lifetime_product_id      = CASE WHEN $8  IS NULL THEN lifetime_product_id      WHEN $8  = '' THEN NULL ELSE $8  END,
                early_adopter_product_id = CASE WHEN $9  IS NULL THEN early_adopter_product_id WHEN $9  = '' THEN NULL ELSE $9  END,
                standard_product_id      = CASE WHEN $10 IS NULL THEN standard_product_id      WHEN $10 = '' THEN NULL ELSE $10 END,
                pricing_enabled          = COALESCE($11, pricing_enabled),
                lifetime_visible         = COALESCE($12, lifetime_visible),
                early_adopter_visible    = COALESCE($13, early_adopter_visible),
                standard_visible         = COALESCE($14, standard_visible),
                orgs_enabled             = COALESCE($15, orgs_enabled),
                updated_at               = NOW(),
                updated_by               = $16
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
        .bind(pricing_enabled)
        .bind(lifetime_visible)
        .bind(early_adopter_visible)
        .bind(standard_visible)
        .bind(orgs_enabled)
        .bind(updated_by)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }
}
