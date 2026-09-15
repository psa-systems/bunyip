//! BUNYIP-692: repository for the org-tier catalogue and per-org tier
//! selection.
//!
//! Thin SQL over `org_pricing_tiers` and `organizations.org_tier_id`. The
//! `orgs_enabled` flag is enforced by the service layer above, not here,
//! so the repository stays reusable from a background task that has
//! already decided the flag is on.

use sqlx::{Error as SqlxError, PgPool};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{OrgPricingTier, Organization};

pub struct OrgPricingRepository;

impl OrgPricingRepository {
    pub async fn create(
        pool: &PgPool,
        name: &str,
        stripe_price_id: &str,
        included_seats: i32,
        seat_cap: Option<i32>,
        visibility: &str,
        sort_order: i32,
    ) -> Result<OrgPricingTier, AppError> {
        sqlx::query_as::<_, OrgPricingTier>(
            "INSERT INTO org_pricing_tiers \
             (name, stripe_price_id, included_seats, seat_cap, visibility, sort_order) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
        )
        .bind(name)
        .bind(stripe_price_id)
        .bind(included_seats)
        .bind(seat_cap)
        .bind(visibility)
        .bind(sort_order)
        .fetch_one(pool)
        .await
        .map_err(map_sqlx)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<OrgPricingTier>, AppError> {
        sqlx::query_as::<_, OrgPricingTier>("SELECT * FROM org_pricing_tiers WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(map_sqlx)
    }

    /// Every tier the admin has configured, ordered by `sort_order` then
    /// `created_at`. Used by the admin CRUD list; the public path filters
    /// with `list_public`.
    pub async fn list_all(pool: &PgPool) -> Result<Vec<OrgPricingTier>, AppError> {
        sqlx::query_as::<_, OrgPricingTier>(
            "SELECT * FROM org_pricing_tiers ORDER BY sort_order ASC, created_at ASC",
        )
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)
    }

    /// Only tiers with `visibility = 'public'`. Used by the public pricing
    /// endpoint. A hidden tier stays reachable through the admin CRUD and
    /// through an existing org that already picked it, but the public
    /// catalogue does not surface it.
    pub async fn list_public(pool: &PgPool) -> Result<Vec<OrgPricingTier>, AppError> {
        sqlx::query_as::<_, OrgPricingTier>(
            "SELECT * FROM org_pricing_tiers \
             WHERE visibility = 'public' \
             ORDER BY sort_order ASC, created_at ASC",
        )
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)
    }

    /// Partial update. Only fields the caller supplied are written; every
    /// unset field is left alone. `COALESCE($n, column)` keeps the SQL a
    /// single UPDATE that fires the `updated_at` trigger once.
    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        name: Option<&str>,
        stripe_price_id: Option<&str>,
        included_seats: Option<i32>,
        seat_cap: Option<Option<i32>>,
        visibility: Option<&str>,
        sort_order: Option<i32>,
    ) -> Result<OrgPricingTier, AppError> {
        // `seat_cap` is a double Option so the caller can distinguish
        // "leave alone" from "set to NULL"; the CASE expression below picks
        // which one applied.
        let seat_cap_touched = seat_cap.is_some();
        let seat_cap_value = seat_cap.flatten();

        sqlx::query_as::<_, OrgPricingTier>(
            "UPDATE org_pricing_tiers SET \
                name = COALESCE($2, name), \
                stripe_price_id = COALESCE($3, stripe_price_id), \
                included_seats = COALESCE($4, included_seats), \
                seat_cap = CASE WHEN $5 THEN $6 ELSE seat_cap END, \
                visibility = COALESCE($7, visibility), \
                sort_order = COALESCE($8, sort_order), \
                updated_at = NOW() \
             WHERE id = $1 RETURNING *",
        )
        .bind(id)
        .bind(name)
        .bind(stripe_price_id)
        .bind(included_seats)
        .bind(seat_cap_touched)
        .bind(seat_cap_value)
        .bind(visibility)
        .bind(sort_order)
        .fetch_one(pool)
        .await
        .map_err(map_sqlx)
    }

    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, AppError> {
        let result = sqlx::query("DELETE FROM org_pricing_tiers WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .map_err(map_sqlx)?;
        Ok(result.rows_affected() > 0)
    }

    /// Write `sort_order` for each id in the list to its position in the
    /// list, inside one transaction. Any id NOT in the list keeps its
    /// current `sort_order`; that is deliberate so a partial reorder does
    /// not accidentally reset every other row.
    pub async fn reorder(pool: &PgPool, ids: &[Uuid]) -> Result<(), AppError> {
        let mut tx = pool.begin().await.map_err(map_sqlx)?;
        for (index, id) in ids.iter().enumerate() {
            sqlx::query(
                "UPDATE org_pricing_tiers SET sort_order = $1, updated_at = NOW() WHERE id = $2",
            )
            .bind(index as i32)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(())
    }

    /// Set `organizations.org_tier_id`. `None` clears it (BUNYIP-693 refuses
    /// to subscribe against a cleared tier).
    pub async fn set_organization_tier(
        pool: &PgPool,
        organization_id: Uuid,
        org_tier_id: Option<Uuid>,
    ) -> Result<Organization, AppError> {
        sqlx::query_as::<_, Organization>(
            "UPDATE organizations SET org_tier_id = $1, updated_at = NOW() \
             WHERE id = $2 RETURNING id, owner_bunyip_user_id, name, created_at, updated_at",
        )
        .bind(org_tier_id)
        .bind(organization_id)
        .fetch_one(pool)
        .await
        .map_err(map_sqlx)
    }

    pub async fn get_organization_tier(
        pool: &PgPool,
        organization_id: Uuid,
    ) -> Result<Option<Uuid>, AppError> {
        let row: Option<(Option<Uuid>,)> =
            sqlx::query_as("SELECT org_tier_id FROM organizations WHERE id = $1")
                .bind(organization_id)
                .fetch_optional(pool)
                .await
                .map_err(map_sqlx)?;
        Ok(row.and_then(|(v,)| v))
    }
}

fn map_sqlx(e: SqlxError) -> AppError {
    if let SqlxError::Database(db_err) = &e {
        if db_err.code().as_deref() == Some("23505") {
            return AppError::conflict(db_err.message().to_string());
        }
        // `23503` is foreign_key_violation: e.g. deleting a tier an org
        // still references. Surface it as a Conflict so the admin sees a
        // 409 rather than a raw 500.
        if db_err.code().as_deref() == Some("23503") {
            return AppError::conflict(db_err.message().to_string());
        }
    }
    AppError::from(e)
}
