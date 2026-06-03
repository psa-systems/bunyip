//! Per-product entitlement repository (BUNYIP-39).
//!
//! The access decision itself lives in [`crate::services`] callers; this
//! repository only answers "is there an active grant" and performs grant /
//! revoke. Grants are upserted so re-granting a previously revoked entitlement
//! clears `revoked_at` (and refreshes provenance) rather than erroring.

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::entitlement::{ApplicationEntitlement, UserEntitlementRow};

pub struct EntitlementRepository;

impl EntitlementRepository {
    /// Whether the user has an ACTIVE entitlement for the product. This is the
    /// hot-path check called from the OCI and download gates; it is only
    /// consulted for products with `requires_entitlement = TRUE`.
    pub async fn is_entitled(
        pool: &PgPool,
        user_id: Uuid,
        application_id: Uuid,
    ) -> Result<bool, AppError> {
        let exists = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM application_entitlements
                WHERE user_id = $1 AND application_id = $2 AND revoked_at IS NULL
            )
            "#,
        )
        .bind(user_id)
        .bind(application_id)
        .fetch_one(pool)
        .await?;
        Ok(exists)
    }

    /// Grant (or re-activate) an entitlement. Idempotent: a second grant for an
    /// already-active row just refreshes `granted_at`/`granted_by`/`source`.
    pub async fn grant(
        pool: &PgPool,
        user_id: Uuid,
        application_id: Uuid,
        granted_by: Option<Uuid>,
        source: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            INSERT INTO application_entitlements
                (user_id, application_id, granted_by, source, granted_at, revoked_at)
            VALUES ($1, $2, $3, $4, now(), NULL)
            ON CONFLICT (user_id, application_id) DO UPDATE
                SET granted_by = EXCLUDED.granted_by,
                    source     = EXCLUDED.source,
                    granted_at = now(),
                    revoked_at = NULL
            "#,
        )
        .bind(user_id)
        .bind(application_id)
        .bind(granted_by)
        .bind(source)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Revoke an active entitlement (no-op if none active). Returns whether a
    /// row was actually revoked, so callers can audit only real revocations.
    pub async fn revoke(
        pool: &PgPool,
        user_id: Uuid,
        application_id: Uuid,
    ) -> Result<bool, AppError> {
        let affected = sqlx::query(
            r#"
            UPDATE application_entitlements
            SET revoked_at = now()
            WHERE user_id = $1 AND application_id = $2 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .bind(application_id)
        .execute(pool)
        .await?
        .rows_affected();
        Ok(affected > 0)
    }

    /// Revoke every active entitlement for a user that came from a given source
    /// (used by the Stripe webhook: cancelling a subscription revokes only the
    /// Stripe-sourced grants, never an admin's manual grant). Returns the set
    /// of application ids that were revoked, for auditing.
    pub async fn revoke_all_for_user_by_source(
        pool: &PgPool,
        user_id: Uuid,
        source: &str,
    ) -> Result<Vec<Uuid>, AppError> {
        let ids = sqlx::query_scalar::<_, Uuid>(
            r#"
            UPDATE application_entitlements
            SET revoked_at = now()
            WHERE user_id = $1 AND source = $2 AND revoked_at IS NULL
            RETURNING application_id
            "#,
        )
        .bind(user_id)
        .bind(source)
        .fetch_all(pool)
        .await?;
        Ok(ids)
    }

    /// Active entitlements for a user, joined to product display fields, for the
    /// admin "what can this user access" view.
    pub async fn list_for_user(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Vec<UserEntitlementRow>, AppError> {
        let rows = sqlx::query_as::<_, UserEntitlementRow>(
            r#"
            SELECT a.id AS application_id, a.slug, a.display_name,
                   a.requires_entitlement, e.granted_at, e.source
            FROM application_entitlements e
            JOIN applications a ON a.id = e.application_id
            WHERE e.user_id = $1 AND e.revoked_at IS NULL
            ORDER BY a.display_name ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Raw active entitlement rows for a user (no join), for callers that only
    /// need the application ids.
    pub async fn active_application_ids(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>, AppError> {
        let ids = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT application_id FROM application_entitlements
            WHERE user_id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;
        Ok(ids)
    }

    /// The product ids a Stripe price grants (via the price->product mapping).
    pub async fn applications_for_price(
        pool: &PgPool,
        stripe_price_id: &str,
    ) -> Result<Vec<Uuid>, AppError> {
        let ids = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT spe.application_id
            FROM stripe_price_entitlements spe
            JOIN applications a ON a.id = spe.application_id
            WHERE spe.stripe_price_id = $1 AND a.is_active = TRUE
            "#,
        )
        .bind(stripe_price_id)
        .fetch_all(pool)
        .await?;
        Ok(ids)
    }

    /// Map a Stripe price to a product (admin-managed). Idempotent.
    pub async fn add_price_mapping(
        pool: &PgPool,
        stripe_price_id: &str,
        application_id: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            INSERT INTO stripe_price_entitlements (stripe_price_id, application_id)
            VALUES ($1, $2)
            ON CONFLICT (stripe_price_id, application_id) DO NOTHING
            "#,
        )
        .bind(stripe_price_id)
        .bind(application_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Remove a Stripe price->product mapping.
    pub async fn remove_price_mapping(
        pool: &PgPool,
        stripe_price_id: &str,
        application_id: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            DELETE FROM stripe_price_entitlements
            WHERE stripe_price_id = $1 AND application_id = $2
            "#,
        )
        .bind(stripe_price_id)
        .bind(application_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// All active entitlement rows for a product (admin "who can access X").
    pub async fn list_for_application(
        pool: &PgPool,
        application_id: Uuid,
    ) -> Result<Vec<ApplicationEntitlement>, AppError> {
        let rows = sqlx::query_as::<_, ApplicationEntitlement>(
            r#"
            SELECT user_id, application_id, granted_at, granted_by, source, revoked_at
            FROM application_entitlements
            WHERE application_id = $1 AND revoked_at IS NULL
            ORDER BY granted_at DESC
            "#,
        )
        .bind(application_id)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }
}
