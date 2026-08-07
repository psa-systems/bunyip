//! Per-product entitlement repository (BUNYIP-39).
//!
//! [`EntitlementRepository::is_allowed`] is the single per-product access
//! decision every distribution surface calls; the lower-level `is_entitled`
//! /`grant`/`revoke` primitives answer "is there an active grant" and mutate
//! grants. Grants are upserted so re-granting a previously revoked entitlement
//! clears `revoked_at` (and refreshes provenance) rather than erroring.

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::entitlement::UserEntitlementRow;
use crate::models::Application;

pub struct EntitlementRepository;

impl EntitlementRepository {
    /// The full per-product access decision for a member who has already passed
    /// the membership gate (BUNYIP-39). Open products and admins short-circuit
    /// without touching the database; only a restricted product for a
    /// non-admin runs the entitlement lookup. This is the single decision point
    /// every distribution surface (OCI, downloads, web, catalog metadata)
    /// calls so the rule cannot drift between them.
    pub async fn is_allowed(
        pool: &PgPool,
        user_id: Uuid,
        is_admin: bool,
        app: &Application,
    ) -> Result<bool, AppError> {
        if !app.requires_entitlement || is_admin {
            return Ok(true);
        }
        Self::is_entitled(pool, user_id, app.id).await
    }

    /// Grant the given product to every member who currently has access
    /// (mirrors the migration backfill predicate and `User::is_access_allowed`).
    /// Called when an admin flips a previously-open product to restricted, so
    /// members who could access it while it was open keep access (the
    /// "preserve current access" guarantee, extended past migration time).
    /// Existing grants are left untouched (`DO NOTHING`). Returns rows inserted.
    pub async fn backfill_for_application(
        pool: &PgPool,
        application_id: Uuid,
    ) -> Result<u64, AppError> {
        let affected = sqlx::query(
            r#"
            INSERT INTO application_entitlements (user_id, application_id, granted_by, source)
            SELECT u.id, $1, NULL, 'backfill'
            FROM users u
            WHERE u.deleted_at IS NULL
              AND u.role <> 'admin'
              AND (
                    u.lifetime_member = TRUE
                    OR (u.trial_ends_at IS NOT NULL AND u.trial_ends_at > now())
                    OR u.membership_status IN ('active', 'grace_period')
              )
            ON CONFLICT (user_id, application_id) DO NOTHING
            "#,
        )
        .bind(application_id)
        .execute(pool)
        .await?
        .rows_affected();
        Ok(affected)
    }

    /// Whether the user has an ACTIVE entitlement for the product. Prefer
    /// [`Self::is_allowed`] at gates (it short-circuits open products/admins);
    /// this is the raw grant lookup.
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
    ///
    /// Takes any `PgExecutor` (not just `&PgPool`) so the self-service download
    /// gate can run it inside a `begin_with_user` transaction under per-user RLS
    /// (BUNYIP-344). A `&PgPool` still satisfies the bound, so existing callers
    /// are unaffected.
    pub async fn active_application_ids(
        executor: impl sqlx::PgExecutor<'_>,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>, AppError> {
        let ids = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT application_id FROM application_entitlements
            WHERE user_id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .fetch_all(executor)
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
}
