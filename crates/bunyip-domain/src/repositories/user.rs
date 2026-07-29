//! User repository

use chrono::{self, DateTime, Utc};
use sqlx::postgres::Postgres;
use sqlx::{PgPool, QueryBuilder};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{normalize_email, CreateUser, MembershipStatus, SubscriptionTier, User};

pub struct UserRepository;

impl UserRepository {
    /// Create a new user
    ///
    /// The email is lowercased via [`normalize_email`] before insert (BUNYIP-325)
    /// so the stored address can never diverge in case from the
    /// `LOWER(email)`-based lookups or the verification / welcome mail. This is
    /// the single INSERT choke point, so every signup surface (register,
    /// magic-link auto-create, admin setup) inherits normalization here.
    pub async fn create(pool: &PgPool, data: CreateUser) -> Result<User, AppError> {
        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (email, password_hash, role)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(normalize_email(&data.email))
        .bind(&data.password_hash)
        .bind(data.role.as_str())
        .fetch_one(pool)
        .await?;

        Ok(user)
    }

    /// Find user by ID
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>, AppError> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    /// Find user by email
    pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<User>, AppError> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT * FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL
            "#,
        )
        .bind(email)
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    /// Find user by Stripe customer ID
    pub async fn find_by_stripe_customer_id(
        pool: &PgPool,
        customer_id: &str,
    ) -> Result<Option<User>, AppError> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT * FROM users WHERE stripe_customer_id = $1 AND deleted_at IS NULL
            "#,
        )
        .bind(customer_id)
        .fetch_optional(pool)
        .await?;

        Ok(user)
    }

    /// Update user's password hash
    pub async fn update_password(
        pool: &PgPool,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE users
            SET password_hash = $1, updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(password_hash)
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// BUNYIP-139: update the user's optional profile fields (first_name,
    /// last_name, phone). Each Option is interpreted at the SQL level: `Some`
    /// writes the value; `None` clears the column to NULL. Whitespace
    /// normalization (trim, "" -> NULL) is the caller's responsibility - this
    /// method writes verbatim. Returns the updated user row.
    pub async fn update_profile(
        pool: &PgPool,
        user_id: Uuid,
        first_name: Option<&str>,
        last_name: Option<&str>,
        phone: Option<&str>,
    ) -> Result<User, AppError> {
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET first_name = $1, last_name = $2, phone = $3, updated_at = NOW()
            WHERE id = $4 AND deleted_at IS NULL
            RETURNING *
            "#,
        )
        .bind(first_name)
        .bind(last_name)
        .bind(phone)
        .bind(user_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::not_found("User"))?;

        Ok(user)
    }

    /// BUNYIP-408: store (or replace) the user's avatar. The bytes land in the
    /// dedicated `user_avatars` table (one row per user, UPSERT on re-upload)
    /// and `users.avatar_updated_at` is stamped to NOW() in the SAME transaction
    /// so the cheap "an avatar exists" marker never drifts from the stored blob.
    /// Content-type + size are validated by the caller (handler) before this is
    /// reached; the DB CHECK constraints are the last-line backstop. Returns the
    /// updated user row (carrying the fresh `avatar_updated_at`).
    pub async fn set_avatar(
        pool: &PgPool,
        user_id: Uuid,
        mime_type: &str,
        data: &[u8],
    ) -> Result<User, AppError> {
        let size = i32::try_from(data.len())
            .map_err(|_| AppError::validation("avatar", "Avatar is too large"))?;
        let mut tx = pool.begin().await?;
        sqlx::query(
            r#"
            INSERT INTO user_avatars (user_id, mime_type, size_bytes, data, updated_at)
            VALUES ($1, $2, $3, $4, NOW())
            ON CONFLICT (user_id) DO UPDATE
                SET mime_type = EXCLUDED.mime_type,
                    size_bytes = EXCLUDED.size_bytes,
                    data = EXCLUDED.data,
                    updated_at = NOW()
            "#,
        )
        .bind(user_id)
        .bind(mime_type)
        .bind(size)
        .bind(data)
        .execute(&mut *tx)
        .await?;

        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET avatar_updated_at = NOW(), updated_at = NOW()
            WHERE id = $1 AND deleted_at IS NULL
            RETURNING *
            "#,
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::not_found("User"))?;

        tx.commit().await?;
        Ok(user)
    }

    /// BUNYIP-408: remove the user's avatar. Deletes the `user_avatars` row and
    /// clears `users.avatar_updated_at` back to NULL in one transaction, so the
    /// UI falls back to the initials/icon. Idempotent: removing an absent avatar
    /// simply leaves both already-empty and returns the (unchanged) user row.
    pub async fn clear_avatar(pool: &PgPool, user_id: Uuid) -> Result<User, AppError> {
        let mut tx = pool.begin().await?;
        sqlx::query("DELETE FROM user_avatars WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET avatar_updated_at = NULL, updated_at = NOW()
            WHERE id = $1 AND deleted_at IS NULL
            RETURNING *
            "#,
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::not_found("User"))?;

        tx.commit().await?;
        Ok(user)
    }

    /// BUNYIP-408: fetch the stored avatar bytes + MIME for serving. `None` when
    /// the user has no avatar. Only the avatar-serving handler calls this, so the
    /// BYTEA is never loaded on the ordinary user-fetch path.
    pub async fn get_avatar(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Option<(String, Vec<u8>)>, AppError> {
        let row = sqlx::query_as::<_, (String, Vec<u8>)>(
            "SELECT mime_type, data FROM user_avatars WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Update email verified status
    pub async fn set_email_verified(pool: &PgPool, user_id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE users
            SET email_verified = TRUE, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Update membership status
    pub async fn update_membership_status<'e, E>(
        executor: E,
        user_id: Uuid,
        status: MembershipStatus,
    ) -> Result<(), AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        sqlx::query(
            r#"
            UPDATE users
            SET subscription_status = $1, updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(status.as_str())
        .bind(user_id)
        .execute(executor)
        .await?;

        Ok(())
    }

    /// BUNYIP-209: mark the user as having consumed their signup free trial.
    /// Called from the `checkout.session.completed` webhook once a trial
    /// session finalizes, so a later subscribe cannot re-grant the trial.
    /// Idempotent: a replayed webhook just re-sets the flag to TRUE.
    pub async fn mark_trial_used<'e, E>(executor: E, user_id: Uuid) -> Result<(), AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        sqlx::query(
            r#"
            UPDATE users
            SET has_used_trial = TRUE, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(executor)
        .await?;

        Ok(())
    }

    /// Activate membership (set subscription_status to 'active')
    pub async fn activate_membership(pool: &PgPool, user_id: Uuid) -> Result<User, AppError> {
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET subscription_status = 'active',
                updated_at = NOW()
            WHERE id = $1 AND deleted_at IS NULL
            RETURNING *
            "#,
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::not_found("User"))?;

        Ok(user)
    }

    /// Update Stripe customer ID
    pub async fn update_stripe_customer_id<'e, E>(
        executor: E,
        user_id: Uuid,
        customer_id: &str,
    ) -> Result<(), AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        sqlx::query(
            r#"
            UPDATE users
            SET stripe_customer_id = $1, updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(customer_id)
        .bind(user_id)
        .execute(executor)
        .await?;

        Ok(())
    }

    /// Store the Stripe customer ID and authorized payment method ID captured at signup.
    pub async fn update_stripe_registration_info(
        pool: &PgPool,
        user_id: Uuid,
        customer_id: &str,
        payment_method_id: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE users
            SET stripe_customer_id = $1, stripe_payment_method_id = $2, updated_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(customer_id)
        .bind(payment_method_id)
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Lock price for user
    pub async fn lock_price(
        pool: &PgPool,
        user_id: Uuid,
        price_id: &str,
        amount: i32,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE users
            SET price_locked = TRUE, locked_price_id = $1, locked_price_amount = $2, updated_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(price_id)
        .bind(amount)
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Set grace period
    pub async fn set_grace_period<'e, E>(
        executor: E,
        user_id: Uuid,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<(), AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        sqlx::query(
            r#"
            UPDATE users
            SET grace_period_start = $1, grace_period_end = $2, updated_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(start)
        .bind(end)
        .bind(user_id)
        .execute(executor)
        .await?;

        Ok(())
    }

    /// Reset subscription tier to standard when a membership is revoked/canceled.
    /// This frees the lifetime or early_adopter slot so it can be assigned to the next user.
    pub async fn reset_subscription_tier<'e, E>(executor: E, user_id: Uuid) -> Result<(), AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        sqlx::query(
            r#"
            UPDATE users
            SET subscription_tier = 'standard',
                lifetime_member = FALSE,
                trial_ends_at = NULL,
                subscription_override_by = NULL,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(executor)
        .await?;

        Ok(())
    }

    /// Set subscription tier from a Stripe subscription event.
    /// Clears trial_ends_at (user is now a paid subscriber) but does not touch subscription_status.
    pub async fn upgrade_subscription_tier<'e, E>(
        executor: E,
        user_id: Uuid,
        tier: &SubscriptionTier,
    ) -> Result<(), AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        let lifetime_member = matches!(tier, SubscriptionTier::Lifetime | SubscriptionTier::Free);
        sqlx::query(
            r#"
            UPDATE users
            SET subscription_tier = $1,
                lifetime_member   = $2,
                trial_ends_at     = NULL,
                updated_at        = NOW()
            WHERE id = $3
            "#,
        )
        .bind(tier.as_str())
        .bind(lifetime_member)
        .bind(user_id)
        .execute(executor)
        .await?;

        Ok(())
    }

    /// Clear grace period
    pub async fn clear_grace_period<'e, E>(executor: E, user_id: Uuid) -> Result<(), AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        sqlx::query(
            r#"
            UPDATE users
            SET grace_period_start = NULL, grace_period_end = NULL, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(executor)
        .await?;

        Ok(())
    }

    /// Update user's email address
    ///
    /// The new email is lowercased via [`normalize_email`] before write
    /// (BUNYIP-325), the second and last write path to `users.email`, so an
    /// email change can no more store a mixed-case address than a fresh signup.
    pub async fn update_email<'e, E>(
        executor: E,
        user_id: Uuid,
        new_email: &str,
        set_verified: bool,
    ) -> Result<(), AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        sqlx::query(
            r#"
            UPDATE users
            SET email = $1, email_verified = $2, updated_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(normalize_email(new_email))
        .bind(set_verified)
        .bind(user_id)
        .execute(executor)
        .await?;

        Ok(())
    }

    /// Lock a user row `FOR UPDATE` to serialize concurrent mutations within a
    /// transaction. Returns whether a (non-deleted) row was locked.
    pub async fn lock_for_update<'e, E>(executor: E, user_id: Uuid) -> Result<bool, AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        let row: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(executor)
            .await?;

        Ok(row.is_some())
    }

    /// Lock and fetch a non-deleted user row `FOR UPDATE` within a transaction.
    pub async fn find_by_id_for_update<'e, E>(
        executor: E,
        user_id: Uuid,
    ) -> Result<Option<User>, AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(executor)
        .await?;

        Ok(user)
    }

    /// Check whether an email is already registered to a non-deleted user.
    /// Accepts any executor so it can run inside a transaction.
    pub async fn email_exists<'e, E>(executor: E, email: &str) -> Result<bool, AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL",
        )
        .bind(email)
        .fetch_optional(executor)
        .await?;

        Ok(row.is_some())
    }

    /// Check whether an email is reserved by any user, active OR soft-deleted
    /// (BUNYIP-330). Register / email-change / invite-accept guard against
    /// this so a deleted account's email stays permanently locked and can't
    /// be re-claimed by a new user. Login / OCI-auth continue to use
    /// [`Self::email_exists`] / [`Self::find_by_email`], which filter to
    /// non-deleted rows (a deleted user can't sign in).
    pub async fn email_reserved<'e, E>(executor: E, email: &str) -> Result<bool, AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        let row: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM users WHERE LOWER(email) = LOWER($1)")
                .bind(email)
                .fetch_optional(executor)
                .await?;

        Ok(row.is_some())
    }

    /// Update last login timestamp
    pub async fn update_last_login(pool: &PgPool, user_id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE users
            SET last_login_at = NOW(), updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// BUNYIP-366: record the ISO 3166-1 alpha-2 country of the user's most
    /// recent geolocatable login, for the next login's change comparison.
    pub async fn set_last_login_country(
        pool: &PgPool,
        user_id: Uuid,
        country: Option<&str>,
    ) -> Result<(), AppError> {
        sqlx::query("UPDATE users SET last_login_country = $2, updated_at = NOW() WHERE id = $1")
            .bind(user_id)
            .bind(country)
            .execute(pool)
            .await?;
        Ok(())
    }

    /// BUNYIP-366: set the per-user opt-out for the new-login-location email
    /// alert. `true` (the column default) keeps alerts on; `false` disables them.
    pub async fn set_login_location_alerts(
        pool: &PgPool,
        user_id: Uuid,
        enabled: bool,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE users SET login_location_alerts = $2, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(user_id)
        .bind(enabled)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Soft delete user
    pub async fn soft_delete(pool: &PgPool, user_id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE users
            SET deleted_at = NOW(), updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Reactivate a soft-deleted user by clearing `deleted_at`.
    ///
    /// Returns `true` when a previously-deleted row was restored, `false` when
    /// no matching soft-deleted user exists (already active or unknown id), so
    /// the caller can distinguish a real reactivation from a no-op.
    pub async fn restore(pool: &PgPool, user_id: Uuid) -> Result<bool, AppError> {
        let result = sqlx::query(
            r#"
            UPDATE users
            SET deleted_at = NULL, updated_at = NOW()
            WHERE id = $1 AND deleted_at IS NOT NULL
            "#,
        )
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Clear the non-cascade dependents that would block deleting `user_ids`,
    /// then delete the user rows - all within the caller's transaction. Shared by
    /// every hard-delete entry point (BUNYIP-246 / BUNYIP-248). Returns the
    /// number of user rows removed.
    ///
    /// Most child tables FK `users(id) ON DELETE CASCADE` (including
    /// `oauth_authorization_codes.user_id` since BUNYIP-248), so the database
    /// removes them automatically. The exceptions handled here reference
    /// `users(id)` WITHOUT a cascade and would otherwise FK-block the delete:
    /// `audit_logs.actor_id` (written by register / login / reset) and
    /// `admin_notifications.user_id` / `read_by` (written by a feedback
    /// submission). Audit and notification rows are dropped / de-referenced
    /// rather than preserved because this path is only ever reached from
    /// non-production e2e cleanup (the `?purge` flag, the disposable reaper, and
    /// `bunyip-e2e-bootstrap`), so we are only erasing test data.
    ///
    /// STILL OUT OF SCOPE: the admin actor `*_by` columns
    /// (`oidc_clients.created_by`, `admin_invites.invited_by`,
    /// `stripe_config.updated_by`, `tier_config.updated_by`,
    /// `feedback.responded_by`, `subscription_override_by`,
    /// `oauth_client_user_tenants.created_by`, `oidc_sessions_and_codes`
    /// `granted_by`) are populated ONLY by admin actions a subscriber disposable
    /// cannot perform, so nothing clears them. If an admin-disposable spec ever
    /// lands, extend this helper (or give those FKs `SET NULL`); there is no
    /// production impact, as production never hard-deletes users.
    async fn clear_deps_and_delete_users(
        tx: &mut sqlx::Transaction<'_, Postgres>,
        user_ids: &[Uuid],
    ) -> Result<u64, AppError> {
        sqlx::query("DELETE FROM audit_logs WHERE actor_id = ANY($1)")
            .bind(user_ids)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM admin_notifications WHERE user_id = ANY($1)")
            .bind(user_ids)
            .execute(&mut **tx)
            .await?;
        sqlx::query("UPDATE admin_notifications SET read_by = NULL WHERE read_by = ANY($1)")
            .bind(user_ids)
            .execute(&mut **tx)
            .await?;
        let result = sqlx::query("DELETE FROM users WHERE id = ANY($1)")
            .bind(user_ids)
            .execute(&mut **tx)
            .await?;
        Ok(result.rows_affected())
    }

    /// HARD-delete a single user row and its non-cascade dependents (BUNYIP-246).
    /// Only ever reached from non-production e2e cleanup paths (the `?purge`
    /// flag, the disposable reaper, and `bunyip-e2e-bootstrap`). Returns the
    /// number of user rows removed. See [`Self::clear_deps_and_delete_users`].
    pub async fn hard_delete(pool: &PgPool, user_id: Uuid) -> Result<u64, AppError> {
        let mut tx = pool.begin().await?;
        let removed = Self::clear_deps_and_delete_users(&mut tx, &[user_id]).await?;
        tx.commit().await?;
        Ok(removed)
    }

    /// HARD-delete every user row matching an exact email (BUNYIP-246). Because
    /// the email uniqueness index is partial (`WHERE deleted_at IS NULL`), one
    /// email can name an active row plus soft-deleted rows; this removes them
    /// all, preserving the `bunyip-e2e-bootstrap --cleanup` by-email semantics.
    /// Returns the number of user rows removed.
    pub async fn hard_delete_by_email(pool: &PgPool, email: &str) -> Result<u64, AppError> {
        let mut tx = pool.begin().await?;
        let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
            .bind(email)
            .fetch_all(&mut *tx)
            .await?;
        let removed = Self::clear_deps_and_delete_users(&mut tx, &ids).await?;
        tx.commit().await?;
        Ok(removed)
    }

    /// Apply a seed-time membership snapshot in one write (PSA-50). Seeding sets
    /// these fields as plain DB state (no Stripe objects): status, tier,
    /// lifetime, price-lock, and trial end. This is NOT a production membership
    /// path - real changes go through the dedicated setters
    /// ([`update_membership_status`](Self::update_membership_status),
    /// [`assign_subscription_tier`](Self::assign_subscription_tier),
    /// [`grant_lifetime_membership`](Self::grant_lifetime_membership),
    /// [`lock_price`](Self::lock_price)); this single-statement shortcut lets a
    /// seed template express an arbitrary membership snapshot for demo data.
    pub async fn apply_seed_membership(
        pool: &PgPool,
        user_id: Uuid,
        status: MembershipStatus,
        tier: &SubscriptionTier,
        lifetime: bool,
        price_locked: bool,
        locked_price_amount: Option<i32>,
        trial_ends_at: Option<DateTime<Utc>>,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE users SET
                subscription_status = $2,
                subscription_tier   = $3,
                lifetime_member     = $4,
                price_locked        = $5,
                locked_price_amount = $6,
                trial_ends_at       = $7,
                updated_at          = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(status.as_str())
        .bind(tier.as_str())
        .bind(lifetime)
        .bind(price_locked)
        .bind(locked_price_amount)
        .bind(trial_ends_at)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// HARD-delete every user whose email ends with `@{domain}`, clearing the
    /// same non-cascade dependencies as
    /// [`hard_delete_by_email`](Self::hard_delete_by_email) (PSA-50 reset /
    /// idempotent re-import). Uses an exact suffix comparison (not `LIKE`), so a
    /// `_` or `%` in the domain can never widen the match on this delete path.
    /// Returns the rows removed.
    pub async fn hard_delete_seed_users(pool: &PgPool, domain: &str) -> Result<u64, AppError> {
        let mut tx = pool.begin().await?;
        let suffix = format!("@{domain}");
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM users WHERE right(lower(email), length($1)) = lower($1)",
        )
        .bind(&suffix)
        .fetch_all(&mut *tx)
        .await?;
        let removed = Self::clear_deps_and_delete_users(&mut tx, &ids).await?;
        tx.commit().await?;
        Ok(removed)
    }

    /// List the live users whose email ends with `@{domain}` (the reserved seed
    /// scope), for PSA-52 export. Same suffix comparison as
    /// [`hard_delete_seed_users`](Self::hard_delete_seed_users), so export and
    /// reset operate on exactly the same set.
    pub async fn list_seed_users(pool: &PgPool, domain: &str) -> Result<Vec<User>, AppError> {
        let suffix = format!("@{domain}");
        let users = sqlx::query_as::<_, User>(
            "SELECT * FROM users \
             WHERE right(lower(email), length($1)) = lower($1) AND deleted_at IS NULL \
             ORDER BY email",
        )
        .bind(&suffix)
        .fetch_all(pool)
        .await?;
        Ok(users)
    }

    /// HARD-delete e2e disposable accounts older than `max_age_secs` whose email
    /// matches `pattern` (a SQL `LIKE` pattern, e.g. `%+e2e-%` for the disposable
    /// subaddress marker) (BUNYIP-246). The reaper safety net for crashed e2e
    /// runs. The eligible ids are resolved once (the cutoff uses the transaction
    /// timestamp), then deleted via the shared helper. Returns the number of user
    /// rows removed.
    pub async fn hard_delete_stale_disposable(
        pool: &PgPool,
        pattern: &str,
        max_age_secs: i64,
    ) -> Result<u64, AppError> {
        let mut tx = pool.begin().await?;
        let ids: Vec<Uuid> = sqlx::query_scalar(
            r#"
            SELECT id FROM users
            WHERE email LIKE $1
              AND created_at < NOW() - ($2::double precision * INTERVAL '1 second')
            "#,
        )
        .bind(pattern)
        .bind(max_age_secs)
        .fetch_all(&mut *tx)
        .await?;
        let removed = Self::clear_deps_and_delete_users(&mut tx, &ids).await?;
        tx.commit().await?;
        Ok(removed)
    }

    /// Set two_factor_enabled flag on a user
    pub async fn set_two_factor_enabled(
        pool: &PgPool,
        user_id: Uuid,
        enabled: bool,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE users SET two_factor_enabled = $2, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(user_id)
        .bind(enabled)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Update user role
    pub async fn update_role(pool: &PgPool, user_id: Uuid, role: &str) -> Result<User, AppError> {
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET role = $2, updated_at = NOW()
            WHERE id = $1 AND deleted_at IS NULL
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(role)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::not_found("User"))?;

        Ok(user)
    }

    /// List users with pagination.
    ///
    /// `active` selects which side of the soft-delete boundary to return:
    /// `Some(true)` lists live accounts (the default admin view), `Some(false)`
    /// lists suspended (soft-deleted) accounts so an admin can find and
    /// reactivate them (BUNYIP-120), and `None` lists BOTH (the "All" segment
    /// added in the BUNYIP-410 filter overhaul). Callers wanting the historical
    /// active-only default must pass `Some(true)` explicitly.
    ///
    /// `sort_by` is a whitelisted column key (`email` / `tier` / `verified` /
    /// `joined`); anything else falls back to newest-first by join date. `id` is
    /// always appended as a stable tiebreak so pagination never drops or repeats
    /// a row across pages.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_paginated(
        pool: &PgPool,
        page: i32,
        per_page: i32,
        search: Option<&str>,
        status_filter: Option<MembershipStatus>,
        active: Option<bool>,
        // BUNYIP-410: consolidated users+memberships admin list filters. `tier`
        // matches `COALESCE(subscription_tier,'standard')` (rows may predate the
        // tier column); `verified` filters on `email_verified`. Both `None` =
        // unfiltered, preserving the pre-410 behaviour.
        tier: Option<&str>,
        verified: Option<bool>,
        sort_by: Option<&str>,
        sort_desc: bool,
    ) -> Result<(Vec<User>, i64), AppError> {
        let offset = (page - 1) * per_page;
        let search_pattern = search.map(|s| format!("%{}%", s));

        let deleted_clause = match active {
            Some(true) => " WHERE deleted_at IS NULL",
            Some(false) => " WHERE deleted_at IS NOT NULL",
            // "All": both live and suspended. `WHERE TRUE` keeps the trailing
            // `AND <filter>` clauses below valid without special-casing them.
            None => " WHERE TRUE",
        };

        // Build the filter clause once on both the page query and the count
        // query via QueryBuilder so the placeholders always match the bindings
        // (the previous hand-numbered `$3`/`$4` count query bound `$1`/`$2`).
        let mut query = QueryBuilder::new(format!("SELECT * FROM users{deleted_clause}"));
        let mut count_query =
            QueryBuilder::new(format!("SELECT COUNT(*) FROM users{deleted_clause}"));

        if let Some(pattern) = &search_pattern {
            query
                .push(" AND LOWER(email) LIKE LOWER(")
                .push_bind(pattern.as_str())
                .push(")");
            count_query
                .push(" AND LOWER(email) LIKE LOWER(")
                .push_bind(pattern.as_str())
                .push(")");
        }

        if let Some(status) = &status_filter {
            query
                .push(" AND subscription_status = ")
                .push_bind(status.as_str());
            count_query
                .push(" AND subscription_status = ")
                .push_bind(status.as_str());
        }

        if let Some(tier) = tier {
            query
                .push(" AND COALESCE(subscription_tier, 'standard') = ")
                .push_bind(tier);
            count_query
                .push(" AND COALESCE(subscription_tier, 'standard') = ")
                .push_bind(tier);
        }

        if let Some(verified) = verified {
            query.push(" AND email_verified = ").push_bind(verified);
            count_query
                .push(" AND email_verified = ")
                .push_bind(verified);
        }

        // Whitelisted sort column -> SQL expression. Never interpolate the raw
        // key: only these fixed expressions can reach the query, so a crafted
        // `sort` param cannot inject SQL. Unknown / absent falls back to join
        // date. `id` is the stable tiebreak.
        let sort_expr = match sort_by {
            Some("email") => "LOWER(email)",
            Some("tier") => "COALESCE(subscription_tier, 'standard')",
            Some("verified") => "email_verified",
            Some("joined") => "created_at",
            _ => "created_at",
        };
        let dir = if sort_desc { "DESC" } else { "ASC" };
        query
            .push(format!(" ORDER BY {sort_expr} {dir}, id {dir} LIMIT "))
            .push_bind(per_page)
            .push(" OFFSET ")
            .push_bind(offset);

        let users = query.build_query_as::<User>().fetch_all(pool).await?;
        let total: (i64,) = count_query.build_query_as().fetch_one(pool).await?;

        Ok((users, total.0))
    }

    /// Atomically assign a subscription tier to a user.
    ///
    /// Must be called inside a transaction that holds a `pg_advisory_xact_lock`
    /// to prevent concurrent verifications from racing on the same slot count.
    /// Returns the tier that was assigned.
    pub async fn assign_subscription_tier<'e, E>(
        executor: E,
        user_id: Uuid,
        tier: &SubscriptionTier,
        early_adopter_trial_days: i64,
        standard_trial_days: i64,
    ) -> Result<(), AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        // Trial length is the tier's admin-configured window (BUNYIP-291 AC1);
        // lifetime/free never trial and are permanently entitled.
        let trial_ends_at = tier
            .trial_days(early_adopter_trial_days, standard_trial_days)
            .map(|days| chrono::Utc::now() + chrono::Duration::days(days));
        let lifetime_member = matches!(tier, SubscriptionTier::Lifetime | SubscriptionTier::Free);

        sqlx::query(
            r#"
            UPDATE users
            SET subscription_tier = $1,
                lifetime_member = $2,
                trial_ends_at = $3,
                subscription_status = 'active',
                updated_at = NOW()
            WHERE id = $4
            "#,
        )
        .bind(tier.as_str())
        .bind(lifetime_member)
        .bind(trial_ends_at)
        .bind(user_id)
        .execute(executor)
        .await?;

        Ok(())
    }

    /// Count users assigned to each tier — used inside a transaction with an advisory lock
    /// to atomically determine which tier the next verified user should receive.
    ///
    /// Counts are based on how many users have actually been assigned each tier,
    /// not total verified users. This ensures tier slots are filled correctly even
    /// if users existed before the tier system was introduced.
    ///
    /// Admin-granted lifetimes (`subscription_override_by IS NOT NULL`) are counted
    /// the same as organically-claimed ones: they occupy a real lifetime slot, so they
    /// must count against the configured cap and be reflected in the admin slot-usage
    /// display. Excluding them let the count read 0 while active lifetimes existed,
    /// defeating the cap and misleading the Tier Settings page (BUNYIP-96).
    ///
    /// Email verification is deliberately NOT a filter: an active `lifetime` /
    /// `early_adopter` subscription occupies a slot whether or not the holder has
    /// verified their email. Gating on `email_verified = true` let unverified
    /// lifetimes read as 0, so they bypassed the cap and the Tier Settings page
    /// under-reported usage (BUNYIP-105). Only soft-deleted users (`deleted_at`)
    /// are excluded.
    pub async fn count_tier_assignments<'e, E>(executor: E) -> Result<(i64, i64), AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        let row: (i64, i64) = sqlx::query_as(Self::COUNT_TIER_ASSIGNMENTS_SQL)
            .fetch_one(executor)
            .await?;
        Ok(row)
    }

    /// SQL backing [`Self::count_tier_assignments`]. Held as a named const so the
    /// BUNYIP-105 regression test can assert the `email_verified` predicate stays
    /// dropped without needing a live database.
    const COUNT_TIER_ASSIGNMENTS_SQL: &'static str = r#"
            SELECT
                COUNT(*) FILTER (WHERE subscription_tier = 'lifetime') AS lifetime_count,
                COUNT(*) FILTER (WHERE subscription_tier = 'early_adopter') AS early_adopter_count
            FROM users
            WHERE deleted_at IS NULL
            "#;

    /// Grant lifetime membership to a user (admin override).
    pub async fn grant_lifetime_membership(
        pool: &PgPool,
        user_id: Uuid,
        granted_by: Uuid,
    ) -> Result<User, AppError> {
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET subscription_tier = 'lifetime',
                lifetime_member = TRUE,
                trial_ends_at = NULL,
                subscription_override_by = $2,
                subscription_status = 'active',
                updated_at = NOW()
            WHERE id = $1 AND deleted_at IS NULL
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(granted_by)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::not_found("User"))?;

        Ok(user)
    }

    /// Revoke a previously-granted lifetime / free admin-override membership.
    /// Returns the user to `standard` tier with no active subscription, mirroring
    /// the post-cancel Stripe state. Caller is responsible for any Stripe-side
    /// cleanup (cancelling the $0 invoice subscription, etc.).
    pub async fn revoke_lifetime_membership(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<User, AppError> {
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET subscription_tier = 'standard',
                lifetime_member = FALSE,
                trial_ends_at = NULL,
                subscription_override_by = NULL,
                subscription_status = 'none',
                updated_at = NOW()
            WHERE id = $1 AND deleted_at IS NULL AND lifetime_member = TRUE
            RETURNING *
            "#,
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::not_found("Lifetime membership"))?;

        Ok(user)
    }

    /// Grant free membership to a user (admin override, not tied to signup count).
    pub async fn grant_free_membership(
        pool: &PgPool,
        user_id: Uuid,
        granted_by: Uuid,
    ) -> Result<User, AppError> {
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users
            SET subscription_tier = 'free',
                lifetime_member = TRUE,
                trial_ends_at = NULL,
                subscription_override_by = $2,
                subscription_status = 'active',
                updated_at = NOW()
            WHERE id = $1 AND deleted_at IS NULL
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(granted_by)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::not_found("User"))?;

        Ok(user)
    }

    /// Get email addresses of all active admin users for system notifications
    pub async fn find_admin_emails(pool: &PgPool) -> Result<Vec<String>, AppError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT email FROM users WHERE role = 'admin' AND deleted_at IS NULL ORDER BY created_at ASC",
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|(email,)| email).collect())
    }

    /// Count of active (non-deleted) users among `emails`. Powers the
    /// `/e2e-bootstrapped` readiness probe (BUNYIP-163): one indexed lookup, no
    /// per-row data returned.
    pub async fn count_active_by_emails(pool: &PgPool, emails: &[String]) -> Result<i64, AppError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM users WHERE email = ANY($1) AND deleted_at IS NULL",
        )
        .bind(emails)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Find users in grace period
    pub async fn find_in_grace_period(pool: &PgPool) -> Result<Vec<User>, AppError> {
        let users = sqlx::query_as::<_, User>(
            r#"
            SELECT * FROM users
            WHERE subscription_status = 'grace_period'
            AND grace_period_end IS NOT NULL
            AND deleted_at IS NULL
            ORDER BY grace_period_end ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(users)
    }
}

#[cfg(test)]
mod tests {
    use super::UserRepository;

    /// BUNYIP-105 regression: slot-usage counts must include unverified holders.
    ///
    /// The bug was a `WHERE email_verified = true` predicate that dropped
    /// unverified `lifetime` / `early_adopter` users from the count, letting them
    /// bypass the cap and read as 0 on the Tier Settings page. The count query
    /// must NOT filter on `email_verified`, so an unverified active lifetime still
    /// occupies its slot. Soft-deleted users (`deleted_at`) stay excluded.
    #[test]
    fn count_tier_assignments_sql_does_not_filter_on_email_verified() {
        let sql = UserRepository::COUNT_TIER_ASSIGNMENTS_SQL;
        assert!(
            !sql.contains("email_verified"),
            "count_tier_assignments must not filter on email_verified, or unverified \
             lifetimes undercount and bypass the cap (BUNYIP-105); SQL was: {sql}"
        );
        assert!(
            sql.contains("deleted_at IS NULL"),
            "count_tier_assignments must still exclude soft-deleted users; SQL was: {sql}"
        );
    }
}
