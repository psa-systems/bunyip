//! User repository

use chrono::{self, DateTime, Utc};
use sqlx::postgres::Postgres;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{CreateUser, MembershipStatus, SubscriptionTier, User};

pub struct UserRepository;

impl UserRepository {
    /// Create a new user
    pub async fn create(pool: &PgPool, data: CreateUser) -> Result<User, AppError> {
        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (email, password_hash, role)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(&data.email)
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
    pub async fn update_email(
        pool: &PgPool,
        user_id: Uuid,
        new_email: &str,
        set_verified: bool,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE users
            SET email = $1, email_verified = $2, updated_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(new_email)
        .bind(set_verified)
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(())
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

    /// List users with pagination
    pub async fn list_paginated(
        pool: &PgPool,
        page: i32,
        per_page: i32,
        search: Option<&str>,
        status_filter: Option<MembershipStatus>,
    ) -> Result<(Vec<User>, i64), AppError> {
        let offset = (page - 1) * per_page;

        // Build dynamic query based on filters
        let mut conditions = vec!["deleted_at IS NULL".to_string()];

        if search.is_some() {
            conditions.push("LOWER(email) LIKE LOWER($3)".to_string());
        }

        if let Some(_status) = &status_filter {
            let idx = if search.is_some() { 4 } else { 3 };
            conditions.push(format!("subscription_status = ${}", idx));
        }

        let where_clause = conditions.join(" AND ");
        let query = format!(
            "SELECT * FROM users WHERE {} ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            where_clause
        );
        let count_query = format!("SELECT COUNT(*) FROM users WHERE {}", where_clause);

        // Execute queries based on filters
        let (users, total): (Vec<User>, i64) = match (search, &status_filter) {
            (Some(s), Some(status)) => {
                let search_pattern = format!("%{}%", s);
                let users = sqlx::query_as::<_, User>(&query)
                    .bind(per_page)
                    .bind(offset)
                    .bind(&search_pattern)
                    .bind(status.as_str())
                    .fetch_all(pool)
                    .await?;

                let total: (i64,) = sqlx::query_as(&count_query)
                    .bind(&search_pattern)
                    .bind(status.as_str())
                    .fetch_one(pool)
                    .await?;

                (users, total.0)
            }
            (Some(s), None) => {
                let search_pattern = format!("%{}%", s);
                let users = sqlx::query_as::<_, User>(&query)
                    .bind(per_page)
                    .bind(offset)
                    .bind(&search_pattern)
                    .fetch_all(pool)
                    .await?;

                let total: (i64,) = sqlx::query_as(&count_query)
                    .bind(&search_pattern)
                    .fetch_one(pool)
                    .await?;

                (users, total.0)
            }
            (None, Some(status)) => {
                let users = sqlx::query_as::<_, User>(&query)
                    .bind(per_page)
                    .bind(offset)
                    .bind(status.as_str())
                    .fetch_all(pool)
                    .await?;

                let total: (i64,) = sqlx::query_as(&count_query)
                    .bind(status.as_str())
                    .fetch_one(pool)
                    .await?;

                (users, total.0)
            }
            (None, None) => {
                let users = sqlx::query_as::<_, User>(&query)
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?;

                let total: (i64,) = sqlx::query_as(&count_query).fetch_one(pool).await?;

                (users, total.0)
            }
        };

        Ok((users, total))
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
        let (lifetime_member, trial_ends_at) = match tier {
            SubscriptionTier::Lifetime | SubscriptionTier::Free => (true, None),
            SubscriptionTier::EarlyAdopter => {
                let ends = chrono::Utc::now() + chrono::Duration::days(early_adopter_trial_days);
                (false, Some(ends))
            }
            SubscriptionTier::Standard => {
                let ends = chrono::Utc::now() + chrono::Duration::days(standard_trial_days);
                (false, Some(ends))
            }
        };

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
    pub async fn count_tier_assignments<'e, E>(executor: E) -> Result<(i64, i64), AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        let row: (i64, i64) = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE subscription_tier = 'lifetime' AND subscription_override_by IS NULL) AS lifetime_count,
                COUNT(*) FILTER (WHERE subscription_tier = 'early_adopter') AS early_adopter_count
            FROM users
            WHERE email_verified = true AND deleted_at IS NULL
            "#,
        )
        .fetch_one(executor)
        .await?;
        Ok(row)
    }

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
