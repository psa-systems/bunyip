//! Admin invite repository

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::token::{AdminInvite, CreateAdminInvite};

pub struct InviteRepository;

impl InviteRepository {
    /// Create a new admin invite
    pub async fn create(pool: &PgPool, data: CreateAdminInvite) -> Result<AdminInvite, AppError> {
        let invite = sqlx::query_as::<_, AdminInvite>(
            r#"
            INSERT INTO admin_invites (email, token_hash, invited_by, role, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(&data.email)
        .bind(&data.token_hash)
        .bind(data.invited_by)
        .bind(&data.role)
        .bind(data.expires_at)
        .fetch_one(pool)
        .await?;

        Ok(invite)
    }

    /// Find a valid (not revoked, not accepted, not expired) invite by token hash
    pub async fn find_valid_by_token_hash(
        pool: &PgPool,
        token_hash: &str,
    ) -> Result<Option<AdminInvite>, AppError> {
        let invite = sqlx::query_as::<_, AdminInvite>(
            r#"
            SELECT * FROM admin_invites
            WHERE token_hash = $1
              AND revoked_at IS NULL
              AND accepted_at IS NULL
              AND expires_at > NOW()
            "#,
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;

        Ok(invite)
    }

    /// Find a pending (not revoked, not accepted, not expired) invite by email
    pub async fn find_pending_by_email(
        pool: &PgPool,
        email: &str,
    ) -> Result<Option<AdminInvite>, AppError> {
        let invite = sqlx::query_as::<_, AdminInvite>(
            r#"
            SELECT * FROM admin_invites
            WHERE LOWER(email) = LOWER($1)
              AND revoked_at IS NULL
              AND accepted_at IS NULL
              AND expires_at > NOW()
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(email)
        .fetch_optional(pool)
        .await?;

        Ok(invite)
    }

    /// Mark an invite as accepted
    pub async fn mark_accepted(pool: &PgPool, invite_id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE admin_invites SET accepted_at = NOW() WHERE id = $1
            "#,
        )
        .bind(invite_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Mark an invite as revoked
    pub async fn mark_revoked(pool: &PgPool, invite_id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE admin_invites SET revoked_at = NOW() WHERE id = $1
            "#,
        )
        .bind(invite_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Revoke all pending invites for an email
    pub async fn revoke_pending_by_email(pool: &PgPool, email: &str) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE admin_invites SET revoked_at = NOW()
            WHERE LOWER(email) = LOWER($1)
              AND revoked_at IS NULL
              AND accepted_at IS NULL
              AND expires_at > NOW()
            "#,
        )
        .bind(email)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// List all invites with pagination
    pub async fn list_all(
        pool: &PgPool,
        page: i32,
        per_page: i32,
    ) -> Result<(Vec<AdminInvite>, i64), AppError> {
        let offset = (page - 1) * per_page;

        let invites = sqlx::query_as::<_, AdminInvite>(
            r#"
            SELECT * FROM admin_invites
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(per_page as i64)
        .bind(offset as i64)
        .fetch_all(pool)
        .await?;

        let total: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM admin_invites
            "#,
        )
        .fetch_one(pool)
        .await?;

        Ok((invites, total.0))
    }
}
