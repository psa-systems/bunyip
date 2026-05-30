//! Token repository for refresh tokens, magic links, and password resets

use chrono::{DateTime, Utc};
use sqlx::postgres::Postgres;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{
    CreateEmailChangeRequest, CreateEmailVerificationToken, CreateMagicLinkToken,
    CreatePasswordResetToken, CreateRefreshToken, EmailChangeRequest, EmailVerificationToken,
    MagicLinkToken, PasswordResetToken, RefreshToken,
};

pub struct TokenRepository;

impl TokenRepository {
    // =====================
    // Refresh Tokens
    // =====================

    /// Create a new refresh token
    pub async fn create_refresh_token(
        pool: &PgPool,
        data: CreateRefreshToken,
    ) -> Result<RefreshToken, AppError> {
        let token = sqlx::query_as::<_, RefreshToken>(
            r#"
            INSERT INTO refresh_tokens (user_id, token_hash, device_info, ip_address, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(data.user_id)
        .bind(&data.token_hash)
        .bind(&data.device_info)
        .bind(data.ip_address)
        .bind(data.expires_at)
        .fetch_one(pool)
        .await?;

        Ok(token)
    }

    /// Find refresh token by hash
    pub async fn find_refresh_token_by_hash(
        pool: &PgPool,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>, AppError> {
        let token = sqlx::query_as::<_, RefreshToken>(
            r#"
            SELECT * FROM refresh_tokens
            WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()
            "#,
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;

        Ok(token)
    }

    /// Find refresh token by hash regardless of validity (for diagnostics)
    pub async fn find_refresh_token_by_hash_any(
        pool: &PgPool,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>, AppError> {
        let token = sqlx::query_as::<_, RefreshToken>(
            r#"
            SELECT * FROM refresh_tokens
            WHERE token_hash = $1
            "#,
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;

        Ok(token)
    }

    /// Find all active refresh tokens for a user
    pub async fn find_user_refresh_tokens(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Vec<RefreshToken>, AppError> {
        let tokens = sqlx::query_as::<_, RefreshToken>(
            r#"
            SELECT * FROM refresh_tokens
            WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;

        Ok(tokens)
    }

    /// Alias for find_user_refresh_tokens
    pub async fn find_active_refresh_tokens_for_user(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Vec<RefreshToken>, AppError> {
        Self::find_user_refresh_tokens(pool, user_id).await
    }

    /// Find refresh token by ID
    pub async fn find_refresh_token_by_id(
        pool: &PgPool,
        token_id: Uuid,
    ) -> Result<Option<RefreshToken>, AppError> {
        let token = sqlx::query_as::<_, RefreshToken>(
            r#"
            SELECT * FROM refresh_tokens WHERE id = $1
            "#,
        )
        .bind(token_id)
        .fetch_optional(pool)
        .await?;

        Ok(token)
    }

    /// Update last used time for a refresh token
    pub async fn update_refresh_token_last_used(
        pool: &PgPool,
        token_id: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE refresh_tokens SET last_used_at = NOW() WHERE id = $1
            "#,
        )
        .bind(token_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Revoke a specific refresh token
    pub async fn revoke_refresh_token(pool: &PgPool, token_id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1
            "#,
        )
        .bind(token_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Revoke refresh token by hash
    pub async fn revoke_refresh_token_by_hash(
        pool: &PgPool,
        token_hash: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1
            "#,
        )
        .bind(token_hash)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Revoke all refresh tokens for a user
    pub async fn revoke_all_user_refresh_tokens(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE refresh_tokens SET revoked_at = NOW()
            WHERE user_id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    // =====================
    // Magic Link Tokens
    // =====================

    /// Create a new magic link token
    pub async fn create_magic_link_token(
        pool: &PgPool,
        data: CreateMagicLinkToken,
    ) -> Result<MagicLinkToken, AppError> {
        let token = sqlx::query_as::<_, MagicLinkToken>(
            r#"
            INSERT INTO magic_link_tokens (email, token_hash, expires_at, ip_address)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(&data.email)
        .bind(&data.token_hash)
        .bind(data.expires_at)
        .bind(data.ip_address)
        .fetch_one(pool)
        .await?;

        Ok(token)
    }

    /// Find magic link token by hash
    pub async fn find_magic_link_token_by_hash(
        pool: &PgPool,
        token_hash: &str,
    ) -> Result<Option<MagicLinkToken>, AppError> {
        let token = sqlx::query_as::<_, MagicLinkToken>(
            r#"
            SELECT * FROM magic_link_tokens
            WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
            "#,
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;

        Ok(token)
    }

    /// Mark magic link token as used
    pub async fn mark_magic_link_token_used(pool: &PgPool, token_id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE magic_link_tokens SET used_at = NOW() WHERE id = $1
            "#,
        )
        .bind(token_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Count recent magic link tokens for an email (for rate limiting)
    pub async fn count_recent_magic_link_tokens(
        pool: &PgPool,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<i64, AppError> {
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM magic_link_tokens
            WHERE LOWER(email) = LOWER($1) AND created_at > $2
            "#,
        )
        .bind(email)
        .bind(since)
        .fetch_one(pool)
        .await?;

        Ok(count.0)
    }

    // =====================
    // Password Reset Tokens
    // =====================

    /// Create a new password reset token
    pub async fn create_password_reset_token(
        pool: &PgPool,
        data: CreatePasswordResetToken,
    ) -> Result<PasswordResetToken, AppError> {
        let token = sqlx::query_as::<_, PasswordResetToken>(
            r#"
            INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, ip_address)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(data.user_id)
        .bind(&data.token_hash)
        .bind(data.expires_at)
        .bind(data.ip_address)
        .fetch_one(pool)
        .await?;

        Ok(token)
    }

    /// Find password reset token by hash
    pub async fn find_password_reset_token_by_hash(
        pool: &PgPool,
        token_hash: &str,
    ) -> Result<Option<PasswordResetToken>, AppError> {
        let token = sqlx::query_as::<_, PasswordResetToken>(
            r#"
            SELECT * FROM password_reset_tokens
            WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
            "#,
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;

        Ok(token)
    }

    /// Mark password reset token as used
    pub async fn mark_password_reset_token_used(
        pool: &PgPool,
        token_id: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1
            "#,
        )
        .bind(token_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Count recent password reset tokens for a user (for rate limiting)
    pub async fn count_recent_password_reset_tokens(
        pool: &PgPool,
        user_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<i64, AppError> {
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM password_reset_tokens
            WHERE user_id = $1 AND created_at > $2
            "#,
        )
        .bind(user_id)
        .bind(since)
        .fetch_one(pool)
        .await?;

        Ok(count.0)
    }

    // =====================
    // Email Change Requests
    // =====================

    /// Create a new email change request
    pub async fn create_email_change_request(
        pool: &PgPool,
        data: CreateEmailChangeRequest,
    ) -> Result<EmailChangeRequest, AppError> {
        let request = sqlx::query_as::<_, EmailChangeRequest>(
            r#"
            INSERT INTO email_change_requests (user_id, new_email, token_hash, expires_at, ip_address)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(data.user_id)
        .bind(&data.new_email)
        .bind(&data.token_hash)
        .bind(data.expires_at)
        .bind(data.ip_address)
        .fetch_one(pool)
        .await?;

        Ok(request)
    }

    /// Find email change request by token hash
    pub async fn find_email_change_request_by_hash(
        pool: &PgPool,
        token_hash: &str,
    ) -> Result<Option<EmailChangeRequest>, AppError> {
        let request = sqlx::query_as::<_, EmailChangeRequest>(
            r#"
            SELECT * FROM email_change_requests
            WHERE token_hash = $1 AND confirmed_at IS NULL AND canceled_at IS NULL AND expires_at > NOW()
            "#,
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;

        Ok(request)
    }

    /// Cancel all pending email change requests for a user
    pub async fn cancel_pending_email_change_requests(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE email_change_requests SET canceled_at = NOW()
            WHERE user_id = $1 AND confirmed_at IS NULL AND canceled_at IS NULL AND expires_at > NOW()
            "#,
        )
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Confirm an email change request
    pub async fn confirm_email_change_request(
        pool: &PgPool,
        request_id: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE email_change_requests SET confirmed_at = NOW() WHERE id = $1
            "#,
        )
        .bind(request_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Count recent email change requests for a user (for rate limiting)
    pub async fn count_recent_email_change_requests(
        pool: &PgPool,
        user_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<i64, AppError> {
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM email_change_requests
            WHERE user_id = $1 AND created_at > $2
            "#,
        )
        .bind(user_id)
        .bind(since)
        .fetch_one(pool)
        .await?;

        Ok(count.0)
    }

    // ==============================
    // Email Verification Tokens
    // ==============================

    /// Create a new email verification token
    pub async fn create_email_verification_token(
        pool: &PgPool,
        data: CreateEmailVerificationToken,
    ) -> Result<EmailVerificationToken, AppError> {
        let token = sqlx::query_as::<_, EmailVerificationToken>(
            r#"
            INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, ip_address)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(data.user_id)
        .bind(&data.token_hash)
        .bind(data.expires_at)
        .bind(data.ip_address)
        .fetch_one(pool)
        .await?;

        Ok(token)
    }

    /// Find email verification token by hash
    pub async fn find_email_verification_token_by_hash(
        pool: &PgPool,
        token_hash: &str,
    ) -> Result<Option<EmailVerificationToken>, AppError> {
        let token = sqlx::query_as::<_, EmailVerificationToken>(
            r#"
            SELECT * FROM email_verification_tokens
            WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
            "#,
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;

        Ok(token)
    }

    /// Mark email verification token as used
    pub async fn mark_email_verification_token_used<'e, E>(
        executor: E,
        token_id: Uuid,
    ) -> Result<(), AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        sqlx::query(
            r#"
            UPDATE email_verification_tokens SET used_at = NOW() WHERE id = $1
            "#,
        )
        .bind(token_id)
        .execute(executor)
        .await?;

        Ok(())
    }

    /// Count recent email verification tokens for a user (for rate limiting)
    pub async fn count_recent_email_verification_tokens(
        pool: &PgPool,
        user_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<i64, AppError> {
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM email_verification_tokens
            WHERE user_id = $1 AND created_at > $2
            "#,
        )
        .bind(user_id)
        .bind(since)
        .fetch_one(pool)
        .await?;

        Ok(count.0)
    }

    // =====================
    // Cleanup
    // =====================

    /// Clean up expired tokens (run periodically)
    pub async fn cleanup_expired_tokens(pool: &PgPool) -> Result<u64, AppError> {
        let mut total = 0u64;

        // Delete expired refresh tokens
        let result = sqlx::query(
            r#"
            DELETE FROM refresh_tokens WHERE expires_at < NOW()
            "#,
        )
        .execute(pool)
        .await?;
        total += result.rows_affected();

        // Delete expired magic link tokens
        let result = sqlx::query(
            r#"
            DELETE FROM magic_link_tokens WHERE expires_at < NOW()
            "#,
        )
        .execute(pool)
        .await?;
        total += result.rows_affected();

        // Delete expired password reset tokens
        let result = sqlx::query(
            r#"
            DELETE FROM password_reset_tokens WHERE expires_at < NOW()
            "#,
        )
        .execute(pool)
        .await?;
        total += result.rows_affected();

        // Delete expired email change requests
        let result = sqlx::query(
            r#"
            DELETE FROM email_change_requests WHERE expires_at < NOW()
            "#,
        )
        .execute(pool)
        .await?;
        total += result.rows_affected();

        // Delete expired email verification tokens
        let result = sqlx::query(
            r#"
            DELETE FROM email_verification_tokens WHERE expires_at < NOW()
            "#,
        )
        .execute(pool)
        .await?;
        total += result.rows_affected();

        Ok(total)
    }
}
