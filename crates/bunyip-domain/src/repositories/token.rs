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

/// One user who is at or over an email-resend limiter's threshold within the
/// rolling window (BUNYIP-315). Carries what the admin read path needs to
/// synthesize a rate-limit entry: the resolved user, the in-window `count`, and
/// the `oldest` in-window `created_at` for computing `retry_after`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EmailResendLimiterRow {
    pub user_id: Uuid,
    pub email: String,
    pub count: i64,
    pub oldest: DateTime<Utc>,
}

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

    /// A page of a user's active refresh tokens, newest first (BUNYIP-177).
    pub async fn find_user_refresh_tokens_paginated(
        pool: &PgPool,
        user_id: Uuid,
        per_page: i32,
        offset: i64,
    ) -> Result<Vec<RefreshToken>, AppError> {
        let tokens = sqlx::query_as::<_, RefreshToken>(
            r#"
            SELECT * FROM refresh_tokens
            WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(user_id)
        .bind(per_page)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok(tokens)
    }

    /// Count of a user's active refresh tokens, for pagination totals (BUNYIP-177).
    pub async fn count_user_refresh_tokens(pool: &PgPool, user_id: Uuid) -> Result<i64, AppError> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM refresh_tokens
            WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
            "#,
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
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

    /// Revoke all refresh tokens for a user across BOTH refresh-token surfaces.
    ///
    /// Bunyip carries two parallel refresh-token schemes: the legacy
    /// `refresh_tokens` table (HS256 session tokens) and the OIDC scheme in
    /// `refresh_tokens_v2` gated by `refresh_token_families`. A security event
    /// such as a password change, password reset, "log out everywhere", or
    /// account deletion must invalidate every outstanding refresh token, so this
    /// revokes all three relations in one transaction. Revoking the family is
    /// what blocks the OIDC refresh endpoint (it checks the family); the v2 rows
    /// are revoked too so per-token bookkeeping stays consistent.
    ///
    /// Generic over [`sqlx::Acquire`] so callers can pass either a `&PgPool`
    /// (the revocation runs in its own transaction) or an existing
    /// `&mut Transaction` (the revocation joins the caller's transaction, e.g.
    /// the email-change flows that must revoke atomically with the email
    /// update). In the latter case `begin` opens a nested transaction
    /// (savepoint) so the three statements still commit or roll back together.
    pub async fn revoke_all_user_refresh_tokens<'a, A>(
        executor: A,
        user_id: Uuid,
    ) -> Result<(), AppError>
    where
        A: sqlx::Acquire<'a, Database = Postgres>,
    {
        let mut tx = executor.begin().await?;

        // Legacy HS256 refresh tokens.
        sqlx::query(
            r#"
            UPDATE refresh_tokens SET revoked_at = NOW()
            WHERE user_id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        // OIDC refresh-token families (the surface the OIDC refresh endpoint
        // consults to reject a whole login session).
        sqlx::query(
            r#"
            UPDATE refresh_token_families
            SET revoked_at = NOW(), revoke_reason = 'security_event'
            WHERE user_id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        // OIDC refresh tokens themselves.
        sqlx::query(
            r#"
            UPDATE refresh_tokens_v2 SET revoked_at = NOW()
            WHERE user_id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(())
    }

    /// Revoke every OIDC refresh-token family (and its `refresh_tokens_v2`
    /// rows) for one `(user, client)` pair. BUNYIP-200: an admin tenant
    /// unassign/reassign must kill outstanding refresh tokens for that client
    /// so a rotated token can no longer keep minting the stale tenant claim.
    /// `client_id` is the public `oauth_clients.client_id` UUID, the same
    /// value stored on `refresh_token_families.client_id` and
    /// `oauth_client_user_tenants.oauth_client_id`. Returns the number of
    /// families revoked. Scoped to the OIDC v2 surface only; the legacy
    /// `refresh_tokens` table has no per-client binding.
    pub async fn revoke_client_user_refresh_tokens(
        pool: &PgPool,
        user_id: Uuid,
        client_id: Uuid,
    ) -> Result<u64, AppError> {
        let mut tx = pool.begin().await?;

        let result = sqlx::query(
            r#"
            UPDATE refresh_token_families
            SET revoked_at = NOW(), revoke_reason = 'tenant_reassigned'
            WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .bind(client_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            UPDATE refresh_tokens_v2 SET revoked_at = NOW()
            WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .bind(client_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(result.rows_affected())
    }

    /// Revoke all of a user's active refresh tokens EXCEPT one (the caller's
    /// current session). Powers "log out all other devices" (BUNYIP-137).
    /// Scoped to the legacy `refresh_tokens` table, which is the surface the
    /// active-sessions panel lists; OIDC SSO sessions are managed separately.
    /// Returns the number of sessions revoked.
    pub async fn revoke_other_user_refresh_tokens(
        pool: &PgPool,
        user_id: Uuid,
        keep_token_id: Uuid,
    ) -> Result<u64, AppError> {
        let result = sqlx::query(
            r#"
            UPDATE refresh_tokens SET revoked_at = NOW()
            WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .bind(keep_token_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
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

    /// BUNYIP-256: mark every still-valid password reset token for the user
    /// as used, returning the count cleared. Called by
    /// `request_password_reset` so a fresh reset request invalidates any
    /// older outstanding tokens for the same user. Cuts the surface to one
    /// live token per user at a time and matches the common UX ("only the
    /// most recent link works"); a user staring at three reset emails
    /// after triple-clicking the form gets a clear single-truth answer.
    pub async fn revoke_pending_password_reset_tokens(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<u64, AppError> {
        let result = sqlx::query(
            r#"
            UPDATE password_reset_tokens
            SET used_at = NOW()
            WHERE user_id = $1 AND used_at IS NULL AND expires_at > NOW()
            "#,
        )
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
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
    pub async fn confirm_email_change_request<'e, E>(
        executor: E,
        request_id: Uuid,
    ) -> Result<(), AppError>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        sqlx::query(
            r#"
            UPDATE email_change_requests SET confirmed_at = NOW() WHERE id = $1
            "#,
        )
        .bind(request_id)
        .execute(executor)
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

    /// Oldest email change request `created_at` within the window (for
    /// computing an accurate `retry_after`, BUNYIP-313). Returns `None` when
    /// there are no in-window requests.
    pub async fn oldest_recent_email_change_request(
        pool: &PgPool,
        user_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<Option<DateTime<Utc>>, AppError> {
        let row: (Option<DateTime<Utc>>,) = sqlx::query_as(
            r#"
            SELECT MIN(created_at) FROM email_change_requests
            WHERE user_id = $1 AND created_at > $2
            "#,
        )
        .bind(user_id)
        .bind(since)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
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

    /// Oldest email verification token `created_at` within the window (for
    /// computing an accurate `retry_after`, BUNYIP-313). Returns `None` when
    /// there are no in-window tokens.
    pub async fn oldest_recent_email_verification_token(
        pool: &PgPool,
        user_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<Option<DateTime<Utc>>, AppError> {
        let row: (Option<DateTime<Utc>>,) = sqlx::query_as(
            r#"
            SELECT MIN(created_at) FROM email_verification_tokens
            WHERE user_id = $1 AND created_at > $2
            "#,
        )
        .bind(user_id)
        .bind(since)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Users at or over `threshold` email-verification resends within the
    /// window since `since`, joined to their email, with the resend `count` and
    /// the `oldest` in-window `created_at` (for an accurate `retry_after`).
    /// Backs the admin "currently rate-limited" view (BUNYIP-315). Only
    /// non-deleted users are returned. Highest count first.
    pub async fn list_email_verification_over_limit(
        pool: &PgPool,
        since: DateTime<Utc>,
        threshold: i64,
    ) -> Result<Vec<EmailResendLimiterRow>, AppError> {
        let rows = sqlx::query_as::<_, EmailResendLimiterRow>(
            r#"
            SELECT u.id AS user_id, u.email AS email,
                   COUNT(t.id) AS count, MIN(t.created_at) AS oldest
            FROM email_verification_tokens t
            JOIN users u ON u.id = t.user_id AND u.deleted_at IS NULL
            WHERE t.created_at > $1
            GROUP BY u.id, u.email
            HAVING COUNT(t.id) >= $2
            ORDER BY COUNT(t.id) DESC
            "#,
        )
        .bind(since)
        .bind(threshold)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Users at or over `threshold` email-change requests within the window
    /// since `since`, joined to their email, with the request `count` and the
    /// `oldest` in-window `created_at`. Backs the admin "currently rate-limited"
    /// view (BUNYIP-315). Only non-deleted users are returned. Highest first.
    pub async fn list_email_change_over_limit(
        pool: &PgPool,
        since: DateTime<Utc>,
        threshold: i64,
    ) -> Result<Vec<EmailResendLimiterRow>, AppError> {
        let rows = sqlx::query_as::<_, EmailResendLimiterRow>(
            r#"
            SELECT u.id AS user_id, u.email AS email,
                   COUNT(r.id) AS count, MIN(r.created_at) AS oldest
            FROM email_change_requests r
            JOIN users u ON u.id = r.user_id AND u.deleted_at IS NULL
            WHERE r.created_at > $1
            GROUP BY u.id, u.email
            HAVING COUNT(r.id) >= $2
            ORDER BY COUNT(r.id) DESC
            "#,
        )
        .bind(since)
        .bind(threshold)
        .fetch_all(pool)
        .await?;

        Ok(rows)
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
