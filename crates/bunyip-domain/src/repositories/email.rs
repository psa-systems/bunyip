//! Email configuration repository (singleton, id=1) — BUNYIP-351

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::email::EmailConfigRow;

pub struct EmailConfigRepository;

impl EmailConfigRepository {
    pub async fn get(pool: &PgPool) -> Result<EmailConfigRow, AppError> {
        let row = sqlx::query_as::<_, EmailConfigRow>("SELECT * FROM email_config WHERE id = 1")
            .fetch_one(pool)
            .await?;
        Ok(row)
    }

    /// Clears the encrypted SMTP password (and its nonce) from the DB. Called
    /// when decryption fails (e.g. the encryption key was rotated), mirroring
    /// `StripeConfigRepository::clear_secrets`.
    pub async fn clear_password(pool: &PgPool) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE email_config
            SET smtp_password = NULL,
                smtp_password_nonce = NULL,
                updated_at = NOW()
            WHERE id = 1
            "#,
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Rewrite the stored SMTP password ciphertext under a new key version,
    /// touching nothing else (BUNYIP-483 re-encrypt pass). `updated_by` is left
    /// alone: re-encryption is not an operator edit of the configuration.
    pub async fn update_password_encryption(
        pool: &PgPool,
        smtp_password: &[u8],
        smtp_password_nonce: &[u8],
        key_version: i16,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE email_config
            SET smtp_password = $1,
                smtp_password_nonce = $2,
                key_version = $3,
                updated_at = NOW()
            WHERE id = 1
            "#,
        )
        .bind(smtp_password)
        .bind(smtp_password_nonce)
        .bind(key_version)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Updates only the fields that are `Some`. `None` leaves the existing DB
    /// value unchanged (COALESCE). The SMTP password is passed as a
    /// pre-encrypted (ciphertext, nonce) pair; when present, `key_version` is
    /// updated alongside it.
    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        pool: &PgPool,
        enabled: Option<bool>,
        smtp_host: Option<String>,
        smtp_port: Option<i32>,
        smtp_tls: Option<String>,
        smtp_username: Option<String>,
        smtp_password: Option<Vec<u8>>,
        smtp_password_nonce: Option<Vec<u8>>,
        key_version: i16,
        from_email: Option<String>,
        from_name: Option<String>,
        admin_notification_emails: Option<String>,
        updated_by: Uuid,
    ) -> Result<EmailConfigRow, AppError> {
        let row = sqlx::query_as::<_, EmailConfigRow>(
            r#"
            UPDATE email_config
            SET
                enabled                   = COALESCE($1, enabled),
                smtp_host                 = COALESCE($2, smtp_host),
                smtp_port                 = COALESCE($3, smtp_port),
                smtp_tls                  = COALESCE($4, smtp_tls),
                smtp_username             = COALESCE($5, smtp_username),
                smtp_password             = CASE WHEN $6::BYTEA IS NOT NULL THEN $6 ELSE smtp_password END,
                smtp_password_nonce       = CASE WHEN $6::BYTEA IS NOT NULL THEN $7 ELSE smtp_password_nonce END,
                key_version               = CASE WHEN $6::BYTEA IS NOT NULL THEN $8 ELSE key_version END,
                from_email                = COALESCE($9, from_email),
                from_name                 = COALESCE($10, from_name),
                admin_notification_emails = COALESCE($11, admin_notification_emails),
                updated_at                = NOW(),
                updated_by                = $12
            WHERE id = 1
            RETURNING *
            "#,
        )
        .bind(enabled)
        .bind(smtp_host)
        .bind(smtp_port)
        .bind(smtp_tls)
        .bind(smtp_username)
        .bind(smtp_password)
        .bind(smtp_password_nonce)
        .bind(key_version)
        .bind(from_email)
        .bind(from_name)
        .bind(admin_notification_emails)
        .bind(updated_by)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// Write the encrypted IMAP password (ciphertext + nonce) under
    /// `key_version` as an operator edit (BUNYIP-571), mirroring how `update`
    /// writes the SMTP password. Non-password IMAP columns are left untouched.
    pub async fn update_imap_password(
        pool: &PgPool,
        imap_password: &[u8],
        imap_password_nonce: &[u8],
        key_version: i16,
        updated_by: Uuid,
    ) -> Result<EmailConfigRow, AppError> {
        let row = sqlx::query_as::<_, EmailConfigRow>(
            r#"
            UPDATE email_config
            SET imap_password       = $1,
                imap_password_nonce = $2,
                key_version         = $3,
                updated_at          = NOW(),
                updated_by          = $4
            WHERE id = 1
            RETURNING *
            "#,
        )
        .bind(imap_password)
        .bind(imap_password_nonce)
        .bind(key_version)
        .bind(updated_by)
        .fetch_one(pool)
        .await?;
        Ok(row)
    }

    /// Rewrite the stored IMAP password ciphertext under a new key version
    /// (re-encrypt / secrets-migrate pass), touching nothing else.
    pub async fn update_imap_password_encryption(
        pool: &PgPool,
        imap_password: &[u8],
        imap_password_nonce: &[u8],
        key_version: i16,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE email_config
            SET imap_password       = $1,
                imap_password_nonce = $2,
                key_version         = $3,
                updated_at          = NOW()
            WHERE id = 1
            "#,
        )
        .bind(imap_password)
        .bind(imap_password_nonce)
        .bind(key_version)
        .execute(pool)
        .await?;
        Ok(())
    }
}
