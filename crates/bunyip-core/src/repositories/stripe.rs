use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::stripe::StripeConfig;

pub struct StripeConfigRepository;

impl StripeConfigRepository {
    pub async fn get(pool: &PgPool) -> Result<StripeConfig, AppError> {
        let config = sqlx::query_as::<_, StripeConfig>("SELECT * FROM stripe_config WHERE id = 1")
            .fetch_one(pool)
            .await?;
        Ok(config)
    }

    /// Clears encrypted secrets (secret_key, webhook_secret and their nonces) from the DB.
    /// Called when decryption fails (e.g. encryption key was rotated).
    pub async fn clear_secrets(pool: &PgPool) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE stripe_config
            SET secret_key = NULL,
                secret_key_nonce = NULL,
                webhook_secret = NULL,
                webhook_secret_nonce = NULL,
                updated_at = NOW()
            WHERE id = 1
            "#,
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Updates only the fields that are `Some`. `None` leaves the existing DB value unchanged.
    /// Secrets are passed as pre-encrypted (ciphertext, nonce) pairs.
    pub async fn update(
        pool: &PgPool,
        secret_key: Option<Vec<u8>>,
        secret_key_nonce: Option<Vec<u8>>,
        webhook_secret: Option<Vec<u8>>,
        webhook_secret_nonce: Option<Vec<u8>>,
        updated_by: Uuid,
        key_version: i16,
        app_tag: Option<String>,
    ) -> Result<StripeConfig, AppError> {
        let config = sqlx::query_as::<_, StripeConfig>(
            r#"
            UPDATE stripe_config
            SET
                secret_key            = CASE WHEN $1::BYTEA IS NOT NULL THEN $1 ELSE secret_key END,
                secret_key_nonce      = CASE WHEN $1::BYTEA IS NOT NULL THEN $2 ELSE secret_key_nonce END,
                webhook_secret        = CASE WHEN $3::BYTEA IS NOT NULL THEN $3 ELSE webhook_secret END,
                webhook_secret_nonce  = CASE WHEN $3::BYTEA IS NOT NULL THEN $4 ELSE webhook_secret_nonce END,
                key_version           = CASE WHEN $1::BYTEA IS NOT NULL OR $3::BYTEA IS NOT NULL THEN $6 ELSE key_version END,
                app_tag               = COALESCE($7, app_tag),
                updated_at            = NOW(),
                updated_by            = $5
            WHERE id = 1
            RETURNING *
            "#,
        )
        .bind(secret_key)
        .bind(secret_key_nonce)
        .bind(webhook_secret)
        .bind(webhook_secret_nonce)
        .bind(updated_by)
        .bind(key_version)
        .bind(app_tag)
        .fetch_one(pool)
        .await?;

        Ok(config)
    }

    /// Update encryption data for the singleton stripe_config row (used during key rotation).
    pub async fn update_encryption(
        pool: &PgPool,
        secret_key: Option<Vec<u8>>,
        secret_key_nonce: Option<Vec<u8>>,
        webhook_secret: Option<Vec<u8>>,
        webhook_secret_nonce: Option<Vec<u8>>,
        key_version: i16,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE stripe_config
            SET
                secret_key = COALESCE($1, secret_key),
                secret_key_nonce = COALESCE($2, secret_key_nonce),
                webhook_secret = COALESCE($3, webhook_secret),
                webhook_secret_nonce = COALESCE($4, webhook_secret_nonce),
                key_version = $5,
                updated_at = NOW()
            WHERE id = 1
            "#,
        )
        .bind(secret_key)
        .bind(secret_key_nonce)
        .bind(webhook_secret)
        .bind(webhook_secret_nonce)
        .bind(key_version)
        .execute(pool)
        .await?;
        Ok(())
    }
}
