//! The singleton `mokosh_config` row (BUNYIP-983).

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::mokosh::MokoshConfigRow;

pub struct MokoshConfigRepository;

impl MokoshConfigRepository {
    pub async fn get(pool: &PgPool) -> Result<MokoshConfigRow, AppError> {
        let row = sqlx::query_as::<_, MokoshConfigRow>("SELECT * FROM mokosh_config WHERE id = 1")
            .fetch_one(pool)
            .await?;
        Ok(row)
    }

    /// Replace the public half as an operator edit. The ciphertext columns are
    /// left alone: the secret is written through the governed-secret path, so
    /// an admin fixing a mistyped client id does not re-enter the secret.
    pub async fn update_client_id(
        pool: &PgPool,
        google_client_id: &str,
        updated_by: Uuid,
    ) -> Result<MokoshConfigRow, AppError> {
        let row = sqlx::query_as::<_, MokoshConfigRow>(
            r#"
            UPDATE mokosh_config
            SET google_client_id = $1,
                updated_at       = NOW(),
                updated_by       = $2
            WHERE id = 1
            RETURNING *
            "#,
        )
        .bind(google_client_id)
        .bind(updated_by)
        .fetch_one(pool)
        .await?;
        Ok(row)
    }

    /// Write the encrypted client secret (ciphertext + nonce) under
    /// `key_version` as an operator edit.
    pub async fn update_client_secret(
        pool: &PgPool,
        google_client_secret: &[u8],
        google_client_secret_nonce: &[u8],
        key_version: i16,
        updated_by: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE mokosh_config
            SET google_client_secret       = $1,
                google_client_secret_nonce = $2,
                key_version                = $3,
                updated_at                 = NOW(),
                updated_by                 = $4
            WHERE id = 1
            "#,
        )
        .bind(google_client_secret)
        .bind(google_client_secret_nonce)
        .bind(key_version)
        .bind(updated_by)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Rewrite the stored secret under a new key version (re-encrypt,
    /// `secrets-migrate` and settings-import passes), touching nothing else and
    /// claiming no operator edit.
    pub async fn update_client_secret_encryption(
        pool: &PgPool,
        google_client_secret: &[u8],
        google_client_secret_nonce: &[u8],
        key_version: i16,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE mokosh_config
            SET google_client_secret       = $1,
                google_client_secret_nonce = $2,
                key_version                = $3,
                updated_at                 = NOW()
            WHERE id = 1
            "#,
        )
        .bind(google_client_secret)
        .bind(google_client_secret_nonce)
        .bind(key_version)
        .execute(pool)
        .await?;
        Ok(())
    }
}
