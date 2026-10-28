//! The singleton `mirzam_config` row (BUNYIP-997).

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::mirzam::{MirzamConfigRow, MirzamSettings};

pub struct MirzamConfigRepository;

impl MirzamConfigRepository {
    pub async fn get(pool: &PgPool) -> Result<MirzamConfigRow, AppError> {
        let row = sqlx::query_as::<_, MirzamConfigRow>("SELECT * FROM mirzam_config WHERE id = 1")
            .fetch_one(pool)
            .await?;
        Ok(row)
    }

    /// Replace the four non-secret settings as an operator edit. The token
    /// columns are left alone: the token is written through the governed-secret
    /// path.
    pub async fn update_settings(
        pool: &PgPool,
        settings: &MirzamSettings,
        updated_by: Uuid,
    ) -> Result<MirzamConfigRow, AppError> {
        let row = sqlx::query_as::<_, MirzamConfigRow>(
            r#"
            UPDATE mirzam_config
            SET enabled      = $1,
                base_url     = $2,
                updates_list = $3,
                notices_list = $4,
                updated_at   = NOW(),
                updated_by   = $5
            WHERE id = 1
            RETURNING *
            "#,
        )
        .bind(settings.enabled)
        .bind(&settings.base_url)
        .bind(&settings.updates_list)
        .bind(&settings.notices_list)
        .bind(updated_by)
        .fetch_one(pool)
        .await?;
        Ok(row)
    }

    /// Write the encrypted API token (ciphertext + nonce) under `key_version`
    /// as an operator edit.
    pub async fn update_api_token(
        pool: &PgPool,
        api_token: &[u8],
        api_token_nonce: &[u8],
        key_version: i16,
        updated_by: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE mirzam_config
            SET api_token       = $1,
                api_token_nonce = $2,
                key_version     = $3,
                updated_at      = NOW(),
                updated_by      = $4
            WHERE id = 1
            "#,
        )
        .bind(api_token)
        .bind(api_token_nonce)
        .bind(key_version)
        .bind(updated_by)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Rewrite the stored API token under a new key version (re-encrypt,
    /// `secrets-migrate` and settings-import passes), touching nothing else and
    /// claiming no operator edit.
    pub async fn update_api_token_encryption(
        pool: &PgPool,
        api_token: &[u8],
        api_token_nonce: &[u8],
        key_version: i16,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE mirzam_config
            SET api_token       = $1,
                api_token_nonce = $2,
                key_version     = $3,
                updated_at      = NOW()
            WHERE id = 1
            "#,
        )
        .bind(api_token)
        .bind(api_token_nonce)
        .bind(key_version)
        .execute(pool)
        .await?;
        Ok(())
    }
}
