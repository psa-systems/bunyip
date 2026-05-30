//! TOTP two-factor authentication repository

use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{RecoveryCode, UserTotp};

pub struct TotpRepository;

impl TotpRepository {
    /// Insert or update TOTP configuration for a user (upsert)
    pub async fn upsert_totp(
        pool: &PgPool,
        user_id: Uuid,
        encrypted_secret: &[u8],
        nonce: &[u8],
        key_version: i16,
    ) -> Result<UserTotp, sqlx::Error> {
        sqlx::query_as::<_, UserTotp>(
            r#"
            INSERT INTO user_totp (user_id, encrypted_secret, nonce, key_version)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id) DO UPDATE
            SET encrypted_secret = $2, nonce = $3, key_version = $4,
                verified = FALSE, enabled_at = NULL, updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(encrypted_secret)
        .bind(nonce)
        .bind(key_version)
        .fetch_one(pool)
        .await
    }

    /// Update encryption data for a specific TOTP record (used during key rotation).
    pub async fn update_encryption(
        pool: &PgPool,
        id: Uuid,
        encrypted_secret: &[u8],
        nonce: &[u8],
        key_version: i16,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE user_totp
            SET encrypted_secret = $2, nonce = $3, key_version = $4, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(encrypted_secret)
        .bind(nonce)
        .bind(key_version)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Find TOTP configuration by user ID
    pub async fn find_by_user_id(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Option<UserTotp>, sqlx::Error> {
        sqlx::query_as::<_, UserTotp>("SELECT * FROM user_totp WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await
    }

    /// Mark TOTP as verified and enable 2FA on the user
    pub async fn mark_verified(pool: &PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query(
            "UPDATE user_totp SET verified = TRUE, enabled_at = NOW(), updated_at = NOW() WHERE user_id = $1",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query("UPDATE users SET two_factor_enabled = TRUE, updated_at = NOW() WHERE id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await
    }

    /// Delete TOTP configuration and disable 2FA on the user
    pub async fn delete_by_user_id(pool: &PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM user_totp WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "UPDATE users SET two_factor_enabled = FALSE, updated_at = NOW() WHERE id = $1",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await
    }

    /// Insert recovery codes (deletes old ones first)
    pub async fn insert_recovery_codes(
        pool: &PgPool,
        user_id: Uuid,
        code_hashes: &[String],
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        for hash in code_hashes {
            sqlx::query("INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)")
                .bind(user_id)
                .bind(hash)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await
    }

    /// Find all unused recovery codes for a user (max 8)
    pub async fn find_all_unused_recovery_codes(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Vec<RecoveryCode>, sqlx::Error> {
        sqlx::query_as::<_, RecoveryCode>(
            "SELECT * FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    /// Find an unused recovery code by hash
    pub async fn find_unused_recovery_code(
        pool: &PgPool,
        user_id: Uuid,
        code_hash: &str,
    ) -> Result<Option<RecoveryCode>, sqlx::Error> {
        sqlx::query_as::<_, RecoveryCode>(
            "SELECT * FROM recovery_codes WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
        )
        .bind(user_id)
        .bind(code_hash)
        .fetch_optional(pool)
        .await
    }

    /// Mark a recovery code as used
    pub async fn mark_recovery_code_used(pool: &PgPool, code_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE recovery_codes SET used_at = NOW() WHERE id = $1")
            .bind(code_id)
            .execute(pool)
            .await?;
        Ok(())
    }

    /// Count unused recovery codes for a user
    pub async fn count_unused_recovery_codes(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }
}
